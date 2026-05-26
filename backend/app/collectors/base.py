import asyncio
import logging
import time
from abc import ABC, abstractmethod
from typing import Any
from datetime import datetime, timezone

import httpx

logger = logging.getLogger(__name__)

# ── Circuit breaker ───────────────────────────────────────────────────────────
# Per-collector state stored at class level (class name → state dict).
# States: CLOSED (normal), OPEN (blocked), HALF_OPEN (testing).
_CB_STATES: dict[str, dict] = {}
_CB_FAILURE_THRESHOLD = 5      # consecutive failures to open
_CB_RECOVERY_SECONDS  = 60     # seconds before retrying from OPEN


def _cb_state(name: str) -> dict:
    if name not in _CB_STATES:
        _CB_STATES[name] = {"state": "CLOSED", "failures": 0, "opened_at": None}
    return _CB_STATES[name]


def _cb_allow(name: str) -> bool:
    cb = _cb_state(name)
    if cb["state"] == "CLOSED":
        return True
    if cb["state"] == "OPEN":
        if time.monotonic() - cb["opened_at"] > _CB_RECOVERY_SECONDS:
            cb["state"] = "HALF_OPEN"
            logger.info("Circuit breaker %s → HALF_OPEN (testing)", name)
            return True
        return False
    return True  # HALF_OPEN: allow one attempt


def _cb_success(name: str) -> None:
    cb = _cb_state(name)
    if cb["state"] != "CLOSED":
        logger.info("Circuit breaker %s → CLOSED (recovered)", name)
    cb.update({"state": "CLOSED", "failures": 0, "opened_at": None})


def _cb_failure(name: str) -> None:
    cb = _cb_state(name)
    cb["failures"] += 1
    if cb["state"] == "HALF_OPEN" or cb["failures"] >= _CB_FAILURE_THRESHOLD:
        cb["state"] = "OPEN"
        cb["opened_at"] = time.monotonic()
        logger.warning(
            "Circuit breaker %s → OPEN after %d failures", name, cb["failures"]
        )


class BaseCollector(ABC):
    name: str = "base"
    max_retries: int = 3
    base_delay: float = 1.0

    def __init__(self):
        self.client = httpx.AsyncClient(timeout=30.0)

    @abstractmethod
    async def fetch_data(self) -> list[dict[str, Any]]:
        """Fetch raw data from source API."""
        ...

    @abstractmethod
    async def normalize(self, raw_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Normalize raw data to internal format."""
        ...

    async def fetch_with_retry(self, url: str, **kwargs) -> httpx.Response:
        last_error = None
        for attempt in range(self.max_retries):
            try:
                response = await self.client.get(url, **kwargs)
                if response.status_code == 429:
                    retry_after = float(response.headers.get("Retry-After", self.base_delay * (2 ** attempt)))
                    logger.warning(f"{self.name}: Rate limited, waiting {retry_after}s")
                    await asyncio.sleep(retry_after)
                    continue
                response.raise_for_status()
                return response
            except httpx.HTTPStatusError as e:
                last_error = e
                if e.response.status_code < 500:
                    raise
                delay = self.base_delay * (2 ** attempt)
                logger.warning(f"{self.name}: HTTP error {e.response.status_code}, retry {attempt+1}/{self.max_retries} in {delay}s")
                await asyncio.sleep(delay)
            except httpx.RequestError as e:
                last_error = e
                delay = self.base_delay * (2 ** attempt)
                logger.warning(f"{self.name}: Request error: {e}, retry {attempt+1}/{self.max_retries} in {delay}s")
                await asyncio.sleep(delay)
        raise last_error or RuntimeError(f"{self.name}: Max retries exceeded")

    async def store_raw(self, items: list[dict[str, Any]], entity_type: str, db_session=None):
        """Store raw data to RawData table."""
        if db_session is None:
            return
        from app.models.application import RawData
        for item in items:
            raw = RawData(
                source=self.name,
                entity_type=entity_type,
                raw_json=item,
                ingested_at=datetime.now(timezone.utc),
            )
            db_session.add(raw)

    async def run(self, db_session=None) -> dict[str, Any]:
        """Main entry point: fetch, normalize, store. Guards with circuit breaker."""
        if not _cb_allow(self.name):
            logger.warning("%s: Circuit breaker OPEN, skipping collection", self.name)
            return {"source": self.name, "count": 0, "error": "Circuit breaker open", "data": []}

        logger.info(f"{self.name}: Starting collection")
        try:
            raw_items = await self.fetch_data()
            logger.info(f"{self.name}: Fetched {len(raw_items)} items")
            normalized = await self.normalize(raw_items)
            if db_session:
                await self.store_raw(raw_items, "raw", db_session)
            _cb_success(self.name)
            logger.info(f"{self.name}: Collection complete, {len(normalized)} normalized")
            return {"source": self.name, "count": len(normalized), "data": normalized}
        except Exception as e:
            _cb_failure(self.name)
            logger.error(f"{self.name}: Collection failed: {e}", exc_info=True)
            return {"source": self.name, "count": 0, "error": str(e), "data": []}
        finally:
            await self.client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.client.aclose()
