import logging
from typing import Any

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


def _extract_nested(data: Any, path: str) -> Any:
    """Extract value from nested dict using dot-notation path, e.g. 'data.items'."""
    if not path:
        return data
    parts = path.split(".")
    current = data
    for part in parts:
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
        if current is None:
            return None
    return current


class CustomApiCollector:
    name = "custom_api"

    def __init__(self, credentials: dict, db: AsyncSession):
        self.base_url = credentials.get("base_url", "").rstrip("/")
        self.endpoint_path = credentials.get("endpoint_path", "")
        self.auth_type = credentials.get("auth_type", "none").lower()
        self.auth_value = credentials.get("auth_value", "")
        self.auth_header = credentials.get("auth_header", "Authorization")
        self.data_field = credentials.get("data_field", "")
        self.entity_type = credentials.get("entity_type", "endpoint")
        self.display_name = credentials.get("custom_name", "Custom API")
        self.db = db

    def _headers(self) -> dict:
        headers: dict[str, str] = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if self.auth_type == "bearer":
            headers["Authorization"] = f"Bearer {self.auth_value}"
        elif self.auth_type == "api_key":
            headers[self.auth_header] = self.auth_value
        elif self.auth_type == "basic":
            headers["Authorization"] = f"Basic {self.auth_value}"
        return headers

    async def test_connection(self) -> dict:
        if not self.base_url:
            return {"success": False, "message": "No base URL configured"}

        url = f"{self.base_url}{self.endpoint_path}"
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(url, headers=self._headers())
                if resp.status_code == 401:
                    return {"success": False, "message": "Unauthorized (401) — check your credentials"}
                if resp.status_code == 403:
                    return {"success": False, "message": "Forbidden (403) — insufficient permissions"}
                if resp.status_code == 404:
                    return {"success": False, "message": f"Endpoint not found (404): {url}"}
                resp.raise_for_status()
                try:
                    body = resp.json()
                    records = _extract_nested(body, self.data_field)
                    count = len(records) if isinstance(records, list) else "N/A"
                except Exception:
                    count = "N/A"
                return {"success": True, "message": f"Connected. HTTP 200. Records sampled: {count}"}
        except httpx.ConnectError as e:
            return {"success": False, "message": f"Connection error: {str(e)}"}
        except httpx.TimeoutException:
            return {"success": False, "message": "Connection timed out"}
        except Exception as e:
            return {"success": False, "message": f"Error: {str(e)}"}

    async def collect(self) -> dict:
        if not self.base_url:
            return {"records_synced": 0, "error": "No base URL configured"}

        url = f"{self.base_url}{self.endpoint_path}"
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                resp = await client.get(url, headers=self._headers())
                resp.raise_for_status()
                body = resp.json()

            records = _extract_nested(body, self.data_field)
            if not isinstance(records, list):
                if isinstance(body, list):
                    records = body
                else:
                    records = [body] if body else []

            count = await self._store_records(records)
            return {"records_synced": count}
        except Exception as e:
            logger.error(f"CustomAPI collect error: {e}", exc_info=True)
            return {"records_synced": 0, "error": str(e)}

    async def _store_records(self, records: list[Any]) -> int:
        from app.models.application import RawData

        count = 0
        for record in records:
            if not isinstance(record, dict):
                record = {"value": record}
            raw = RawData(
                source=self.display_name,
                entity_type=self.entity_type,
                raw_json=record,
            )
            self.db.add(raw)
            count += 1

        if count:
            await self.db.flush()
        return count
