"""
Symantec CloudSOC collector — pulls exposure-relevant activity from the
CloudSOC Investigate API and threat incidents from Detect.

Auth:  Basic auth (Key-ID : Key-Secret) + X-Elastica-Dbname-Resolved: True
Docs:  https://techdocs.broadcom.com/us/en/symantec-security-software/
       information-security/symantec-cloudsoc/cloud/api-home.html

What we pull (last 7 days):
  • Investigate/all  — filtered to exposure events only:
      – Emails / files sent to external recipients
      – Any event CloudSOC rates as high or critical severity
  • Detect/incidents — DLP threat incidents (already threat-scored)

Everything else (routine internal activity, calendar updates, Slack posts,
informational Gmail receives) is discarded before writing to the DB.
"""
import asyncio
import base64
import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

_DEFAULT_BASE_URL    = "https://api-vip.elastica.net"
_RETENTION_DAYS      = 7
_MAX_RECORDS         = 10_000
# Investigate has millions of records — cap page scans to avoid runaway loops.
# We fetch the most-recent events first; once we've scanned this many raw API
# pages we stop, regardless of how many exposure events we've accumulated.
_INVESTIGATE_MAX_PAGES = 20   # 20 pages × 1,000 events = 20,000 raw events scanned
_sync_lock           = asyncio.Lock()

# Severity levels that CloudSOC considers elevated
_ELEVATED_SEVERITY = {"critical", "high", "warning", "medium"}

# Activity types that represent outbound / sharing actions
_OUTGOING_ACTIVITY = {
    "send", "share", "upload", "forward", "publish", "copy",
    "post", "invite", "add member", "add user",
}


def _is_exposure(item: dict) -> bool:
    """Return True if this Investigate event is worth storing."""
    sev = (item.get("severity") or "").lower()
    if sev in _ELEVATED_SEVERITY:
        return True

    ext_count = item.get("external_recipient_count") or 0
    act = (item.get("activity_type") or "").lower()
    if ext_count > 0 and act != "receive":
        return True

    return False


def _b64(key_id: str, key_secret: str) -> str:
    return base64.b64encode(f"{key_id}:{key_secret}".encode()).decode()


def _headers(key_id: str, key_secret: str) -> dict:
    return {
        "Authorization": f"Basic {_b64(key_id, key_secret)}",
        "Content-Type": "application/json",
        "X-Elastica-Dbname-Resolved": "True",
    }


def _build_investigate_details(item: dict) -> dict:
    d: dict[str, Any] = {
        "app":         "cloudsoc",
        "source":      "investigate",
        "event_name":  _classify_exposure(item),
        "description": (item.get("message") or "").strip() or None,
    }
    for field in (
        "service", "activity_type", "object_type", "severity",
        "external_recipients", "external_recipient_count",
        "internal_recipients", "internal_recipient_count",
        "sender", "subject", "file_size", "resource_id",
    ):
        val = item.get(field)
        if val not in (None, "", [], {}, 0):
            d[field] = val

    obj_name = item.get("name") or item.get("object_name")
    if obj_name:
        d["object_name"] = obj_name

    return {k: v for k, v in d.items() if v is not None}


def _classify_exposure(item: dict) -> str:
    sev = (item.get("severity") or "").lower()
    ext_count = item.get("external_recipient_count") or 0
    act = (item.get("activity_type") or "").lower()

    if ext_count > 0 and act != "receive":
        return "external_share"
    if sev in ("critical", "high"):
        return "policy_violation"
    return "flagged_activity"


def _build_detect_details(item: dict) -> dict:
    d: dict[str, Any] = {
        "app":         "cloudsoc",
        "source":      "detect",
        "event_name":  "threat_incident",
    }
    for field in ("service", "activity_type", "object_type", "severity",
                  "threat_score", "ioi_code"):
        val = item.get(field)
        if val not in (None, "", [], {}):
            d[field] = val

    score = item.get("threat_score")
    svc   = item.get("service") or "cloud service"
    d["description"] = f"Threat incident — score {score}/100 on {svc}" if score else f"Threat incident on {svc}"
    return d


def _is_suspicious_investigate(item: dict) -> bool:
    sev = (item.get("severity") or "").lower()
    if sev in ("critical", "high"):
        return True
    if (item.get("external_recipient_count") or 0) > 0:
        return True
    return False


class CloudSOCCollector:
    name = "cloudsoc"

    def __init__(self, credentials: dict, db: AsyncSession):
        self.tenant_id  = (credentials.get("tenant_id") or "").strip()
        self.key_id     = (credentials.get("key_id") or "").strip()
        self.key_secret = (credentials.get("key_secret") or "").strip()
        self.base_url   = (credentials.get("base_url") or _DEFAULT_BASE_URL).rstrip("/")
        self.db = db

    def _hdrs(self) -> dict:
        return _headers(self.key_id, self.key_secret)

    def _url(self, path: str) -> str:
        return f"{self.base_url}/{self.tenant_id}{path}"

    async def test_connection(self) -> dict:
        if not all([self.tenant_id, self.key_id, self.key_secret]):
            return {"success": False, "message": "tenant_id, key_id, and key_secret are all required"}

        url = self._url("/api/admin/v1/logs/get/")
        try:
            async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
                cutoff = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S")
                resp = await client.get(url, headers=self._hdrs(),
                    params={"app": "Investigate", "subtype": "all", "limit": 1, "created_timestamp": cutoff})

                if resp.status_code == 401:
                    return {"success": False, "message": "Authentication failed — check Key-ID and Key-Secret"}
                if resp.status_code == 403:
                    return {"success": False, "message": "Access denied (403) — verify the API key has admin permissions"}
                if resp.status_code == 404:
                    return {"success": False, "message": f"Tenant not found (404) — verify Tenant ID '{self.tenant_id}'"}
                if not resp.is_success:
                    return {"success": False, "message": f"Unexpected response {resp.status_code}: {resp.text[:200]}"}

                body = resp.text.strip()
                if not body:
                    return {"success": False, "message": "Empty response — check Tenant ID and base URL"}

                data = resp.json()
                items = data.get("logs") or data.get("data") or []
                return {
                    "success": True,
                    "message": f"Connected to CloudSOC — tenant '{self.tenant_id}' accessible ({len(items)} sample events)",
                }
        except httpx.ConnectError as e:
            return {"success": False, "message": f"Connection error: {e}"}
        except httpx.TimeoutException:
            return {"success": False, "message": "Connection timed out — check base URL and network access"}
        except Exception as e:
            return {"success": False, "message": f"Error: {e}"}

    async def collect(self) -> dict:
        if not all([self.tenant_id, self.key_id, self.key_secret]):
            return {"records_synced": 0, "error": "Not configured — tenant_id, key_id, key_secret required"}

        if _sync_lock.locked():
            return {"records_synced": 0, "detail": "sync already running"}

        async with _sync_lock:
            try:
                await self._purge_old_events()
                inv_count = await self._sync_investigate()
                det_count = await self._sync_detect()
                return {
                    "records_synced": inv_count + det_count,
                    "detail": {
                        "investigate_exposure_events": inv_count,
                        "detect_incidents":            det_count,
                    },
                }
            except Exception as e:
                logger.error("CloudSOC collect failed: %s", e, exc_info=True)
                return {"records_synced": 0, "error": str(e)}

    async def _purge_old_events(self) -> None:
        from sqlalchemy import delete
        from app.models.activity import ActivityEvent
        # Delete ALL existing CloudSOC events — we do a full fresh sync every run,
        # so there is no value in keeping stale rows. This also prevents unique-
        # constraint violations when re-inserting events with the same external_id.
        result = await self.db.execute(
            delete(ActivityEvent).where(
                ActivityEvent.details["app"].as_string() == "cloudsoc",
            )
        )
        logger.debug("CloudSOC: purged %d existing events for fresh sync", result.rowcount)

    # ── Investigate: exposure events only ─────────────────────────────────────

    async def _sync_investigate(self) -> int:
        from app.models.user import User
        from app.models.activity import ActivityEvent
        from sqlalchemy import select as sa_select

        url    = self._url("/api/admin/v1/logs/get/")
        cutoff = datetime.now(timezone.utc) - timedelta(days=_RETENTION_DAYS)
        start  = cutoff.strftime("%Y-%m-%dT%H:%M:%S")

        raw_items: list[dict] = []
        pages_fetched = 0

        async with httpx.AsyncClient(timeout=60.0, follow_redirects=True) as client:
            # Fetch the most-recent events first (no offset = page 0 = newest).
            # We stop after _INVESTIGATE_MAX_PAGES regardless of how many
            # exposure events we've found — this bounds API calls to O(20)
            # instead of O(millions) for high-volume tenants.
            while pages_fetched < _INVESTIGATE_MAX_PAGES:
                params: dict[str, Any] = {
                    "app": "Investigate", "subtype": "all",
                    "limit": 1000, "created_timestamp": start,
                }
                if pages_fetched:
                    params["offset"] = pages_fetched * 1000

                resp = await client.get(url, headers=self._hdrs(), params=params)

                if resp.status_code == 429:
                    await asyncio.sleep(int(resp.headers.get("Retry-After", 60)))
                    continue
                if not resp.is_success:
                    logger.warning("CloudSOC Investigate → %d: %s", resp.status_code, resp.text[:200])
                    break

                body = resp.text.strip()
                if not body:
                    break

                try:
                    data = resp.json()
                except Exception:
                    break

                page_items = data.get("logs") or data.get("data") or []
                if not page_items:
                    break

                pages_fetched += 1
                # Keep only exposure-relevant events
                raw_items.extend(i for i in page_items if _is_exposure(i))

                if len(page_items) < 1000:
                    break  # last page — no more data

        logger.info("CloudSOC Investigate: scanned %d pages, %d raw exposure events",
                    pages_fetched, len(raw_items))

        if not raw_items:
            logger.info("CloudSOC Investigate: no exposure events in scanned pages")
            return 0

        # Deduplicate by external_id — the API can return the same record on
        # multiple pages; inserting duplicates would violate the unique index.
        seen_ext_ids: set[str] = set()
        deduped: list[dict] = []
        for item in raw_items:
            ext_id = f"cs_inv_{item['_id']}" if item.get("_id") else None
            key = ext_id or id(item)  # items without _id are always unique
            if key not in seen_ext_ids:
                seen_ext_ids.add(key)
                deduped.append(item)
        raw_items = deduped

        logger.info("CloudSOC Investigate: %d exposure events after dedup, writing to DB", len(raw_items))

        # Resolve users
        emails = {i.get("user") or i.get("elastica_user") or "" for i in raw_items}
        emails.discard("")
        user_cache: dict[str, Any] = {}
        if emails:
            rows = (await self.db.execute(sa_select(User).where(User.email.in_(emails)))).scalars().all()
            user_cache = {u.email: u for u in rows}

        count = 0
        for item in raw_items:
            try:
                email = item.get("user") or item.get("elastica_user") or ""
                u = user_cache.get(email)

                raw_ts = item.get("created_timestamp") or item.get("inserted_timestamp")
                timestamp = datetime.now(timezone.utc)
                if raw_ts:
                    try:
                        timestamp = datetime.fromisoformat(raw_ts.replace("Z", "+00:00").replace(" ", "T"))
                    except Exception:
                        pass

                details = _build_investigate_details(item)
                ext_id = f"cs_inv_{item['_id']}" if item.get("_id") else None

                self.db.add(ActivityEvent(
                    id            = uuid.uuid4(),
                    user_id       = u.id if u else None,
                    event_type    = "cloud_access",
                    timestamp     = timestamp,
                    ip_address    = item.get("client_ip") or item.get("host") or None,
                    country       = item.get("country") or None,
                    is_suspicious = _is_suspicious_investigate(item),
                    external_id   = ext_id,
                    details       = details,
                ))
                count += 1
            except Exception as e:
                logger.warning("CloudSOC Investigate: failed to process event: %s", e)

        await self.db.flush()
        logger.info("CloudSOC Investigate: synced %d exposure events", count)
        return count

    # ── Detect: threat incidents ──────────────────────────────────────────────

    async def _sync_detect(self) -> int:
        from app.models.user import User
        from app.models.activity import ActivityEvent
        from sqlalchemy import select as sa_select

        url    = self._url("/api/admin/v1/logs/get/")
        cutoff = datetime.now(timezone.utc) - timedelta(days=_RETENTION_DAYS)
        start  = cutoff.strftime("%Y-%m-%dT%H:%M:%S")

        raw_items: list[dict] = []
        offset = 0

        async with httpx.AsyncClient(timeout=60.0, follow_redirects=True) as client:
            while len(raw_items) < _MAX_RECORDS:
                params: dict[str, Any] = {
                    "app": "Detect", "subtype": "incidents",
                    "limit": 1000, "created_timestamp": start,
                }
                if offset:
                    params["offset"] = offset

                resp = await client.get(url, headers=self._hdrs(), params=params)

                if resp.status_code == 429:
                    await asyncio.sleep(int(resp.headers.get("Retry-After", 60)))
                    continue
                if not resp.is_success:
                    logger.warning("CloudSOC Detect → %d: %s", resp.status_code, resp.text[:200])
                    break

                body = resp.text.strip()
                if not body:
                    break
                try:
                    data = resp.json()
                except Exception:
                    break

                items = data.get("logs") or data.get("data") or []
                if not items:
                    break

                raw_items.extend(items)
                offset += len(items)
                if len(items) < 1000:
                    break

        if not raw_items:
            logger.info("CloudSOC Detect: 0 incidents found")
            return 0

        # Deduplicate by external_id before inserting
        seen_ext_ids: set[str] = set()
        deduped: list[dict] = []
        for item in raw_items:
            ext_id = f"cs_det_{item['_id']}" if item.get("_id") else None
            key = ext_id or id(item)
            if key not in seen_ext_ids:
                seen_ext_ids.add(key)
                deduped.append(item)
        raw_items = deduped

        logger.info("CloudSOC Detect: %d incidents after dedup, writing to DB", len(raw_items))

        emails = {i.get("user") or "" for i in raw_items}
        emails.discard("")
        user_cache: dict[str, Any] = {}
        if emails:
            rows = (await self.db.execute(sa_select(User).where(User.email.in_(emails)))).scalars().all()
            user_cache = {u.email: u for u in rows}

        count = 0
        for item in raw_items:
            try:
                email = item.get("user") or ""
                u = user_cache.get(email)

                raw_ts = item.get("incident_start_time") or item.get("inserted_timestamp")
                timestamp = datetime.now(timezone.utc)
                if raw_ts:
                    try:
                        timestamp = datetime.fromisoformat(raw_ts.replace("Z", "+00:00").replace(" ", "T"))
                    except Exception:
                        pass

                details = _build_detect_details(item)
                ext_id = f"cs_det_{item['_id']}" if item.get("_id") else None

                locs = item.get("locations") or []
                country = locs[0].get("country") if locs and isinstance(locs[0], dict) else None

                self.db.add(ActivityEvent(
                    id            = uuid.uuid4(),
                    user_id       = u.id if u else None,
                    event_type    = "cloud_access",
                    timestamp     = timestamp,
                    ip_address    = None,
                    country       = country,
                    is_suspicious = True,
                    external_id   = ext_id,
                    details       = details,
                ))
                count += 1
            except Exception as e:
                logger.warning("CloudSOC Detect: failed to process event: %s", e)

        await self.db.flush()
        logger.info("CloudSOC Detect: synced %d threat incidents", count)
        return count
