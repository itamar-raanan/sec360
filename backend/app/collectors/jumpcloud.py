import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

_INSIGHTS_BASE  = "https://api.jumpcloud.com/insights/directory/v1"
_RETENTION_DAYS = 7
_MAX_EVENTS     = 10_000   # cap per sync run

# ── JumpCloud event_type → our ActivityEvent event_type ──────────────────────
_EVENT_TYPE_MAP: dict[str, str] = {
    # Authentication
    "user_login_attempt":      "login",
    "admin_login_attempt":     "login",
    "sso_auth":                "saml",
    "ldap_bind":               "access_eval",
    "radius_auth":             "access_eval",
    # MFA
    "mfa_enroll":              "user_account",
    "mfa_totp_attempt":        "access_eval",
    "mfa_push_attempt":        "access_eval",
    "mfa_webauthn_attempt":    "access_eval",
    # User lifecycle / account
    "password_change":         "user_account",
    "password_reset_initiate": "user_account",
    "user_create":             "user_account",
    "user_delete":             "user_account",
    "user_suspend":            "user_account",
    "user_unsuspend":          "user_account",
    "user_update":             "user_account",
    # System
    "system_bind":             "user_account",
    "system_unbind":           "user_account",
}

# Events that are inherently suspicious regardless of success/failure
_ALWAYS_SUSPICIOUS = {
    "user_suspend", "user_delete",
}

# Failed auth is suspicious
_AUTH_EVENT_TYPES = {
    "user_login_attempt", "admin_login_attempt",
    "sso_auth", "ldap_bind", "radius_auth",
    "mfa_totp_attempt", "mfa_push_attempt", "mfa_webauthn_attempt",
}


class JumpCloudCollector:
    name = "jumpcloud"

    def __init__(self, credentials: dict, db: AsyncSession):
        self.api_key = credentials.get("api_key", "")
        self.base_url = "https://console.jumpcloud.com/api"
        self.db = db

    def _headers(self) -> dict:
        return {
            "x-api-key": self.api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    async def test_connection(self) -> dict:
        if not self.api_key:
            return {"success": False, "message": "No API key configured"}
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                # Test systems (core requirement)
                sys_resp = await client.get(
                    f"{self.base_url}/systems",
                    headers=self._headers(),
                    params={"limit": 1},
                )
                if sys_resp.status_code == 401:
                    return {"success": False, "message": "Invalid API key (401 Unauthorized)"}
                if sys_resp.status_code == 403:
                    return {"success": False, "message": "API key lacks 'Systems' read permission (403 Forbidden)"}
                sys_resp.raise_for_status()
                sys_total = sys_resp.json().get("totalCount", 0)

                # Test users (optional — warn if missing)
                usr_resp = await client.get(
                    f"{self.base_url}/systemusers",
                    headers=self._headers(),
                    params={"limit": 1},
                )
                if usr_resp.status_code == 403:
                    return {
                        "success": True,
                        "message": (
                            f"Connected. {sys_total} systems found. "
                            "Note: API key is missing 'Users' read permission — user sync will be skipped."
                        ),
                    }
                usr_resp.raise_for_status()
                usr_total = usr_resp.json().get("totalCount", 0)

                # Test Insights / Directory Events API (optional)
                cutoff = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
                ins_resp = await client.post(
                    f"{_INSIGHTS_BASE}/events",
                    headers=self._headers(),
                    json={"service": ["all"], "start_time": cutoff, "limit": 1},
                )
                insights_note = ""
                if ins_resp.status_code == 200:
                    insights_note = " · Directory Events API accessible"
                elif ins_resp.status_code == 403:
                    insights_note = " · Directory Events API: API key lacks 'Directory Insights' permission (login events skipped)"
                else:
                    insights_note = f" · Directory Events API: {ins_resp.status_code}"

                return {
                    "success": True,
                    "message": f"Connected. {sys_total} systems, {usr_total} users found.{insights_note}",
                }
        except httpx.ConnectError as e:
            return {"success": False, "message": f"Connection error: {str(e)}"}
        except httpx.TimeoutException:
            return {"success": False, "message": "Connection timed out"}
        except Exception as e:
            return {"success": False, "message": f"Error: {str(e)}"}

    async def collect(self) -> dict:
        if not self.api_key:
            return {"records_synced": 0, "users": 0, "endpoints": 0, "error": "No API key configured"}

        user_count     = 0
        endpoint_count = 0
        event_count    = 0
        warnings: list[str] = []

        # Users — gracefully degrade if API key lacks 'Users' read permission
        try:
            users_raw = await self._fetch_users()
            user_count = await self._upsert_users(users_raw)
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 403:
                logger.warning("JumpCloud: API key lacks Users read permission — skipping user sync")
                warnings.append("Users skipped: API key needs 'Users' read permission in JumpCloud")
            else:
                logger.error(f"JumpCloud: user fetch failed: {e}")
                warnings.append(f"Users error: {e}")
        except Exception as e:
            logger.error(f"JumpCloud: user fetch failed: {e}", exc_info=True)
            warnings.append(f"Users error: {e}")

        # Systems — collected independently
        try:
            systems_raw = await self._fetch_systems()
            endpoint_count = await self._upsert_systems(systems_raw)
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 403:
                logger.warning("JumpCloud: API key lacks Systems read permission — skipping system sync")
                warnings.append("Systems skipped: API key needs 'Systems' read permission in JumpCloud")
            else:
                logger.error(f"JumpCloud: system fetch failed: {e}")
                warnings.append(f"Systems error: {e}")
        except Exception as e:
            logger.error(f"JumpCloud: system fetch failed: {e}", exc_info=True)
            warnings.append(f"Systems error: {e}")

        # Directory Events (login / auth / account change events)
        try:
            events_raw = await self._fetch_events()
            event_count = await self._sync_events(events_raw)
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 403:
                logger.info("JumpCloud: Directory Insights API not permitted — skipping event sync")
                warnings.append("Events skipped: API key needs 'Directory Insights' permission in JumpCloud")
            else:
                logger.error(f"JumpCloud: event fetch failed: {e}")
                warnings.append(f"Events error: {e}")
        except Exception as e:
            logger.error(f"JumpCloud: event fetch failed: {e}", exc_info=True)
            warnings.append(f"Events error: {e}")

        result: dict = {
            "records_synced": user_count + endpoint_count + event_count,
            "users":     user_count,
            "endpoints": endpoint_count,
            "events":    event_count,
        }
        if warnings:
            result["warning"] = "; ".join(warnings)
        return result

    async def _fetch_users(self) -> list:
        results = []
        offset = 0
        limit = 100
        async with httpx.AsyncClient(timeout=30.0) as client:
            while True:
                resp = await client.get(
                    f"{self.base_url}/systemusers",
                    headers=self._headers(),
                    params={"limit": limit, "skip": offset},
                )
                resp.raise_for_status()
                data = resp.json()
                batch = data.get("results", [])
                results.extend(batch)
                total = data.get("totalCount", 0)
                offset += len(batch)
                if offset >= total or len(batch) == 0:
                    break
        return results

    async def _fetch_systems(self) -> list:
        results = []
        offset = 0
        limit = 100
        async with httpx.AsyncClient(timeout=30.0) as client:
            while True:
                resp = await client.get(
                    f"{self.base_url}/systems",
                    headers=self._headers(),
                    params={"limit": limit, "skip": offset},
                )
                resp.raise_for_status()
                data = resp.json()
                batch = data.get("results", [])
                results.extend(batch)
                total = data.get("totalCount", 0)
                offset += len(batch)
                if offset >= total or len(batch) == 0:
                    break
        return results

    def _normalize_user(self, raw: dict) -> dict:
        mfa_info = raw.get("mfa", {}) or {}
        # Determine employment status from JumpCloud fields
        if raw.get("suspended"):
            emp_status = "inactive"   # suspended in JumpCloud
        elif raw.get("activated") and not raw.get("account_locked"):
            emp_status = "active"
        else:
            emp_status = "inactive"
        # Extract phone from phoneNumbers list if available
        # JumpCloud sometimes puts URLs or other non-phone values in the number field
        phone_numbers = raw.get("phoneNumbers") or []
        phone = None
        for pn in phone_numbers:
            val = (pn.get("number") or "").strip()
            # Accept only values that look like phone numbers (start with +, digit, or paren)
            if val and not val.startswith("http") and any(c.isdigit() for c in val):
                phone = val[:50]  # guard against VARCHAR(50) limit
                break
        return {
            "full_name": f"{raw.get('firstname', '')} {raw.get('lastname', '')}".strip(),
            "email": raw.get("email", ""),
            "username": raw.get("username") or "",
            "department": raw.get("department"),
            "manager": raw.get("manager"),
            "job_title": raw.get("jobTitle"),
            "phone": phone,
            "mfa_enabled": bool(mfa_info.get("configured", False)),
            "employment_status": emp_status,
            "suspended": bool(raw.get("suspended", False)),
            "external_id": raw.get("_id"),
            "last_login": raw.get("lastUpdated"),
        }

    # MAC address patterns: "ae:78:9b:3d:a2:25" or "ae-78-9b-3d-a2-25"
    _MAC_RE = __import__("re").compile(
        r"^([0-9a-f]{2}[:\-]){5}[0-9a-f]{2}$", __import__("re").IGNORECASE
    )

    @classmethod
    def _clean_hostname(cls, raw_hostname: str) -> str:
        """Normalise a JumpCloud hostname for storage."""
        h = (raw_hostname or "").strip()
        # Reject known placeholder values
        if h.lower() in ("(string)", "string", "localhost", ""):
            return ""
        # Reject MAC addresses used as hostnames (JumpCloud fallback for unnamed systems)
        if cls._MAC_RE.match(h):
            return ""
        # Reject router-adopted hostnames (e.g. "Mac.fritz.box", "Mac.bbrouter")
        # These are network-assigned names with no value — the real name will come
        # from displayName via _normalize_system's generic-hostname override.
        for router_sfx in (".fritz.box", ".bbrouter", ".router", ".gateway", ".lan.local"):
            if h.lower().endswith(router_sfx):
                return ""

        # Strip DNS suffixes
        for sfx in (".corp.local", ".local", ".internal", ".corp", ".domain", ".home", ".lan"):
            if h.lower().endswith(sfx):
                h = h[: -len(sfx)]
                break
        # Handle possessive apostrophe: "bens's MacBook Air" → "bens MacBook Air"
        # (not "benss MacBook Air" which a plain replace would produce)
        for apos in ("'", "\u2019"):
            if apos in h:
                idx = h.index(apos)
                after = h[idx + 1:]
                if after.lower().startswith("s") and (len(after) == 1 or not after[1].isalpha()):
                    h = h[:idx] + h[idx + 2:]   # strip apostrophe AND the 's'
                else:
                    h = h.replace(apos, "")      # bare apostrophe: just remove
                break
        return h.strip()

    # Generic Apple device hostnames that macOS assigns when the computer
    # hasn't been named.  We prefer displayName over these.
    _GENERIC_APPLE_HOSTNAMES = {
        "mac", "macbook", "macbook air", "macbook pro", "imac",
        "mac mini", "mac pro", "mac studio", "ipad", "iphone", "ipod touch",
    }

    def _normalize_system(self, raw: dict) -> dict:
        ip = None
        remote_ip = raw.get("remoteIP")
        if remote_ip:
            ip = remote_ip

        raw_hostname = (raw.get("hostname") or "").strip()
        display_name = (raw.get("displayName") or "").strip()

        h_low = raw_hostname.lower()
        is_generic = (
            h_low in self._GENERIC_APPLE_HOSTNAMES          # bare "Mac", "MacBook", …
            or h_low.startswith("mac.")                      # Mac.fritz.box, Mac.bbrouter
            or h_low.startswith("macbook.")
        )
        if is_generic and display_name:
            # Use the admin-set displayName instead of the useless macOS hostname
            raw_hostname = display_name
        elif not raw_hostname:
            raw_hostname = display_name

        return {
            "hostname": self._clean_hostname(raw_hostname),
            "serial_number": raw.get("serialNumber") or raw.get("serial_number"),
            "os_version": f"{raw.get('os', '')} {raw.get('version', '')}".strip(),
            "ip_address": ip,
            "last_seen": raw.get("lastContact"),
            "external_id": raw.get("_id"),
            "is_active": raw.get("active", False),
        }

    async def _upsert_users(self, raw_list: list) -> int:
        import uuid as _uuid
        from sqlalchemy import select
        from app.models.user import User

        count = 0
        touched_ids: set[_uuid.UUID] = set()

        for raw in raw_list:
            normalized = self._normalize_user(raw)
            email = normalized.get("email")
            if not email:
                continue

            result = await self.db.execute(select(User).where(User.email == email))
            user = result.scalars().first()

            last_login = None
            if normalized.get("last_login"):
                try:
                    last_login = datetime.fromisoformat(normalized["last_login"].replace("Z", "+00:00"))
                except Exception:
                    pass

            # Build jumpcloud source entry
            jc_source = {
                "active": normalized.get("employment_status") == "active",
                "suspended": normalized.get("suspended", False),
                "mfa": normalized.get("mfa_enabled", False),
                "last_seen": normalized.get("last_login"),
                "external_id": normalized.get("external_id"),
                "username": normalized.get("username") or "",
            }

            if not user:
                user = User(
                    full_name=normalized.get("full_name") or email,
                    email=email,
                    department=normalized.get("department"),
                    manager=normalized.get("manager"),
                    job_title=normalized.get("job_title"),
                    phone=normalized.get("phone"),
                    mfa_enabled=normalized.get("mfa_enabled", False),
                    employment_status=normalized.get("employment_status", "active"),
                    suspended=normalized.get("suspended", False),
                    last_login=last_login,
                    sources={"jumpcloud": jc_source},
                )
                self.db.add(user)
                await self.db.flush()  # populate user.id before tracking
            else:
                if normalized.get("full_name"):
                    user.full_name = normalized["full_name"]
                if normalized.get("department"):
                    user.department = normalized["department"]
                if normalized.get("manager"):
                    user.manager = normalized["manager"]
                if normalized.get("job_title"):
                    user.job_title = normalized["job_title"]
                if normalized.get("phone"):
                    user.phone = normalized["phone"]
                user.mfa_enabled = normalized.get("mfa_enabled", user.mfa_enabled)
                user.employment_status = normalized.get("employment_status", user.employment_status)
                user.suspended = normalized.get("suspended", False)
                if last_login:
                    user.last_login = last_login
                # Merge sources: preserve existing keys (e.g. google), update jumpcloud
                existing_sources = dict(user.sources) if user.sources else {}
                existing_sources["jumpcloud"] = jc_source
                user.sources = existing_sources

            if user.id:
                touched_ids.add(user.id)
            count += 1

        await self.db.flush()

        # Prune: users with a JumpCloud source entry that weren't returned by the
        # API this sync have been deleted in JumpCloud — mark them inactive.
        jc_users = (
            await self.db.execute(
                select(User).where(
                    User.sources["jumpcloud"].isnot(None),
                    User.employment_status != "inactive",
                )
            )
        ).scalars().all()
        pruned = 0
        for u in jc_users:
            if u.id not in touched_ids:
                # Remove the JumpCloud source entry and mark inactive
                updated_sources = dict(u.sources) if u.sources else {}
                updated_sources.pop("jumpcloud", None)
                u.sources = updated_sources
                u.employment_status = "inactive"
                u.suspended = True
                pruned += 1
        if pruned:
            logger.info("JumpCloud: marked %d removed users as inactive", pruned)
            await self.db.flush()

        return count

    async def _upsert_systems(self, raw_list: list) -> int:
        import uuid as _uuid
        from sqlalchemy import select
        from app.models.endpoint import Endpoint
        from app.engines.correlation import find_endpoint_by_serial, normalize_serial

        count = 0
        touched_ids: set[_uuid.UUID] = set()

        for raw in raw_list:
            normalized = self._normalize_system(raw)
            hostname = normalized.get("hostname")
            if not hostname:
                continue

            serial = normalize_serial(normalized.get("serial_number"))

            last_seen = None
            if normalized.get("last_seen"):
                try:
                    last_seen = datetime.fromisoformat(normalized["last_seen"].replace("Z", "+00:00"))
                except Exception:
                    pass

            endpoint = None

            # 1. Try serial number match first — finds endpoints created by S1
            #    before JumpCloud synced (same physical machine, different hostname)
            if serial:
                endpoint = await find_endpoint_by_serial(self.db, serial)

            # 2. Fall back to exact hostname match
            if not endpoint:
                result = await self.db.execute(
                    select(Endpoint).where(Endpoint.hostname == hostname)
                )
                endpoint = result.scalars().first()

            if not endpoint:
                endpoint = Endpoint(
                    hostname=hostname,
                    serial_number=serial,
                    os_version=normalized.get("os_version"),
                    ip_address=normalized.get("ip_address"),
                    last_seen=last_seen or datetime.now(timezone.utc),
                    source="jumpcloud",
                    is_active=True,
                )
                self.db.add(endpoint)
                await self.db.flush()  # populate endpoint.id before tracking
            else:
                # JumpCloud takes ownership and updates key fields
                endpoint.source = "jumpcloud"
                endpoint.is_active = True   # re-activate if it was previously pruned
                endpoint.hostname = hostname   # use the clean JC hostname as canonical
                if serial:
                    endpoint.serial_number = serial
                if normalized.get("os_version"):
                    endpoint.os_version = normalized["os_version"]
                if normalized.get("ip_address"):
                    endpoint.ip_address = normalized["ip_address"]
                if last_seen:
                    endpoint.last_seen = last_seen

            if endpoint.id:
                touched_ids.add(endpoint.id)
            count += 1

        await self.db.flush()

        # Prune: any JumpCloud-sourced endpoint not seen in this sync was removed
        # from JumpCloud — mark it inactive so it disappears from the UI.
        jc_endpoints = (
            await self.db.execute(
                select(Endpoint).where(
                    Endpoint.source == "jumpcloud",
                    Endpoint.is_active == True,  # noqa: E712
                )
            )
        ).scalars().all()
        pruned = 0
        for ep in jc_endpoints:
            if ep.id not in touched_ids:
                ep.is_active = False
                pruned += 1
        if pruned:
            logger.info("JumpCloud: marked %d removed systems as inactive", pruned)
            await self.db.flush()

        return count

    async def _fetch_events(self) -> list[dict]:
        cutoff = datetime.now(timezone.utc) - timedelta(days=_RETENTION_DAYS)
        start_time = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")
        end_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        results: list[dict] = []
        search_after: Optional[list] = None
        limit = 1000
        async with httpx.AsyncClient(timeout=60.0) as client:
            while len(results) < _MAX_EVENTS:
                body: dict[str, Any] = {
                    "service": ["all"],
                    "start_time": start_time,
                    "end_time": end_time,
                    "limit": limit,
                    "sort": "DESC",
                }
                if search_after:
                    body["searchAfter"] = search_after
                resp = await client.post(
                    f"{_INSIGHTS_BASE}/events",
                    headers=self._headers(),
                    json=body,
                )
                resp.raise_for_status()
                batch = resp.json()
                if not batch:
                    break
                results.extend(batch)
                if len(batch) < limit:
                    break
                last = batch[-1]
                search_after = [last.get("timestamp"), last.get("id")]
        logger.info("JumpCloud Events: fetched %d raw events", len(results))
        return results

    @staticmethod
    def _map_event(raw: dict) -> Optional[dict]:
        jc_type = raw.get("event_type") or raw.get("type") or ""
        our_type = _EVENT_TYPE_MAP.get(jc_type)
        if not our_type:
            return None

        ts_str = raw.get("timestamp") or raw.get("initiated_at")
        timestamp = datetime.now(timezone.utc)
        if ts_str:
            try:
                timestamp = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            except Exception:
                pass

        initiated_by_raw = raw.get("initiated_by")
        initiated_by = initiated_by_raw if isinstance(initiated_by_raw, dict) else {}
        resource_raw = raw.get("resource")
        resource = resource_raw if isinstance(resource_raw, dict) else {}

        # Resolve actor email: admin events have email; user events have username
        email = (
            initiated_by.get("email")
            or resource.get("email")
            or raw.get("username")
            or ""
        )

        # client_ip is the correct field in JC Insights API
        ip = raw.get("client_ip") or raw.get("ip") or None

        geoip_raw = raw.get("geoip")
        geoip = geoip_raw if isinstance(geoip_raw, dict) else {}
        country = geoip.get("country_code") or geoip.get("country_name") or None

        success = raw.get("success")
        if success is None:
            success = True
        suspicious = jc_type in _ALWAYS_SUSPICIOUS or (
            jc_type in _AUTH_EVENT_TYPES and not success
        )

        details: dict[str, Any] = {
            "app": "jumpcloud",
            "event_name": jc_type,
            "success": success,
        }

        # Actor identity
        actor = (
            initiated_by.get("email")
            or initiated_by.get("username")
            or initiated_by.get("name")
        )
        if actor:
            details["actor"] = actor
        if initiated_by.get("type"):
            details["actor_type"] = initiated_by["type"]

        # SAML application name
        app_raw = raw.get("application")
        app_info = app_raw if isinstance(app_raw, dict) else {}
        app_name = (
            app_info.get("display_label")
            or raw.get("jc_application_name")
            or app_info.get("name")
        )
        if app_name:
            details["app_name"] = app_name

        # Target resource
        target_raw = raw.get("target_resource")
        target = target_raw if isinstance(target_raw, dict) else {}
        if target.get("type"):
            details["target_type"] = target["type"]

        # Browser / OS from useragent
        ua_raw = raw.get("useragent")
        ua = ua_raw if isinstance(ua_raw, dict) else {}
        if ua.get("name"):
            details["browser"] = ua["name"]
        if ua.get("os_name"):
            details["os"] = ua.get("os_full") or ua["os_name"]

        # Location detail
        if geoip.get("city"):
            details["city"] = geoip["city"]

        # MFA flag
        mfa_raw = raw.get("mfa")
        if isinstance(mfa_raw, bool):
            details["mfa"] = mfa_raw
        elif isinstance(mfa_raw, dict) and mfa_raw.get("method"):
            details["mfa"] = True
            details["mfa_method"] = mfa_raw["method"]

        # Error message on failed events
        err = raw.get("error_message")
        if err:
            details["error"] = err

        # Out-of-bounds flag
        if raw.get("is_out_of_bound"):
            details["out_of_bounds"] = True

        jc_id = raw.get("id") or raw.get("_id")
        if jc_id:
            details["jc_event_id"] = jc_id

        return {
            "event_type": our_type,
            "timestamp": timestamp,
            "email": email.lower().strip() if email else "",
            "ip_address": ip,
            "country": country,
            "is_suspicious": suspicious,
            "details": details,
            "external_id": f"jc_{jc_id}" if jc_id else None,
        }

    async def _sync_events(self, raw_events: list[dict]) -> int:
        import uuid as _uuid
        from sqlalchemy import delete, select as sa_select
        from sqlalchemy.dialects.postgresql import insert as pg_insert
        from app.models.activity import ActivityEvent
        from app.models.user import User

        if not raw_events:
            return 0

        mapped = [self._map_event(e) for e in raw_events]
        mapped = [m for m in mapped if m is not None]
        if not mapped:
            logger.info("JumpCloud Events: 0 mappable events after filtering")
            return 0

        emails = {m["email"] for m in mapped if m["email"]}
        user_cache: dict[str, Any] = {}
        if emails:
            rows = (
                await self.db.execute(sa_select(User).where(User.email.in_(emails)))
            ).scalars().all()
            user_cache = {u.email: u for u in rows}

        # Secondary lookup: match events whose actor is a JC username (no email)
        # against users who have sources->jumpcloud->username set
        unmatched_actors = {
            m["details"].get("actor")
            for m in mapped
            if not user_cache.get(m["email"]) and m["details"].get("actor")
        }
        username_cache: dict[str, Any] = {}
        if unmatched_actors:
            from sqlalchemy import cast, String
            from sqlalchemy.dialects.postgresql import JSONB
            username_rows = (
                await self.db.execute(
                    sa_select(User).where(
                        User.sources["jumpcloud"]["username"].as_string().in_(unmatched_actors)
                    )
                )
            ).scalars().all()
            username_cache = {
                u.sources["jumpcloud"]["username"]: u
                for u in username_rows
                if u.sources and u.sources.get("jumpcloud", {}).get("username")
            }

        cutoff = datetime.now(timezone.utc) - timedelta(days=_RETENTION_DAYS)
        await self.db.execute(
            delete(ActivityEvent).where(
                ActivityEvent.details["app"].as_string() == "jumpcloud",
                ActivityEvent.timestamp >= cutoff,
            )
        )

        count = 0
        for m in mapped:
            user = user_cache.get(m["email"]) or username_cache.get(
                m["details"].get("actor", "")
            )
            try:
                from sqlalchemy import text as _text
                stmt = pg_insert(ActivityEvent).values(
                    id=_uuid.uuid4(),
                    user_id=user.id if user else None,
                    event_type=m["event_type"],
                    timestamp=m["timestamp"],
                    ip_address=m["ip_address"],
                    country=m["country"],
                    is_suspicious=m["is_suspicious"],
                    details=m["details"],
                    external_id=m.get("external_id"),
                ).on_conflict_do_nothing(
                    index_elements=["external_id"],
                    index_where=_text("external_id IS NOT NULL"),
                )
                await self.db.execute(stmt)
                count += 1
            except Exception as e:
                logger.warning("JumpCloud Events: failed to add event: %s", e)

        await self.db.flush()
        logger.info("JumpCloud Events: synced %d activity events", count)
        return count
