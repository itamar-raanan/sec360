import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

# AD epoch: 100-nanosecond intervals since 1601-01-01
_AD_EPOCH_OFFSET = 116444736000000000  # ticks between 1601-01-01 and 1970-01-01


def _ad_timestamp_to_datetime(value: Any) -> datetime | None:
    """Convert Active Directory lastLogonTimestamp (integer ticks) to datetime."""
    try:
        v = int(value)
        if v <= 0:
            return None
        unix_ts = (v - _AD_EPOCH_OFFSET) / 10_000_000
        return datetime.fromtimestamp(unix_ts, tz=timezone.utc)
    except Exception:
        return None


class ActiveDirectoryCollector:
    name = "active_directory"

    def __init__(self, credentials: dict, db: AsyncSession):
        self.credentials_mode = str(credentials.get("import_mode", "live"))
        self.ldap_host = credentials.get("ldap_host", "")
        self.ldap_port = int(credentials.get("ldap_port") or 389)
        self.base_dn = credentials.get("base_dn", "")
        self.bind_dn = credentials.get("bind_dn", "")
        self.bind_password = credentials.get("bind_password", "")
        self.use_ssl = str(credentials.get("use_ssl", "false")).lower() == "true"
        self.db = db

    def _make_connection(self):
        from ldap3 import Server, Connection, ALL, SAFE_SYNC

        server = Server(
            self.ldap_host,
            port=self.ldap_port,
            use_ssl=self.use_ssl,
            get_info=ALL,
            connect_timeout=15,
        )
        conn = Connection(
            server,
            user=self.bind_dn,
            password=self.bind_password,
            auto_bind=True,
            client_strategy=SAFE_SYNC,
            raise_exceptions=True,
        )
        return conn

    async def test_connection(self) -> dict:
        if self.credentials_mode == "manual":
            return {"success": True, "message": "Manual CSV import mode is configured."}
        if not self.ldap_host:
            return {"success": False, "message": "No LDAP host configured"}
        if not self.bind_dn or not self.bind_password:
            return {"success": False, "message": "Bind DN and password are required"}
        if not self.base_dn:
            return {"success": False, "message": "Base DN is required"}

        loop = asyncio.get_event_loop()
        try:
            result = await loop.run_in_executor(None, self._test_sync)
            return result
        except Exception as e:
            return {"success": False, "message": f"Connection error: {str(e)}"}

    def _test_sync(self) -> dict:
        try:
            conn = self._make_connection()
            conn.search(
                search_base=self.base_dn,
                search_filter="(&(objectClass=person)(objectClass=user))",
                attributes=["sAMAccountName"],
                size_limit=1,
            )
            conn.unbind()
            return {"success": True, "message": f"Connected to {self.ldap_host}. LDAP bind successful."}
        except Exception as e:
            return {"success": False, "message": f"LDAP error: {str(e)}"}

    async def collect(self) -> dict:
        if self.credentials_mode == "manual":
            return {"records_synced": 0, "manual": True}
        if not self.ldap_host or not self.base_dn or not self.bind_dn:
            return {"records_synced": 0, "error": "LDAP host, base DN, and bind DN are required"}

        loop = asyncio.get_event_loop()
        try:
            users_raw, computers_raw = await loop.run_in_executor(None, self._collect_sync)
        except Exception as e:
            logger.error(f"AD collect error: {e}", exc_info=True)
            return {"records_synced": 0, "error": str(e)}

        user_count = await self._upsert_users(users_raw)
        computer_count = await self._upsert_computers(computers_raw)

        return {"records_synced": user_count + computer_count, "users": user_count, "endpoints": computer_count}

    def _collect_sync(self) -> tuple[list[dict], list[dict]]:
        conn = self._make_connection()

        # Fetch enabled users
        conn.search(
            search_base=self.base_dn,
            search_filter="(&(objectClass=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            attributes=["sAMAccountName", "mail", "displayName", "department", "title", "userAccountControl"],
            paged_size=500,
        )
        users_raw: list[dict] = []
        for entry in conn.entries:
            users_raw.append({
                "sAMAccountName": _str_attr(entry, "sAMAccountName"),
                "mail": _str_attr(entry, "mail"),
                "displayName": _str_attr(entry, "displayName"),
                "department": _str_attr(entry, "department"),
                "title": _str_attr(entry, "title"),
                "userAccountControl": _str_attr(entry, "userAccountControl"),
            })

        # Fetch computers
        conn.search(
            search_base=self.base_dn,
            search_filter="(objectClass=computer)",
            attributes=["name", "operatingSystem", "operatingSystemVersion", "dNSHostName", "lastLogonTimestamp"],
            paged_size=500,
        )
        computers_raw: list[dict] = []
        for entry in conn.entries:
            computers_raw.append({
                "name": _str_attr(entry, "name"),
                "operatingSystem": _str_attr(entry, "operatingSystem"),
                "operatingSystemVersion": _str_attr(entry, "operatingSystemVersion"),
                "dNSHostName": _str_attr(entry, "dNSHostName"),
                "lastLogonTimestamp": _str_attr(entry, "lastLogonTimestamp"),
            })

        conn.unbind()
        return users_raw, computers_raw

    async def _upsert_users(self, raw_list: list[dict]) -> int:
        from sqlalchemy import func, select
        from app.models.user import User

        # Resolve all existing rows in bounded batches instead of issuing one
        # SELECT per CSV row. This keeps large manual imports from appearing to
        # hang and also makes live LDAP synchronization substantially faster.
        prepared: dict[str, dict] = {}
        for raw in raw_list:
            email = str(raw.get("mail", "")).strip()
            sam = str(raw.get("sAMAccountName", "")).strip()
            if not email and not sam:
                continue
            if not email:
                email = sam
            prepared[email.lower()] = {**raw, "mail": email, "sAMAccountName": sam}

        existing_by_email: dict[str, User] = {}
        email_keys = list(prepared)
        for offset in range(0, len(email_keys), 500):
            result = await self.db.execute(
                select(User).where(func.lower(User.email).in_(email_keys[offset:offset + 500]))
            )
            for existing in result.scalars().all():
                existing_by_email[existing.email.lower()] = existing

        for email_key, raw in prepared.items():
            email = raw["mail"]
            sam = raw["sAMAccountName"]
            user = existing_by_email.get(email_key)
            display_name = raw.get("displayName") or sam or email
            department = raw.get("department")
            job_title = raw.get("title")
            is_enabled = raw.get("enabled") is not False
            ad_source = {"sAMAccountName": sam, "enabled": is_enabled}

            if not user:
                user = User(
                    full_name=display_name,
                    email=email,
                    department=department,
                    employment_status="active" if is_enabled else "inactive",
                    mfa_enabled=False,
                    suspended=False,
                    job_title=job_title or None,
                    sources={"active_directory": ad_source},
                )
                self.db.add(user)
            else:
                if display_name:
                    user.full_name = display_name
                if department:
                    user.department = department
                if job_title:
                    user.job_title = job_title
                sources = dict(user.sources or {})
                sources["active_directory"] = ad_source
                user.sources = sources
                user.employment_status = "active" if is_enabled else "inactive"
                user.suspended = False

        await self.db.flush()
        return len(prepared)

    async def link_users_to_endpoints(self, emails: list[str]) -> int:
        """Link imported users by exact email-prefix ↔ endpoint-username match."""
        from sqlalchemy import func, select
        from app.engines.correlation import normalize_username
        from app.models.endpoint import Endpoint
        from app.models.user import User

        email_keys = sorted({email.strip().lower() for email in emails if email.strip()})
        imported_users: list[User] = []
        for offset in range(0, len(email_keys), 500):
            result = await self.db.execute(
                select(User).where(func.lower(User.email).in_(email_keys[offset:offset + 500]))
            )
            imported_users.extend(result.scalars().all())

        # A local part can exist in more than one email domain. Do not make an
        # ambiguous ownership assignment in that case.
        users_by_prefix: dict[str, User | None] = {}
        for user in imported_users:
            prefix = user.email.split("@", 1)[0].strip().lower()
            if not prefix:
                continue
            users_by_prefix[prefix] = user if prefix not in users_by_prefix else None

        if not users_by_prefix:
            return 0

        endpoints = (await self.db.execute(
            select(Endpoint).where(
                Endpoint.username.is_not(None),
                Endpoint.lifecycle_state.notin_(("ignored", "decommissioned")),
            )
        )).scalars().all()
        linked = 0
        for endpoint in endpoints:
            user = users_by_prefix.get(normalize_username(endpoint.username or ""))
            if user is not None and endpoint.owner_user_id != user.id:
                endpoint.owner_user_id = user.id
                linked += 1

        await self.db.flush()
        return linked

    async def _upsert_computers(self, raw_list: list[dict]) -> int:
        from sqlalchemy import func, select
        from app.models.endpoint import Endpoint

        count = 0
        for raw in raw_list:
            hostname = (raw.get("dNSHostName") or raw.get("name") or "").strip()
            if not hostname:
                continue

            # Strip domain suffix from DNS hostname for storage
            short_hostname = hostname.split(".")[0] if "." in hostname else hostname

            os_name = raw.get("operatingSystem") or ""
            os_ver = raw.get("operatingSystemVersion") or ""
            os_version = f"{os_name} {os_ver}".strip() or None

            last_seen = _ad_timestamp_to_datetime(raw.get("lastLogonTimestamp"))

            result = await self.db.execute(
                select(Endpoint).where(func.lower(Endpoint.hostname) == short_hostname.lower())
            )
            endpoint = result.scalars().first()

            if not endpoint:
                endpoint = Endpoint(
                    hostname=short_hostname,
                    os_version=os_version,
                    last_seen=last_seen or datetime.now(timezone.utc),
                    source="active_directory",
                )
                self.db.add(endpoint)
            else:
                endpoint.source = "active_directory"
                if os_version:
                    endpoint.os_version = os_version
                if last_seen:
                    endpoint.last_seen = last_seen

            count += 1

        await self.db.flush()
        return count


def _str_attr(entry: Any, attr_name: str) -> str:
    """Safely extract a string value from an ldap3 entry attribute."""
    try:
        val = getattr(entry, attr_name, None)
        if val is None:
            return ""
        # ldap3 attributes have a .value property
        raw = val.value
        if raw is None:
            return ""
        if isinstance(raw, list):
            return str(raw[0]) if raw else ""
        return str(raw)
    except Exception:
        return ""
