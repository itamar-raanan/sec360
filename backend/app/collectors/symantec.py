import asyncio
import logging
from typing import Any
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from app.collectors.base import BaseCollector
from app.core.config import settings

logger = logging.getLogger(__name__)


class SymantecCollector(BaseCollector):
    name = "symantec"

    def __init__(self, credentials: dict = None, db: AsyncSession = None):
        super().__init__()
        if credentials:
            self.db_type = credentials.get("db_type", "postgresql")
            self.db_host = credentials.get("db_host", "")
            self.db_port = credentials.get("db_port", 5432)
            self.db_name = credentials.get("db_name", "")
            self.db_user = credentials.get("db_user", "")
            self.db_password = credentials.get("db_password", "")
        else:
            # Legacy env-based config (not used for DLP DB connection)
            self.db_type = "postgresql"
            self.db_host = settings.SYMANTEC_URL or ""
            self.db_port = 5432
            self.db_name = ""
            self.db_user = settings.SYMANTEC_USERNAME or ""
            self.db_password = settings.SYMANTEC_PASSWORD or ""
        self.db = db

    def _is_oracle(self) -> bool:
        return self.db_type == "oracle"

    async def test_connection(self) -> dict:
        if not self.db_host:
            return {"success": False, "message": "No database host configured"}
        try:
            if self._is_oracle():
                return await self._test_oracle()
            else:
                return await self._test_generic()
        except Exception as e:
            return {"success": False, "message": f"Connection failed: {str(e)}"}

    async def _test_oracle(self) -> dict:
        import oracledb

        def _run():
            dsn = f"{self.db_host}:{self.db_port}/{self.db_name}"
            conn = oracledb.connect(user=self.db_user, password=self.db_password, dsn=dsn)
            try:
                cur = conn.cursor()
                cur.execute("SELECT 1 FROM DUAL")
                cur.fetchone()
                return {"success": True, "message": "Oracle connection successful"}
            finally:
                conn.close()

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _run)

    async def _test_generic(self) -> dict:
        import sqlalchemy
        from sqlalchemy import text as sa_text

        if self.db_type == "mssql":
            conn_str = f"mssql+pymssql://{self.db_user}:{self.db_password}@{self.db_host}:{self.db_port}/{self.db_name}"
        else:
            conn_str = f"postgresql://{self.db_user}:{self.db_password}@{self.db_host}:{self.db_port}/{self.db_name}"

        def _run():
            engine = sqlalchemy.create_engine(conn_str)
            try:
                with engine.connect() as conn:
                    conn.execute(sa_text("SELECT 1"))
                return {"success": True, "message": "Database connection successful"}
            finally:
                engine.dispose()

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _run)

    async def collect(self) -> dict:
        if not self.db_host:
            return {"records_synced": 0, "error": "No database host configured"}
        try:
            records = await self._query_dlp_agents()
            count = await self._upsert_agents(records)
            return {"records_synced": count}
        except Exception as e:
            logger.error(f"Symantec: collect failed: {e}", exc_info=True)
            return {"records_synced": 0, "error": str(e)}

    async def _query_dlp_agents(self) -> list:
        if self._is_oracle():
            return await self._query_oracle()
        else:
            return await self._query_generic()

    async def _query_oracle(self) -> list:
        import oracledb

        query = """
            SELECT
                A.AGENTNAME,
                A.VERSION,
                A.LASTCONNECTIONTIME,
                AUV.USERNAME,
                DECODE(A.STATUS, 1, 'Enabled', 2, 'Disabled', 3, 'Blocked', 'Unknown') AS AGENTSTATENAME,
                AG.NAME AS AGENTGROUPNAME
            FROM PROTECT.AGENT A
            LEFT JOIN AGENTUSERNAMEVIEW AUV
                ON A.AGENTID = AUV.AGENTID
            LEFT JOIN PROTECT.AGENTGROUP AG
                ON A.LASTAGENTGROUPID = AG.ID
            WHERE A.ISDELETED = 0
        """

        def _run():
            dsn = f"{self.db_host}:{self.db_port}/{self.db_name}"
            conn = oracledb.connect(user=self.db_user, password=self.db_password, dsn=dsn)
            try:
                cur = conn.cursor()
                cur.execute(query)
                columns = [col[0].lower() for col in cur.description]
                return [dict(zip(columns, row)) for row in cur.fetchall()]
            finally:
                conn.close()

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _run)

    async def _query_generic(self) -> list:
        import sqlalchemy
        from sqlalchemy import text as sa_text

        if self.db_type == "mssql":
            conn_str = f"mssql+pymssql://{self.db_user}:{self.db_password}@{self.db_host}:{self.db_port}/{self.db_name}"
        else:
            conn_str = f"postgresql://{self.db_user}:{self.db_password}@{self.db_host}:{self.db_port}/{self.db_name}"

        query = (
            "SELECT computer_name AS agentname, agent_version AS version, "
            "last_contact AS lastconnectiontime, NULL AS username, "
            "NULL AS agentstatename, NULL AS agentgroupname "
            "FROM sem_agent"
        )

        def _run():
            engine = sqlalchemy.create_engine(conn_str)
            try:
                with engine.connect() as conn:
                    result = conn.execute(sa_text(query))
                    columns = [c.lower() for c in result.keys()]
                    return [dict(zip(columns, row)) for row in result.fetchall()]
            finally:
                engine.dispose()

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _run)

    # ── Hostname cleaning (same suffixes as JumpCloud collector) ─────────────
    _DNS_SUFFIXES = (
        ".corp.local", ".local", ".internal", ".corp", ".domain", ".home", ".lan",
    )

    @classmethod
    def _clean_hostname(cls, raw: str) -> str:
        """Normalise a Symantec DLP hostname for storage."""
        h = (raw or "").strip()
        if h.lower() in ("(string)", "string", "localhost", ""):
            return ""
        for sfx in cls._DNS_SUFFIXES:
            if h.lower().endswith(sfx):
                h = h[: -len(sfx)]
                break
        h = h.replace("'", "").replace("\u2019", "")
        return h.strip()

    async def _upsert_agents(self, records: list) -> int:
        from datetime import timedelta
        from sqlalchemy import select
        from app.models.endpoint import Endpoint
        from app.models.agent import SecurityAgent
        from app.engines.correlation import (
            find_endpoint_by_hostname,
            normalize_username,
            normalize_hostname,
        )

        # Only process records active in the last 60 days — skip stale DLP entries
        cutoff = datetime.now(timezone.utc) - timedelta(days=60)

        count = 0
        for record in records:
            hostname_raw = record.get("agentname")
            if not hostname_raw:
                continue

            version     = record.get("version")
            username    = record.get("username")
            agent_state = record.get("agentstatename") or None
            agent_group = record.get("agentgroupname") or None

            # ── Parse last_seen ──────────────────────────────────────────────
            last_seen = None
            raw_ts = record.get("lastconnectiontime")
            if raw_ts is not None:
                try:
                    if hasattr(raw_ts, 'isoformat'):
                        dt = datetime(
                            raw_ts.year, raw_ts.month, raw_ts.day,
                            raw_ts.hour, raw_ts.minute, raw_ts.second,
                            getattr(raw_ts, 'microsecond', 0),
                        )
                        last_seen = dt.replace(tzinfo=timezone.utc)
                    else:
                        from dateutil import parser as dateparser
                        parsed = dateparser.parse(str(raw_ts))
                        if parsed:
                            last_seen = parsed.replace(tzinfo=timezone.utc) if not parsed.tzinfo else parsed
                except Exception:
                    pass

            # Skip DLP records that haven't checked in for 60 days
            if last_seen and last_seen < cutoff:
                continue

            # ── Determine agent status ───────────────────────────────────────
            agent_status = "inactive"
            if last_seen:
                age_hours = (datetime.now(timezone.utc) - last_seen).total_seconds() / 3600
                agent_status = "active" if age_hours <= 24 else "inactive"

            # ── Clean hostname (strip .lan, .local, etc.) ────────────────────
            hostname = self._clean_hostname(hostname_raw)
            if not hostname:
                continue

            # ── Endpoint lookup: hostname first, then username fallback ──────
            endpoint = await find_endpoint_by_hostname(self.db, hostname)

            # Username-based fallback: if no hostname match and we have a
            # real username, search JumpCloud endpoints whose username or
            # normalised hostname matches the DLP username prefix.
            if not endpoint and username:
                norm_dlp_user = normalize_username(username)
                if norm_dlp_user and norm_dlp_user not in (
                    "admin", "administrator", "user", "guest", "root", "system"
                ) and len(norm_dlp_user) >= 4:
                    result = await self.db.execute(
                        select(Endpoint).where(Endpoint.source == "jumpcloud")
                    )
                    jc_endpoints = result.scalars().all()
                    for ep in jc_endpoints:
                        ep_norm_user = normalize_username(ep.username or "")
                        ep_norm_host = normalize_hostname(ep.hostname)
                        if (ep_norm_user == norm_dlp_user
                                or ep_norm_host == norm_dlp_user
                                or ep_norm_host.startswith(norm_dlp_user)
                                or norm_dlp_user.startswith(ep_norm_host)):
                            endpoint = ep
                            logger.info(
                                "Symantec: matched %r → %r via username %r",
                                hostname, ep.hostname, norm_dlp_user,
                            )
                            break

            if not endpoint:
                # Create new endpoint sourced from Symantec
                endpoint = Endpoint(
                    hostname=hostname,   # already cleaned
                    last_seen=last_seen or datetime.now(timezone.utc),
                    username=username or None,
                    source="symantec",
                )
                self.db.add(endpoint)
                await self.db.flush()
            else:
                if endpoint.source == "jumpcloud":
                    # JC-owned: only fill in missing fields
                    if username and not endpoint.username:
                        endpoint.username = username
                else:
                    # DLP-owned: DLP is the live source — always refresh
                    if username:
                        endpoint.username = username
                    if last_seen:
                        endpoint.last_seen = last_seen   # keep alive

            # ── Upsert Symantec DLP agent record ─────────────────────────────
            agent_result = await self.db.execute(
                select(SecurityAgent).where(
                    SecurityAgent.endpoint_id == endpoint.id,
                    SecurityAgent.product_name == "symantec",
                )
            )
            agent = agent_result.scalars().first()

            if not agent:
                agent = SecurityAgent(
                    endpoint_id=endpoint.id,
                    product_name="symantec",
                    status=agent_status,
                    version=str(version) if version else None,
                    last_seen=last_seen,
                    agent_state=agent_state,
                    agent_group=agent_group,
                )
                self.db.add(agent)
            else:
                agent.status = agent_status
                if version:
                    agent.version = str(version)
                if last_seen:
                    agent.last_seen = last_seen
                # Always refresh state & group (they can change without a hostname change)
                agent.agent_state = agent_state
                agent.agent_group = agent_group

            count += 1

        await self.db.flush()
        return count

    # Legacy support
    async def fetch_data(self) -> list[dict[str, Any]]:
        logger.warning("Symantec: Not configured for legacy fetch, skipping")
        return []

    async def normalize(self, raw_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return raw_items

    async def upsert_to_db(self, normalized: list[dict[str, Any]], db) -> None:
        pass
