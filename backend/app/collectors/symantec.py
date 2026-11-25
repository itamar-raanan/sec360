import asyncio
import logging
from time import perf_counter
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

    async def collect_inventory(self) -> dict:
        """Refresh agent identities and endpoint mappings without policy SQL."""
        if not self.db_host:
            return {"records_synced": 0, "error": "No database host configured"}
        try:
            started = perf_counter()
            records = await self._query_dlp_agents()
            logger.info("Symantec: inventory query returned %d rows in %.2fs", len(records), perf_counter() - started)
            started = perf_counter()
            count = await self._upsert_agents(records)
            logger.info("Symantec: synced %d agent records in %.2fs", count, perf_counter() - started)
            return {"records_synced": count}
        except Exception as e:
            logger.error("Symantec: inventory collect failed: %s", e, exc_info=True)
            return {"records_synced": 0, "error": str(e)}

    async def collect(self) -> dict:
        """Scheduled/full refresh includes optional policy change tracking."""
        inventory_result = await self.collect_inventory()
        if inventory_result.get("error"):
            return inventory_result
        try:
            count = inventory_result["records_synced"]
            policy_count = 0
            policy_changes = 0
            if self._is_oracle():
                try:
                    from app.services.dlp_policy_search import query_dlp_policy_exclusions
                    from app.services.dlp_policy_tracking import capture_dlp_policy_changes

                    started = perf_counter()
                    policy_rows, truncated = await query_dlp_policy_exclusions({
                        "db_host": self.db_host,
                        "db_port": self.db_port,
                        "db_name": self.db_name,
                        "db_user": self.db_user,
                        "db_password": self.db_password,
                    })
                    logger.info("Symantec: policy query returned %d rows in %.2fs", len(policy_rows), perf_counter() - started)
                    policy_count = len(policy_rows)
                    # Isolate optional policy tracking so a schema-specific
                    # failure cannot leave partial snapshots in this sync.
                    async with self.db.begin_nested():
                        policy_changes = await capture_dlp_policy_changes(
                            self.db, policy_rows, complete=not truncated,
                        )
                except Exception as policy_error:
                    # Endpoint inventory should still sync if the optional
                    # policy metadata query is unsupported by this DLP schema.
                    logger.warning("Symantec: policy change tracking failed: %s", policy_error, exc_info=True)
            return {
                "records_synced": count,
                "policy_patterns_synced": policy_count,
                "policy_changes_logged": policy_changes,
            }
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
                A.AGENTID,
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
            "SELECT computer_name AS agentid, computer_name AS agentname, agent_version AS version, "
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
        import uuid as _uuid
        from sqlalchemy import exists, func, select
        from app.models.endpoint import Endpoint
        from app.models.agent import SecurityAgent
        from app.services.endpoint_inventory import restore_endpoint_from_inventory

        # Legacy correlation can leave two authoritative DLP IDs attached to
        # one endpoint. Plan the repair against the complete snapshot before
        # processing rows, so Oracle result order cannot choose the winner.
        source_hostnames = {}
        for record in records:
            hostname = self._clean_hostname(record.get("agentname"))
            source_id = str(record.get("agentid") or record.get("agentname") or "").strip()
            if hostname and source_id:
                source_hostnames.setdefault(source_id, hostname)
        existing_agents = (await self.db.execute(
            select(SecurityAgent).where(SecurityAgent.product_name == "symantec")
        )).scalars().all()
        agents_by_source = {agent.source_id: agent for agent in existing_agents if agent.source_id}
        mapped_endpoint_ids = {agent.endpoint_id for agent in existing_agents}
        endpoints_by_id = {
            endpoint.id: endpoint
            for endpoint in (await self.db.execute(
                select(Endpoint).where(Endpoint.id.in_(mapped_endpoint_ids))
            )).scalars()
        }
        current_sources_by_endpoint: dict[_uuid.UUID, list[str]] = {}
        for agent in existing_agents:
            if agent.source_id in source_hostnames:
                current_sources_by_endpoint.setdefault(agent.endpoint_id, []).append(agent.source_id)
        keep_source_by_endpoint: dict[_uuid.UUID, str | None] = {}
        for endpoint_id, source_ids in current_sources_by_endpoint.items():
            if len(source_ids) < 2:
                continue
            endpoint = endpoints_by_id.get(endpoint_id)
            exact_matches = [
                source_id for source_id in source_ids
                if endpoint and self._clean_hostname(endpoint.hostname).casefold()
                == source_hostnames[source_id].casefold()
            ]
            # With no unique name match, no source record has sufficient
            # evidence to inherit the shared endpoint's identity or exceptions.
            keep_source_by_endpoint[endpoint_id] = exact_matches[0] if len(exact_matches) == 1 else None

        count = 0
        touched_agent_ids: set[_uuid.UUID] = set()
        claimed_endpoint_ids: set[_uuid.UUID] = set()
        reassigned_endpoint_ids: set[_uuid.UUID] = set()
        seen_source_ids: set[str] = set()
        for record in records:
            hostname_raw = record.get("agentname")
            if not hostname_raw:
                continue

            # Oracle AGENTID is the authoritative DLP identity. The hostname
            # fallback keeps generic/legacy connectors stable.
            source_id = str(record.get("agentid") or hostname_raw).strip()
            if not source_id or source_id in seen_source_ids:
                continue
            seen_source_ids.add(source_id)

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

            # ── Determine agent status ───────────────────────────────────────
            agent_status = "inactive"
            if last_seen:
                age_hours = (datetime.now(timezone.utc) - last_seen).total_seconds() / 3600
                agent_status = "active" if age_hours <= 24 else "inactive"

            # ── Clean hostname (strip .lan, .local, etc.) ────────────────────
            hostname = self._clean_hostname(hostname_raw)
            if not hostname:
                continue

            # Reuse the product's prior mapping first. Hostnames and usernames
            # can change and are not authoritative identities.
            agent = agents_by_source.get(source_id)
            endpoint = endpoints_by_id.get(agent.endpoint_id) if agent else None
            if endpoint and (
                endpoint.id in keep_source_by_endpoint
                and keep_source_by_endpoint[endpoint.id] != source_id
            ):
                reassigned_endpoint_ids.add(endpoint.id)
                logger.info(
                    "Symantec: repairing shared endpoint mapping for agent %s; source hostname %r, previous endpoint %r",
                    source_id, hostname, endpoint.hostname,
                )
                endpoint = None
            if endpoint and endpoint.id in claimed_endpoint_ids:
                endpoint = None

            # An exact hostname can link a previously unmapped DLP agent to
            # another source. Usernames and lossy hostname slugs identify a
            # person, not a machine, and must not select its endpoint.
            if not endpoint:
                candidates = (await self.db.execute(
                    select(Endpoint).where(
                        func.lower(Endpoint.hostname) == hostname.lower(),
                        Endpoint.id.not_in(claimed_endpoint_ids),
                        ~exists().where(
                            SecurityAgent.endpoint_id == Endpoint.id,
                            SecurityAgent.product_name == "symantec",
                            SecurityAgent.source_id.is_not(None),
                            SecurityAgent.source_id != source_id,
                        ),
                    )
                )).scalars().all()
                if len(candidates) == 1:
                    endpoint = candidates[0]

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
                restore_endpoint_from_inventory(endpoint, "symantec_dlp")
                if endpoint.source == "symantec":
                    endpoint.hostname = hostname
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
            if not agent:
                # Adopt one pre-migration row on the matched endpoint. Once it
                # receives a source_id, subsequent source agents remain distinct.
                agent = (await self.db.execute(
                    select(SecurityAgent).where(
                        SecurityAgent.endpoint_id == endpoint.id,
                        SecurityAgent.product_name == "symantec",
                        SecurityAgent.source_id.is_(None),
                    )
                )).scalars().first()

            if not agent:
                agent = SecurityAgent(
                    endpoint_id=endpoint.id,
                    product_name="symantec",
                    source_id=source_id,
                    status=agent_status,
                    version=str(version) if version else None,
                    last_seen=last_seen,
                    agent_state=agent_state,
                    agent_group=agent_group,
                )
                self.db.add(agent)
            else:
                agent.endpoint_id = endpoint.id
                agent.source_id = source_id
                agent.status = agent_status
                if version:
                    agent.version = str(version)
                if last_seen:
                    agent.last_seen = last_seen
                # Always refresh state & group (they can change without a hostname change)
                agent.agent_state = agent_state
                agent.agent_group = agent_group

            await self.db.flush()
            agents_by_source[source_id] = agent
            endpoints_by_id[endpoint.id] = endpoint
            touched_agent_ids.add(agent.id)
            claimed_endpoint_ids.add(endpoint.id)
            count += 1

        await self.db.flush()

        # A successful full DLP query is authoritative. Remove product rows
        # that were not returned so endpoint coverage cannot retain deleted
        # agents indefinitely.
        existing_dlp = (
            await self.db.execute(
                select(SecurityAgent).where(SecurityAgent.product_name == "symantec")
            )
        ).scalars().all()
        pruned = 0
        pruned_endpoint_ids: set[_uuid.UUID] = set(reassigned_endpoint_ids)
        for agent in existing_dlp:
            if agent.id not in touched_agent_ids:
                pruned_endpoint_ids.add(agent.endpoint_id)
                await self.db.delete(agent)
                pruned += 1
        if pruned:
            logger.info("Symantec: removed %d stale DLP agent records", pruned)
            await self.db.flush()

        from app.services.endpoint_inventory import retire_orphaned_source_endpoints

        retired = await retire_orphaned_source_endpoints(
            self.db, "symantec", pruned_endpoint_ids,
        )
        if retired:
            logger.info("Symantec: retired %d orphaned source endpoints", retired)

        return count

    # Legacy support
    async def fetch_data(self) -> list[dict[str, Any]]:
        logger.warning("Symantec: Not configured for legacy fetch, skipping")
        return []

    async def normalize(self, raw_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return raw_items

    async def upsert_to_db(self, normalized: list[dict[str, Any]], db) -> None:
        pass
