import logging
from typing import Any
from datetime import datetime, timezone
import uuid

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.collectors.base import BaseCollector
from app.core.config import settings

logger = logging.getLogger(__name__)


class SentinelOneCollector(BaseCollector):
    name = "sentinelone"

    def __init__(self, credentials: dict = None, db: AsyncSession = None):
        super().__init__()
        if credentials:
            self.api_token = credentials.get("api_key", "")
            console_url = credentials.get("console_url", "")
            # Normalize: strip trailing slash and /web/api/... if present
            if console_url:
                console_url = console_url.rstrip("/")
                if "/web/api" in console_url:
                    console_url = console_url.split("/web/api")[0]
            self.base_url = console_url or "https://usea1.sentinelone.net"
        else:
            self.base_url = settings.SENTINELONE_URL or "https://usea1.sentinelone.net"
            self.api_token = settings.SENTINELONE_API_TOKEN or ""
        self.db = db

    def _headers(self) -> dict:
        return {"Authorization": f"ApiToken {self.api_token}"}

    async def test_connection(self) -> dict:
        if not self.api_token:
            return {"success": False, "message": "No API token configured"}
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"{self.base_url}/web/api/v2.1/agents",
                    headers=self._headers(),
                    params={"limit": 1},
                )
                if resp.status_code == 401:
                    return {"success": False, "message": "Invalid API token (401 Unauthorized)"}
                if resp.status_code == 403:
                    return {"success": False, "message": "Token lacks permissions (403 Forbidden)"}
                resp.raise_for_status()
                data = resp.json()
                total = data.get("pagination", {}).get("totalItems", 0)
                risks = await client.get(
                    f"{self.base_url}/web/api/v2.1/application-management/risks",
                    headers=self._headers(),
                    params={"limit": 1, "skipCount": "true"},
                )
                if risks.status_code == 403:
                    return {
                        "success": False,
                        "message": "Connected to endpoints, but the token lacks Applications: View and View Risks permissions",
                    }
                if risks.status_code == 404:
                    return {
                        "success": False,
                        "message": "Application Vulnerability Management is not available for this SentinelOne tenant",
                    }
                risks.raise_for_status()
                return {
                    "success": True,
                    "message": f"Connected successfully. {total} agents found; application vulnerabilities are accessible.",
                }
        except httpx.ConnectError as e:
            return {"success": False, "message": f"Connection error: {str(e)}"}
        except httpx.TimeoutException:
            return {"success": False, "message": "Connection timed out"}
        except Exception as e:
            return {"success": False, "message": f"Error: {str(e)}"}

    async def collect(self) -> dict:
        if not self.api_token:
            return {"records_synced": 0, "error": "No API token configured"}
        try:
            agents = await self._fetch_agents()
            count, agent_id_map = await self._upsert_agents(agents)
            if agent_id_map:
                await self._collect_app_agents(agent_id_map)
            risks = await self._fetch_application_vulnerabilities()
            vulnerability_count = await self._upsert_application_vulnerabilities(risks, agent_id_map)
            return {
                "records_synced": count + vulnerability_count,
                "agents_synced": count,
                "vulnerabilities_synced": vulnerability_count,
            }
        except Exception as e:
            logger.error(f"SentinelOne: collect failed: {e}", exc_info=True)
            return {"records_synced": 0, "error": str(e)}

    async def _fetch_agents(self) -> list:
        agents = []
        cursor = None
        async with httpx.AsyncClient(timeout=30.0) as client:
            while True:
                params: dict[str, Any] = {"limit": 100}
                if cursor:
                    params["cursor"] = cursor
                resp = await client.get(
                    f"{self.base_url}/web/api/v2.1/agents",
                    headers=self._headers(),
                    params=params,
                )
                resp.raise_for_status()
                data = resp.json()
                batch = data.get("data", [])
                agents.extend(batch)
                cursor = data.get("pagination", {}).get("nextCursor")
                if not cursor or len(batch) == 0:
                    break
        return agents

    async def _fetch_application_vulnerabilities(self) -> list[dict[str, Any]]:
        """Fetch the complete SentinelOne Applications > Vulnerabilities dataset."""
        findings: list[dict[str, Any]] = []
        cursor: str | None = None
        while True:
            params: dict[str, Any] = {
                "limit": 1000,
                "skipCount": "true",
                "sortBy": "application",
                "sortOrder": "asc",
            }
            if cursor:
                params["cursor"] = cursor
            try:
                response = await self.fetch_with_retry(
                    f"{self.base_url}/web/api/v2.1/application-management/risks",
                    headers=self._headers(),
                    params=params,
                )
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code == 403:
                    raise PermissionError(
                        "SentinelOne token requires Applications: View and View Risks permissions"
                    ) from exc
                raise
            payload = response.json()
            batch = payload.get("data") or []
            if not isinstance(batch, list):
                raise ValueError("Unexpected SentinelOne vulnerability response format")
            findings.extend(item for item in batch if isinstance(item, dict))
            next_cursor = payload.get("pagination", {}).get("nextCursor")
            if not next_cursor or not batch or next_cursor == cursor:
                break
            cursor = next_cursor
        logger.info("SentinelOne: fetched %d application vulnerability findings", len(findings))
        return findings

    @staticmethod
    def _parse_datetime(value: Any) -> datetime | None:
        if not value or not isinstance(value, str):
            return None
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None

    @staticmethod
    def _parse_float(value: Any) -> float | None:
        try:
            return float(value) if value not in (None, "") else None
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _parse_int(value: Any) -> int | None:
        try:
            return int(value) if value not in (None, "") else None
        except (TypeError, ValueError):
            return None

    async def _upsert_application_vulnerabilities(
        self,
        findings: list[dict[str, Any]],
        agent_id_map: dict[str, str],
    ) -> int:
        """Bulk-upsert a full snapshot and remove findings no longer returned.

        Application Management tenants can return hundreds of thousands of rows.
        Loading every existing ORM object and flushing one object at a time makes
        that volume effectively unbounded and prevents the surrounding sync from
        committing.  Build plain mappings and let the database perform batched
        ``ON CONFLICT`` upserts instead.
        """
        from sqlalchemy import delete, select
        from app.engines.correlation import normalize_hostname
        from app.models.application import ApplicationVulnerability
        from app.models.endpoint import Endpoint

        dialect_name = self.db.get_bind().dialect.name
        if dialect_name == "postgresql":
            from sqlalchemy.dialects.postgresql import insert as dialect_insert
        elif dialect_name == "sqlite":
            from sqlalchemy.dialects.sqlite import insert as dialect_insert
        else:
            raise RuntimeError(
                f"Application vulnerability bulk sync does not support {dialect_name}"
            )

        now = datetime.now(timezone.utc)

        # Resolve the uncommon hostname fallback once, rather than issuing a
        # database query for every finding that lacks a usable SentinelOne ID.
        endpoint_name_map: dict[str, uuid.UUID] = {}
        endpoints = (await self.db.execute(select(Endpoint))).scalars().all()
        for endpoint in sorted(endpoints, key=lambda item: item.source != "jumpcloud"):
            normalized = normalize_hostname(endpoint.hostname)
            if normalized and normalized not in endpoint_name_map:
                endpoint_name_map[normalized] = endpoint.id

        table = ApplicationVulnerability.__table__
        update_column_names = [
            column.name
            for column in table.columns
            if column.name not in {"id", "sentinelone_id"}
        ]
        # Keep each statement comfortably below asyncpg/PostgreSQL's bind
        # parameter limit. Only the current batch is materialized, which avoids
        # duplicating the already-large SentinelOne response in memory.
        batch_size = 500
        batch: list[dict[str, Any]] = []
        seen_ids: set[str] = set()

        async def flush_batch() -> None:
            if not batch:
                return
            statement = dialect_insert(table).values(batch)
            statement = statement.on_conflict_do_update(
                index_elements=[table.c.sentinelone_id],
                set_={
                    name: getattr(statement.excluded, name)
                    for name in update_column_names
                },
            )
            await self.db.execute(statement)
            batch.clear()

        for raw in findings:
            sentinelone_id = str(raw.get("id") or "").strip()
            if not sentinelone_id:
                logger.warning("SentinelOne: skipping vulnerability finding without id")
                continue
            if sentinelone_id in seen_ids:
                continue
            seen_ids.add(sentinelone_id)

            s1_endpoint_id = str(raw.get("endpointId") or "").strip() or None
            correlated_id = agent_id_map.get(s1_endpoint_id or "")
            endpoint_name = str(raw.get("endpointName") or "Unknown endpoint")
            endpoint_id = (
                uuid.UUID(correlated_id)
                if correlated_id
                else endpoint_name_map.get(normalize_hostname(endpoint_name))
            )
            batch.append({
                "id": uuid.uuid4(),
                "sentinelone_id": sentinelone_id,
                "endpoint_id": endpoint_id,
                "sentinelone_endpoint_id": s1_endpoint_id,
                "application": str(raw.get("application") or raw.get("applicationName") or "Unknown application"),
                "application_name": str(raw.get("applicationName") or raw.get("application") or "Unknown application"),
                "application_vendor": raw.get("applicationVendor"),
                "application_version": raw.get("applicationVersion"),
                "cve_id": str(raw.get("cveId") or "Unknown CVE"),
                "cvss_version": raw.get("cvssVersion"),
                "nvd_cvss_version": raw.get("nvdCvssVersion"),
                "nvd_base_score": self._parse_float(raw.get("nvdBaseScore")),
                "risk_score": self._parse_float(raw.get("riskScore")),
                "severity": str(raw.get("severity") or "UNKNOWN").upper(),
                "endpoint_name": endpoint_name,
                "endpoint_type": raw.get("endpointType"),
                "os_type": raw.get("osType"),
                "days_detected": self._parse_int(raw.get("daysDetected")),
                "detection_date": self._parse_datetime(raw.get("detectionDate")),
                "published_date": self._parse_datetime(raw.get("publishedDate")),
                "last_scan_date": self._parse_datetime(raw.get("lastScanDate")),
                "last_scan_result": raw.get("lastScanResult"),
                "exploit_code_maturity": raw.get("exploitCodeMaturity"),
                "remediation_level": raw.get("remediationLevel"),
                "report_confidence": raw.get("reportConfidence"),
                "mitigation_status": raw.get("mitigationStatus"),
                "mitigation_status_change_time": self._parse_datetime(raw.get("mitigationStatusChangeTime")),
                "mitigation_status_changed_by": raw.get("mitigationStatusChangedBy"),
                "mitigation_status_reason": raw.get("mitigationStatusReason"),
                "status": raw.get("status"),
                "mark_type": raw.get("markType"),
                "marked_by": raw.get("markedBy"),
                "marked_date": self._parse_datetime(raw.get("markedDate")),
                "reason": raw.get("reason"),
                "raw_json": raw,
                "synced_at": now,
            })
            if len(batch) >= batch_size:
                await flush_batch()
                if len(seen_ids) % 25_000 == 0:
                    logger.info(
                        "SentinelOne: imported %d application vulnerability findings",
                        len(seen_ids),
                    )

        await flush_batch()

        stale_result = await self.db.execute(
            delete(ApplicationVulnerability).where(ApplicationVulnerability.synced_at != now)
        )
        removed = stale_result.rowcount or 0

        await self.db.flush()
        logger.info(
            "SentinelOne: synced %d application vulnerabilities; removed %d stale findings",
            len(seen_ids), removed,
        )
        return len(seen_ids)

    async def _upsert_agents(self, agents: list) -> tuple[int, dict]:
        import uuid as _uuid
        from sqlalchemy import select
        from app.models.endpoint import Endpoint
        from app.models.agent import SecurityAgent
        from app.engines.correlation import find_endpoint, normalize_serial

        count = 0
        agent_id_map: dict[str, str] = {}  # s1_agent_id → endpoint_id (str)
        touched_endpoint_ids: set[_uuid.UUID] = set()
        for item in agents:
            s1_agent_id: str | None = item.get("id")
            hostname_raw = item.get("computerName", "")
            # Strip apostrophes and placeholder values at storage time
            hostname = hostname_raw.replace("'", "").replace("\u2019", "").strip()
            if hostname.lower() in ("(string)", "string", "localhost"):
                hostname = ""
            serial_raw = item.get("serialNumber")
            serial = normalize_serial(serial_raw)

            if not hostname and not serial:
                continue

            last_seen = None
            if item.get("lastActiveDate"):
                try:
                    last_seen = datetime.fromisoformat(item["lastActiveDate"].replace("Z", "+00:00"))
                except Exception:
                    pass

            # Serial-first lookup: finds the JumpCloud endpoint even when the
            # hostname reported by S1 differs (renamed machine, encoding differences, etc.)
            endpoint, match_method = await find_endpoint(self.db, serial, hostname)

            if match_method == "serial":
                logger.debug("S1: matched %r to endpoint %r via serial %s",
                             hostname, endpoint.hostname, serial)

            # Collect all IPv4 addresses from every network interface
            ifaces = item.get("networkInterfaces", [])
            all_ipv4: list[str] = []
            for iface in ifaces:
                for addr in (iface.get("inet") or []):
                    if addr and addr not in all_ipv4:
                        all_ipv4.append(addr)
            if not all_ipv4 and item.get("lastIpToMgmt"):
                all_ipv4.append(item["lastIpToMgmt"])
            ip = all_ipv4[0] if all_ipv4 else None
            all_ips_str = ", ".join(all_ipv4) if all_ipv4 else None

            # External (public) IP reported by S1
            external_ip: str | None = item.get("externalIp") or None
            # Console-visible IP (lastIpToMgmt — IP as seen by the S1 management server)

            os_version = f"{item.get('osName', '')} {item.get('osRevision', '')}".strip()

            # Last reboot from S1
            last_reboot: datetime | None = None
            if item.get("lastBoot"):
                try:
                    last_reboot = datetime.fromisoformat(item["lastBoot"].replace("Z", "+00:00"))
                except Exception:
                    pass

            # Agent group (policy group name in S1 console)
            agent_group = item.get("groupName") or None

            # Tags
            tags_raw = item.get("tags") or []
            tags_str = ", ".join(
                t.get("value") or t.get("key") or ""
                for t in tags_raw if isinstance(t, dict)
            ).strip(", ") or None

            # Encryption status
            enc_status = item.get("diskEncryptedStatus") or None
            disk_enc: bool | None = None
            if enc_status == "encrypted":
                disk_enc = True
            elif enc_status == "not_encrypted":
                disk_enc = False
            elif enc_status in (None, "unknown", "not_applicable"):
                ea = item.get("encryptedApplications")
                if ea is not None:
                    disk_enc = bool(ea)

            device_ctrl = item.get("deviceControlEnabled")
            device_ctrl_bool: bool | None = bool(device_ctrl) if device_ctrl is not None else None

            if not endpoint:
                endpoint = Endpoint(
                    hostname=hostname or f"s1-{serial}",
                    serial_number=serial,
                    os_version=os_version or None,
                    username=item.get("lastLoggedInUserName"),
                    ip_address=ip,
                    all_ips=all_ips_str,
                    external_ip=external_ip,
                    last_seen=last_seen or datetime.now(timezone.utc),
                    last_reboot=last_reboot,
                    source="sentinelone",
                    tags=tags_str,
                )
                self.db.add(endpoint)
                await self.db.flush()
            else:
                # Always update S1-authoritative fields (every sync)
                if all_ips_str:
                    endpoint.all_ips = all_ips_str
                if last_reboot:
                    endpoint.last_reboot = last_reboot
                if tags_str is not None:
                    endpoint.tags = tags_str
                # Always refresh external/console IPs — they can change (VPN, roaming)
                endpoint.external_ip = external_ip

                # For JumpCloud-owned endpoints: enrich only missing fields
                # (JC is authoritative for last_seen, ip_address, source)
                if endpoint.source == "jumpcloud":
                    if serial and not endpoint.serial_number:
                        endpoint.serial_number = serial
                    if os_version and not endpoint.os_version:
                        endpoint.os_version = os_version
                    if item.get("lastLoggedInUserName") and not endpoint.username:
                        endpoint.username = item["lastLoggedInUserName"]
                    if ip and not endpoint.ip_address:
                        endpoint.ip_address = ip
                else:
                    # S1-owned endpoints: S1 is the live source — always refresh
                    if serial and not endpoint.serial_number:
                        endpoint.serial_number = serial
                    if os_version:
                        endpoint.os_version = os_version
                    if item.get("lastLoggedInUserName"):
                        endpoint.username = item["lastLoggedInUserName"]
                    if ip:
                        endpoint.ip_address = ip
                    if last_seen:
                        endpoint.last_seen = last_seen   # keep alive

            # Upsert agent
            agent_result = await self.db.execute(
                select(SecurityAgent).where(
                    SecurityAgent.endpoint_id == endpoint.id,
                    SecurityAgent.product_name == "sentinelone",
                )
            )
            agent = agent_result.scalars().first()

            agent_status = "active" if item.get("isActive") else "inactive"
            agent_version = item.get("agentVersion")

            if not agent:
                agent = SecurityAgent(
                    endpoint_id=endpoint.id,
                    product_name="sentinelone",
                    status=agent_status,
                    version=agent_version,
                    last_seen=last_seen,
                    disk_encrypted=disk_enc,
                    encryption_status=enc_status,
                    device_control_enabled=device_ctrl_bool,
                    agent_group=agent_group,
                )
                self.db.add(agent)
            else:
                agent.status = agent_status
                if agent_version:
                    agent.version = agent_version
                if last_seen:
                    agent.last_seen = last_seen
                agent.disk_encrypted = disk_enc
                if enc_status is not None:
                    agent.encryption_status = enc_status
                agent.device_control_enabled = device_ctrl_bool
                if agent_group is not None:
                    agent.agent_group = agent_group

            if s1_agent_id and endpoint and endpoint.id:
                agent_id_map[s1_agent_id] = str(endpoint.id)
            if endpoint and endpoint.id:
                touched_endpoint_ids.add(endpoint.id)

            count += 1

        await self.db.flush()

        # Prune: mark SentinelOne agent rows on endpoints not seen in this sync
        # as inactive — those devices were removed from the S1 console.
        all_s1_agents = (
            await self.db.execute(
                select(SecurityAgent).where(
                    SecurityAgent.product_name == "sentinelone",
                    SecurityAgent.status == "active",
                )
            )
        ).scalars().all()
        pruned = 0
        for agent in all_s1_agents:
            if agent.endpoint_id not in touched_endpoint_ids:
                agent.status = "inactive"
                pruned += 1
        if pruned:
            logger.info("SentinelOne: marked %d removed agents as inactive", pruned)
            await self.db.flush()

        return count, agent_id_map

    # App-name patterns for Symantec WSS (lowercase match)
    _WSS_KEYWORDS = ("wss agent", "blue coat wss", "symantec web security service", "symantec wss")

    # S1 API returns apps per-agent with no agentId in the payload.
    # Must query one agent at a time; run up to CONCURRENCY requests in parallel.
    _APP_CONCURRENCY = 10

    async def _fetch_apps_for_agent(self, client: httpx.AsyncClient, s1_agent_id: str) -> list[dict]:
        """Return Symantec WSS app records for a single S1 agent."""
        try:
            resp = await client.get(
                f"{self.base_url}/web/api/v2.1/agents/applications",
                headers=self._headers(),
                params={"ids": s1_agent_id},
            )
            resp.raise_for_status()
            apps = resp.json().get("data", [])
            matched = []
            for app in apps:
                name_lower = (app.get("name") or "").lower()
                if any(kw in name_lower for kw in self._WSS_KEYWORDS):
                    matched.append({"product": "symantec_wss", "version": app.get("version")})
            return matched
        except Exception as e:
            logger.debug("S1: apps fetch failed for agent %s: %s", s1_agent_id, e)
            return []

    async def _collect_app_agents(self, id_to_endpoint: dict[str, str]) -> None:
        """Fetch WSS apps for all S1 agents concurrently and upsert SecurityAgent rows."""
        import asyncio
        from sqlalchemy import select
        from app.models.agent import SecurityAgent

        now = datetime.now(timezone.utc)
        sem = asyncio.Semaphore(self._APP_CONCURRENCY)

        async def fetch_one(client: httpx.AsyncClient, s1_id: str, ep_id: str):
            async with sem:
                return ep_id, await self._fetch_apps_for_agent(client, s1_id)

        async with httpx.AsyncClient(timeout=30.0) as client:
            tasks = [
                fetch_one(client, s1_id, ep_id)
                for s1_id, ep_id in id_to_endpoint.items()
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        # Build {(endpoint_id, product): version} — first version found wins
        found: dict[tuple[str, str], str | None] = {}
        for res in results:
            if isinstance(res, Exception):
                continue
            ep_id, matches = res
            for m in matches:
                key = (ep_id, m["product"])
                if key not in found:
                    found[key] = m["version"]

        for (endpoint_id, product_name), version in found.items():
            result = await self.db.execute(
                select(SecurityAgent).where(
                    SecurityAgent.endpoint_id == endpoint_id,
                    SecurityAgent.product_name == product_name,
                )
            )
            agent = result.scalars().first()
            if not agent:
                agent = SecurityAgent(
                    endpoint_id=endpoint_id,
                    product_name=product_name,
                    status="active",
                    version=version,
                    last_seen=now,
                )
                self.db.add(agent)
            else:
                if version:
                    agent.version = version
                agent.status = "active"
                agent.last_seen = now

        await self.db.flush()
        logger.info("S1: upserted %d WSS app agent records", len(found))

    # Legacy support for old scheduler pattern
    async def fetch_data(self) -> list[dict[str, Any]]:
        if not self.api_token:
            logger.warning("SentinelOne: No API token configured, skipping")
            return []
        return await self._fetch_agents()

    async def normalize(self, raw_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        normalized = []
        for item in raw_items:
            try:
                normalized.append({
                    "type": "endpoint_agent",
                    "hostname": item.get("computerName", ""),
                    "os_version": f"{item.get('osName', '')} {item.get('osRevision', '')}".strip(),
                    "username": item.get("lastLoggedInUserName"),
                    "ip_address": item.get("lastIpToMgmt"),
                    "location": item.get("siteId"),
                    "last_seen": item.get("lastActiveDate"),
                    "agent_product": "sentinelone",
                    "agent_status": "active" if item.get("isActive") else "inactive",
                    "agent_version": item.get("agentVersion"),
                    "external_id": item.get("id"),
                })
            except Exception as e:
                logger.warning(f"SentinelOne: Failed to normalize item: {e}")
        return normalized

    async def upsert_to_db(self, normalized: list[dict[str, Any]], db) -> None:
        """Legacy upsert used by old scheduler pattern."""
        from sqlalchemy import select
        from app.models.endpoint import Endpoint
        from app.models.agent import SecurityAgent

        for item in normalized:
            result = await db.execute(select(Endpoint).where(Endpoint.hostname == item["hostname"]))
            endpoint = result.scalars().first()

            last_seen = None
            if item.get("last_seen"):
                try:
                    last_seen = datetime.fromisoformat(item["last_seen"].replace("Z", "+00:00"))
                except Exception:
                    pass

            if not endpoint:
                endpoint = Endpoint(
                    hostname=item["hostname"],
                    os_version=item.get("os_version"),
                    username=item.get("username"),
                    ip_address=item.get("ip_address"),
                    last_seen=last_seen,
                )
                db.add(endpoint)
                await db.flush()
            else:
                endpoint.os_version = item.get("os_version") or endpoint.os_version
                endpoint.username = item.get("username") or endpoint.username
                endpoint.ip_address = item.get("ip_address") or endpoint.ip_address
                if last_seen:
                    endpoint.last_seen = last_seen

            agent_result = await db.execute(
                select(SecurityAgent).where(
                    SecurityAgent.endpoint_id == endpoint.id,
                    SecurityAgent.product_name == "sentinelone",
                )
            )
            agent = agent_result.scalars().first()

            if not agent:
                agent = SecurityAgent(
                    endpoint_id=endpoint.id,
                    product_name="sentinelone",
                    status=item["agent_status"],
                    version=item.get("agent_version"),
                    last_seen=last_seen,
                )
                db.add(agent)
            else:
                agent.status = item["agent_status"]
                agent.version = item.get("agent_version") or agent.version
                if last_seen:
                    agent.last_seen = last_seen
