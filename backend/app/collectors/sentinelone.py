import logging
from typing import Any
from datetime import datetime, timezone

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
                return {"success": True, "message": f"Connected successfully. {total} agents found."}
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
            return {"records_synced": count}
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

    # App-name patterns for the two products we track (lowercase match)
    _GP_KEYWORDS  = ("globalprotect",)
    _WSS_KEYWORDS = ("wss agent", "blue coat wss", "symantec web security service", "symantec wss")

    # S1 API returns apps per-agent with no agentId in the payload.
    # Must query one agent at a time; run up to CONCURRENCY requests in parallel.
    _APP_CONCURRENCY = 10

    async def _fetch_apps_for_agent(self, client: httpx.AsyncClient, s1_agent_id: str) -> list[dict]:
        """Return app records that match GP/WSS keywords for a single S1 agent."""
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
                if any(kw in name_lower for kw in self._GP_KEYWORDS):
                    matched.append({"product": "globalprotect", "version": app.get("version")})
                elif any(kw in name_lower for kw in self._WSS_KEYWORDS):
                    matched.append({"product": "symantec_wss", "version": app.get("version")})
            return matched
        except Exception as e:
            logger.debug("S1: apps fetch failed for agent %s: %s", s1_agent_id, e)
            return []

    async def _collect_app_agents(self, id_to_endpoint: dict[str, str]) -> None:
        """Fetch GP/WSS apps for all S1 agents concurrently and upsert SecurityAgent rows."""
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
        logger.info("S1: upserted %d GP/WSS app agent records", len(found))

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
