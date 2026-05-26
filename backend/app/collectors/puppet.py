import logging
from datetime import datetime, timezone
from typing import Any

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


class PuppetCollector:
    name = "puppet"

    def __init__(self, credentials: dict, db: AsyncSession):
        self.base_url = credentials.get("base_url", "").rstrip("/")
        self.api_token = credentials.get("api_token", "")
        self.verify_ssl = str(credentials.get("verify_ssl", "true")).lower() != "false"
        self.db = db

    def _headers(self) -> dict:
        headers: dict[str, str] = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if self.api_token:
            headers["X-Authentication"] = self.api_token
        return headers

    async def test_connection(self) -> dict:
        if not self.base_url:
            return {"success": False, "message": "No base URL configured"}
        try:
            async with httpx.AsyncClient(timeout=15.0, verify=self.verify_ssl) as client:
                resp = await client.get(
                    f"{self.base_url}/pdb/query/v4/nodes",
                    headers=self._headers(),
                    params={"limit": 1},
                )
                if resp.status_code == 401:
                    return {"success": False, "message": "Unauthorized (401) — check your API token"}
                if resp.status_code == 403:
                    return {"success": False, "message": "Forbidden (403) — token lacks read access"}
                resp.raise_for_status()
                data = resp.json()
                node_count = len(data) if isinstance(data, list) else 0
                return {"success": True, "message": f"Connected to PuppetDB. {node_count} node(s) sampled."}
        except httpx.ConnectError as e:
            return {"success": False, "message": f"Connection error: {str(e)}"}
        except httpx.TimeoutException:
            return {"success": False, "message": "Connection timed out"}
        except Exception as e:
            return {"success": False, "message": f"Error: {str(e)}"}

    async def collect(self) -> dict:
        if not self.base_url:
            return {"records_synced": 0, "error": "No base URL configured"}

        try:
            nodes = await self._fetch_nodes()
            os_map = await self._fetch_os_facts()
            count = await self._upsert_nodes(nodes, os_map)
            return {"records_synced": count}
        except Exception as e:
            logger.error(f"PuppetDB collect error: {e}", exc_info=True)
            return {"records_synced": 0, "error": str(e)}

    async def _fetch_nodes(self) -> list[dict[str, Any]]:
        async with httpx.AsyncClient(timeout=60.0, verify=self.verify_ssl) as client:
            resp = await client.get(
                f"{self.base_url}/pdb/query/v4/nodes",
                headers=self._headers(),
            )
            resp.raise_for_status()
            return resp.json()

    async def _fetch_os_facts(self) -> dict[str, str]:
        """Returns certname -> operatingsystem mapping."""
        async with httpx.AsyncClient(timeout=60.0, verify=self.verify_ssl) as client:
            resp = await client.get(
                f"{self.base_url}/pdb/query/v4/facts",
                headers=self._headers(),
                params={"query": '["=","name","operatingsystem"]'},
            )
            resp.raise_for_status()
            facts = resp.json()
        os_map: dict[str, str] = {}
        for fact in facts:
            certname = fact.get("certname", "")
            value = fact.get("value", "")
            if certname and value:
                os_map[certname] = str(value)
        return os_map

    async def _upsert_nodes(self, nodes: list[dict[str, Any]], os_map: dict[str, str]) -> int:
        from sqlalchemy import select
        from app.models.endpoint import Endpoint

        count = 0
        for node in nodes:
            certname = node.get("certname", "").strip()
            if not certname:
                continue

            last_seen: datetime | None = None
            report_ts = node.get("report_timestamp") or node.get("catalog_timestamp") or node.get("facts_timestamp")
            if report_ts:
                try:
                    last_seen = datetime.fromisoformat(report_ts.replace("Z", "+00:00"))
                except Exception:
                    pass

            os_version = os_map.get(certname)

            result = await self.db.execute(
                select(Endpoint).where(Endpoint.hostname == certname)
            )
            endpoint = result.scalars().first()

            if not endpoint:
                endpoint = Endpoint(
                    hostname=certname,
                    os_version=os_version,
                    last_seen=last_seen or datetime.now(timezone.utc),
                    source="puppet",
                )
                self.db.add(endpoint)
            else:
                endpoint.source = "puppet"
                if os_version:
                    endpoint.os_version = os_version
                if last_seen:
                    endpoint.last_seen = last_seen

            count += 1

        await self.db.flush()
        return count
