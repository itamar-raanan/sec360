import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


class PuppetCollector:
    name = "puppet"
    _FACT_PAGE_SIZE = 5_000

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
                nodes = await client.get(
                    f"{self.base_url}/pdb/query/v4/nodes",
                    headers=self._headers(),
                    params={"limit": 1},
                )
                if nodes.status_code == 401:
                    return {"success": False, "message": "Unauthorized (401) — check your API token"}
                if nodes.status_code == 403:
                    return {"success": False, "message": "Forbidden (403) — token lacks node read access"}
                nodes.raise_for_status()

                facts = await client.get(
                    f"{self.base_url}/pdb/query/v4/facts",
                    headers=self._headers(),
                    params={"limit": 1},
                )
                if facts.status_code == 403:
                    return {"success": False, "message": "Connected to PuppetDB, but facts read access is forbidden (403)"}
                facts.raise_for_status()
                node_count = len(nodes.json()) if isinstance(nodes.json(), list) else 0
                return {
                    "success": True,
                    "message": f"Connected to PuppetDB. {node_count} node(s) sampled; facts are accessible.",
                }
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
            facts = await self._fetch_facts()
            now = datetime.now(timezone.utc)
            node_count, endpoint_map = await self._upsert_nodes(nodes, facts, now)
            fact_count = await self._upsert_facts(facts, endpoint_map.keys(), now)
            await self.db.execute(delete(self._node_model()).where(self._node_model().synced_at != now))
            await self.db.flush()
            logger.info("PuppetDB: synced %d nodes and %d facts", node_count, fact_count)
            return {
                "records_synced": node_count + fact_count,
                "nodes_synced": node_count,
                "facts_synced": fact_count,
            }
        except Exception as e:
            logger.error(f"PuppetDB collect error: {e}", exc_info=True)
            return {"records_synced": 0, "error": str(e)}

    @staticmethod
    def _node_model():
        from app.models.puppet import PuppetNode
        return PuppetNode

    async def _fetch_nodes(self) -> list[dict[str, Any]]:
        async with httpx.AsyncClient(timeout=60.0, verify=self.verify_ssl) as client:
            resp = await client.get(
                f"{self.base_url}/pdb/query/v4/nodes",
                headers=self._headers(),
            )
            resp.raise_for_status()
            payload = resp.json()
            if not isinstance(payload, list):
                raise ValueError("Unexpected PuppetDB nodes response format")
            return payload

    async def _fetch_facts(self) -> list[dict[str, Any]]:
        facts: list[dict[str, Any]] = []
        offset = 0
        order_by = json.dumps([
            {"field": "certname", "order": "asc"},
            {"field": "name", "order": "asc"},
        ])
        async with httpx.AsyncClient(timeout=120.0, verify=self.verify_ssl) as client:
            while True:
                response = await client.get(
                    f"{self.base_url}/pdb/query/v4/facts",
                    headers=self._headers(),
                    params={
                        "limit": self._FACT_PAGE_SIZE,
                        "offset": offset,
                        "order_by": order_by,
                    },
                )
                response.raise_for_status()
                batch = response.json()
                if not isinstance(batch, list):
                    raise ValueError("Unexpected PuppetDB facts response format")
                facts.extend(item for item in batch if isinstance(item, dict))
                if len(batch) < self._FACT_PAGE_SIZE:
                    break
                offset += len(batch)
        return facts

    @staticmethod
    def _parse_datetime(value: Any) -> datetime | None:
        if not isinstance(value, str) or not value:
            return None
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None

    @staticmethod
    def _os_map(facts: list[dict[str, Any]]) -> dict[str, str]:
        result: dict[str, str] = {}
        for fact in facts:
            certname = str(fact.get("certname") or "").strip()
            name = str(fact.get("name") or "")
            value = fact.get("value")
            if not certname:
                continue
            if name == "operatingsystem" and value:
                result[certname] = str(value)
            elif name == "os" and isinstance(value, dict):
                os_name = value.get("name")
                release = value.get("release")
                full_release = release.get("full") if isinstance(release, dict) else None
                if os_name:
                    result[certname] = " ".join(
                        part for part in (str(os_name), str(full_release) if full_release else "") if part
                    )
        return result

    async def _upsert_nodes(
        self,
        nodes: list[dict[str, Any]],
        facts: list[dict[str, Any]],
        synced_at: datetime,
    ) -> tuple[int, dict[str, uuid.UUID]]:
        from app.engines.correlation import normalize_hostname
        from app.models.endpoint import Endpoint
        from app.models.puppet import PuppetNode

        os_map = self._os_map(facts)
        endpoint_map: dict[str, uuid.UUID] = {}
        endpoints = (await self.db.execute(select(Endpoint))).scalars().all()
        endpoints.sort(key=lambda item: item.source != "jumpcloud")
        exact_endpoint_map: dict[str, Endpoint] = {}
        normalized_endpoint_map: dict[str, Endpoint] = {}
        for endpoint in endpoints:
            exact_endpoint_map.setdefault(endpoint.hostname.lower(), endpoint)
            normalized = normalize_hostname(endpoint.hostname)
            if normalized:
                normalized_endpoint_map.setdefault(normalized, endpoint)
        existing_nodes = {
            node.certname: node
            for node in (await self.db.execute(select(PuppetNode))).scalars().all()
        }
        count = 0
        for raw in nodes:
            certname = str(raw.get("certname") or "").strip()
            if not certname:
                continue
            report_timestamp = self._parse_datetime(raw.get("report_timestamp"))
            catalog_timestamp = self._parse_datetime(raw.get("catalog_timestamp"))
            facts_timestamp = self._parse_datetime(raw.get("facts_timestamp"))
            last_seen = report_timestamp or catalog_timestamp or facts_timestamp
            environment = (
                raw.get("report_environment")
                or raw.get("catalog_environment")
                or raw.get("facts_environment")
            )

            endpoint = (
                exact_endpoint_map.get(certname.lower())
                or normalized_endpoint_map.get(normalize_hostname(certname))
            )
            if endpoint is None:
                endpoint = Endpoint(
                    hostname=certname,
                    os_version=os_map.get(certname),
                    last_seen=last_seen or synced_at,
                    source="puppet",
                )
                self.db.add(endpoint)
                await self.db.flush()
                exact_endpoint_map[certname.lower()] = endpoint
                normalized = normalize_hostname(certname)
                if normalized:
                    normalized_endpoint_map.setdefault(normalized, endpoint)
            else:
                # Puppet enriches an existing canonical endpoint without taking
                # ownership away from JumpCloud, AD, or another inventory source.
                if not endpoint.os_version and os_map.get(certname):
                    endpoint.os_version = os_map[certname]
                if endpoint.source == "puppet" and last_seen:
                    endpoint.last_seen = last_seen

            puppet_node = existing_nodes.get(certname)
            values = {
                "endpoint_id": endpoint.id,
                "environment": str(environment) if environment else None,
                "latest_report_status": raw.get("latest_report_status"),
                "report_timestamp": report_timestamp,
                "catalog_timestamp": catalog_timestamp,
                "facts_timestamp": facts_timestamp,
                "synced_at": synced_at,
            }
            if puppet_node is None:
                puppet_node = PuppetNode(certname=certname, **values)
                self.db.add(puppet_node)
                existing_nodes[certname] = puppet_node
            else:
                for key, value in values.items():
                    setattr(puppet_node, key, value)
            endpoint_map[certname] = endpoint.id
            count += 1

        await self.db.flush()
        return count, endpoint_map

    async def _upsert_facts(
        self,
        facts: list[dict[str, Any]],
        current_certnames,
        synced_at: datetime,
    ) -> int:
        from app.models.puppet import PuppetFact

        dialect_name = self.db.get_bind().dialect.name
        if dialect_name == "postgresql":
            from sqlalchemy.dialects.postgresql import insert as dialect_insert
        elif dialect_name == "sqlite":
            from sqlalchemy.dialects.sqlite import insert as dialect_insert
        else:
            raise RuntimeError(f"Puppet fact bulk sync does not support {dialect_name}")

        valid_certnames = set(current_certnames)
        table = PuppetFact.__table__
        batch: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()

        async def flush_batch() -> None:
            if not batch:
                return
            statement = dialect_insert(table).values(batch)
            statement = statement.on_conflict_do_update(
                index_elements=[table.c.certname, table.c.name],
                set_={
                    "value": statement.excluded.value,
                    "environment": statement.excluded.environment,
                    "synced_at": statement.excluded.synced_at,
                },
            )
            await self.db.execute(statement)
            batch.clear()

        for raw in facts:
            certname = str(raw.get("certname") or "").strip()
            name = str(raw.get("name") or "").strip()
            key = (certname, name)
            if not certname or not name or certname not in valid_certnames or key in seen:
                continue
            seen.add(key)
            batch.append({
                "id": uuid.uuid4(),
                "certname": certname,
                "name": name,
                "value": raw.get("value"),
                "environment": raw.get("environment"),
                "synced_at": synced_at,
            })
            if len(batch) >= 500:
                await flush_batch()

        await flush_batch()
        await self.db.execute(delete(PuppetFact).where(PuppetFact.synced_at != synced_at))
        await self.db.flush()
        return len(seen)
