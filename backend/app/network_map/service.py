import hashlib
import re
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agent import SecurityAgent
from app.models.endpoint import Endpoint
from app.models.network_map import (
    NetworkMapCollectionRun,
    NetworkMapConnection,
    NetworkMapEquipment,
    NetworkMapFloor,
    NetworkMapObservation,
)
from app.models.puppet import PuppetFact, PuppetNode
from app.models.user import User
from app.network_map.collectors import collect_for_type, normalize_mac


FLOOR_COUNT = 31
MAC_TEXT_RE = re.compile(
    r"(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f])|"
    r"(?<![0-9a-f])(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}(?![0-9a-f])",
    re.IGNORECASE,
)


async def ensure_floors(db: AsyncSession) -> list[NetworkMapFloor]:
    floors = list((await db.execute(select(NetworkMapFloor).order_by(NetworkMapFloor.ordinal))).scalars())
    existing = {floor.ordinal for floor in floors}
    for ordinal in range(1, FLOOR_COUNT + 1):
        if ordinal not in existing:
            db.add(NetworkMapFloor(ordinal=ordinal, label=f"Floor {ordinal}", managed=False))
    if len(existing) != FLOOR_COUNT:
        await db.flush()
        floors = list((await db.execute(select(NetworkMapFloor).order_by(NetworkMapFloor.ordinal))).scalars())
    return floors


def _stable_position(source_key: str) -> tuple[float, float]:
    digest = hashlib.sha256(source_key.encode()).digest()
    x = -8.5 + (int.from_bytes(digest[:2], "big") / 65535) * 17
    z = -4.8 + (int.from_bytes(digest[2:4], "big") / 65535) * 9.6
    return round(x, 2), round(z, 2)


async def _upsert_equipment(
    db: AsyncSession,
    connection: NetworkMapConnection,
    source_key: str,
    kind: str,
    display_name: str,
    metadata: dict[str, Any],
    observed_at: datetime,
) -> NetworkMapEquipment:
    equipment = (await db.execute(select(NetworkMapEquipment).where(
        NetworkMapEquipment.connection_id == connection.id,
        NetworkMapEquipment.source_key == source_key,
    ))).scalar_one_or_none()
    if equipment is None:
        x, z = _stable_position(f"{connection.id}:{source_key}")
        equipment = NetworkMapEquipment(
            connection_id=connection.id,
            source_key=source_key,
            kind=kind,
            display_name=display_name,
            position_x=x,
            position_z=z,
            metadata_json=metadata,
            last_seen=observed_at,
        )
        db.add(equipment)
        await db.flush()
    else:
        equipment.kind = kind
        equipment.display_name = display_name
        equipment.metadata_json = metadata
        equipment.last_seen = observed_at
    return equipment


async def collect_connection(db: AsyncSession, connection: NetworkMapConnection) -> NetworkMapCollectionRun:
    now = datetime.now(timezone.utc)
    run = NetworkMapCollectionRun(connection_id=connection.id, started_at=now)
    db.add(run)
    await db.flush()
    try:
        result = await collect_for_type(connection.connection_type, connection.config or {})
        observations: list[NetworkMapObservation] = []
        equipment_by_key: dict[str, NetworkMapEquipment] = {}

        if connection.connection_type == "cisco_wlc":
            for ap in result.get("aps", []):
                source_key = f"ap:{ap.get('mac') or ap.get('name')}"
                equipment = await _upsert_equipment(
                    db, connection, source_key, "ap", ap.get("name") or "Access point", ap, now
                )
                equipment_by_key[str(ap.get("name") or "").casefold()] = equipment
            wlans = result.get("wlans", {})
            for client in result.get("clients", []):
                mac = normalize_mac(client.get("mac"))
                if not mac:
                    continue
                equipment = equipment_by_key.get(str(client.get("ap") or "").casefold())
                observations.append(NetworkMapObservation(
                    run_id=run.id,
                    connection_id=connection.id,
                    equipment_id=equipment.id if equipment else None,
                    observation_type="wireless",
                    mac_address=mac,
                    ssid=wlans.get(str(client.get("wlan") or "")),
                    state=client.get("state"),
                    raw=client,
                    observed_at=now,
                ))

        elif connection.connection_type == "fortigate":
            for lease in result.get("leases", []):
                mac = normalize_mac(lease.get("mac"))
                if not mac:
                    continue
                observations.append(NetworkMapObservation(
                    run_id=run.id,
                    connection_id=connection.id,
                    observation_type="dhcp",
                    mac_address=mac,
                    hostname=lease.get("hostname"),
                    ip_address=lease.get("ip"),
                    interface=lease.get("interface"),
                    vdom=lease.get("vdom"),
                    state=lease.get("status"),
                    raw=lease,
                    observed_at=now,
                ))

        elif connection.connection_type == "mikrotik":
            equipment = await _upsert_equipment(
                db,
                connection,
                "switch",
                "switch",
                connection.display_name,
                {"base_url": (connection.config or {}).get("base_url", "")},
                now,
            )
            for host in result.get("hosts", []):
                mac = normalize_mac(host.get("mac"))
                if not mac:
                    continue
                observations.append(NetworkMapObservation(
                    run_id=run.id,
                    connection_id=connection.id,
                    equipment_id=equipment.id,
                    observation_type="wired",
                    mac_address=mac,
                    port=host.get("port"),
                    vlan=host.get("vlan"),
                    raw=host,
                    observed_at=now,
                ))

        # Only a successful, complete snapshot retires the previous current
        # view. Failed or partial runs never erase the last useful topology.
        await db.execute(update(NetworkMapObservation).where(
            NetworkMapObservation.connection_id == connection.id,
            NetworkMapObservation.is_current.is_(True),
        ).values(is_current=False))
        db.add_all(observations)
        run.status = "success"
        run.complete_snapshot = True
        run.record_count = len(observations)
        run.completed_at = datetime.now(timezone.utc)
        connection.status = "connected"
        connection.last_error = None
        connection.last_collected_at = run.completed_at
        connection.records_synced = len(observations)
    except Exception as exc:
        run.status = "error"
        run.error = str(exc)[:4000]
        run.completed_at = datetime.now(timezone.utc)
        connection.status = "error"
        connection.last_error = str(exc)[:4000]
    await db.flush()
    return run


def _extract_macs(value: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        for nested in value.values():
            found.update(_extract_macs(nested))
    elif isinstance(value, list):
        for nested in value:
            found.update(_extract_macs(nested))
    elif isinstance(value, str):
        for match in MAC_TEXT_RE.findall(value):
            normalized = normalize_mac(match)
            if normalized:
                found.add(normalized)
    return found


async def _endpoint_mac_index(db: AsyncSession) -> dict[str, list[uuid.UUID]]:
    rows = (await db.execute(
        select(PuppetFact.value, PuppetNode.endpoint_id)
        .join(PuppetNode, PuppetNode.certname == PuppetFact.certname)
        .where(PuppetNode.endpoint_id.is_not(None))
    )).all()
    index: dict[str, set[uuid.UUID]] = defaultdict(set)
    for value, endpoint_id in rows:
        for mac in _extract_macs(value):
            index[mac].add(endpoint_id)
    return {mac: sorted(ids, key=str) for mac, ids in index.items()}


def _dt(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


async def build_map_payload(db: AsyncSession) -> dict[str, Any]:
    floors = await ensure_floors(db)
    connections = list((await db.execute(
        select(NetworkMapConnection).order_by(NetworkMapConnection.connection_type, NetworkMapConnection.display_name)
    )).scalars())
    equipment = list((await db.execute(select(NetworkMapEquipment))).scalars())
    observations = list((await db.execute(select(NetworkMapObservation).where(
        NetworkMapObservation.is_current.is_(True)
    ))).scalars())

    dhcp_by_mac: dict[str, NetworkMapObservation] = {}
    wireless_macs = {row.mac_address for row in observations if row.observation_type == "wireless"}
    for row in observations:
        if row.observation_type == "dhcp":
            current = dhcp_by_mac.get(row.mac_address)
            if current is None or row.observed_at > current.observed_at:
                dhcp_by_mac[row.mac_address] = row

    mac_index = await _endpoint_mac_index(db)
    endpoint_ids = {endpoint_id for ids in mac_index.values() for endpoint_id in ids}
    endpoints = list((await db.execute(select(Endpoint).where(Endpoint.id.in_(endpoint_ids)))).scalars()) if endpoint_ids else []
    endpoint_by_id = {endpoint.id: endpoint for endpoint in endpoints}
    owners = list((await db.execute(select(User).where(User.id.in_({e.owner_user_id for e in endpoints if e.owner_user_id})))).scalars()) if endpoints else []
    owner_by_id = {owner.id: owner for owner in owners}
    agents = list((await db.execute(select(SecurityAgent).where(SecurityAgent.endpoint_id.in_(endpoint_ids)))).scalars()) if endpoint_ids else []
    agents_by_endpoint: dict[uuid.UUID, list[SecurityAgent]] = defaultdict(list)
    for agent in agents:
        agents_by_endpoint[agent.endpoint_id].append(agent)

    equipment_by_id = {item.id: item for item in equipment}
    floor_by_id = {floor.id: floor for floor in floors}
    attachment_rows = []
    for row in observations:
        if row.observation_type == "dhcp":
            continue
        equipment_item = equipment_by_id.get(row.equipment_id)
        if not equipment_item:
            continue
        port_role = (equipment_item.port_overrides or {}).get(str(row.port or ""), {}).get("role")
        if row.observation_type == "wired" and row.mac_address in wireless_macs and port_role != "endpoint":
            continue
        candidates = mac_index.get(row.mac_address, [])
        match_state = "matched" if len(candidates) == 1 else "ambiguous" if len(candidates) > 1 else "no_current_match"
        endpoint = endpoint_by_id.get(candidates[0]) if len(candidates) == 1 else None
        lease = dhcp_by_mac.get(row.mac_address)
        floor_id = equipment_item.floor_id
        override = (equipment_item.port_overrides or {}).get(str(row.port or ""), {})
        if override.get("floor_id"):
            try:
                floor_id = uuid.UUID(str(override["floor_id"]))
            except ValueError:
                pass
        endpoint_agents = agents_by_endpoint.get(endpoint.id, []) if endpoint else []
        owner = owner_by_id.get(endpoint.owner_user_id) if endpoint and endpoint.owner_user_id else None
        attachment_rows.append({
            "id": str(row.id),
            "mac_address": row.mac_address,
            "attachment_type": row.observation_type,
            "equipment_id": str(equipment_item.id),
            "floor_id": str(floor_id) if floor_id else None,
            "port": row.port,
            "vlan": row.vlan,
            "ssid": row.ssid,
            "state": row.state,
            "observed_at": _dt(row.observed_at),
            "match_state": match_state,
            "candidate_endpoint_ids": [str(item) for item in candidates] if len(candidates) > 1 else [],
            "endpoint": ({
                "id": str(endpoint.id),
                "hostname": endpoint.hostname,
                "ip_address": (lease.ip_address if lease and lease.ip_address else endpoint.ip_address),
                "os_version": endpoint.os_version,
                "username": endpoint.username,
                "last_seen": _dt(endpoint.last_seen),
                "risk_score": endpoint.risk_score,
                "owner": owner.full_name if owner else None,
                "products": sorted({agent.product_name for agent in endpoint_agents if agent.status == "active"}),
            } if endpoint else {
                "id": None,
                "hostname": lease.hostname if lease else None,
                "ip_address": lease.ip_address if lease else None,
                "os_version": None,
                "username": None,
                "last_seen": None,
                "risk_score": None,
                "owner": None,
                "products": [],
            }),
        })

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "floors": [{"id": str(f.id), "ordinal": f.ordinal, "label": f.label, "managed": f.managed} for f in floors],
        "connections": [{
            "id": str(c.id), "type": c.connection_type, "name": c.display_name,
            "enabled": c.enabled,
            "status": c.status, "last_collected_at": _dt(c.last_collected_at),
            "last_error": c.last_error,
        } for c in connections],
        "equipment": [{
            "id": str(item.id), "connection_id": str(item.connection_id),
            "kind": item.kind, "name": item.display_name,
            "floor_id": str(item.floor_id) if item.floor_id else None,
            "position": {"x": item.position_x, "z": item.position_z},
            "metadata": item.metadata_json or {}, "port_overrides": item.port_overrides or {},
            "last_seen": _dt(item.last_seen),
        } for item in equipment],
        "attachments": attachment_rows,
        "summary": {
            "floors": sum(1 for floor in floors if floor.managed),
            "building_floors": FLOOR_COUNT,
            "equipment": len(equipment),
            "endpoints": len(attachment_rows),
            "matched": sum(1 for item in attachment_rows if item["match_state"] == "matched"),
            "unassigned_equipment": sum(1 for item in equipment if item.floor_id is None),
        },
    }
