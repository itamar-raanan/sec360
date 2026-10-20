import asyncio
import uuid
from datetime import datetime, timezone
from typing import Any, Literal
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import audit_action, get_current_user, get_db, require_role
from app.models.network_map import NetworkMapCollector, NetworkMapConnection, NetworkMapEquipment, NetworkMapFloor
from app.models.system_settings import SystemSettings
from app.models.user import AuthUser
from app.network_map.collectors import collect_for_type
from app.network_map.collector_auth import issue_collector_token, require_network_collector
from app.network_map.service import build_map_payload, collect_connection, ensure_floors, ingest_collector_snapshot


router = APIRouter(prefix="/network-map", tags=["Network Map"])
ConnectionType = Literal["cisco_wlc", "fortigate", "mikrotik"]
SINGLETON_TYPES = {"cisco_wlc", "fortigate"}
SECRET_FIELDS = {"password", "api_token"}


def _collector_only() -> None:
    raise HTTPException(
        status_code=410,
        detail="Direct Network Map connections are retired. Configure the on-premises collector from Network Map → Config.",
    )


class ConnectionIn(BaseModel):
    connection_type: ConnectionType
    display_name: str = Field(min_length=1, max_length=120)
    enabled: bool = True
    config: dict[str, Any] = Field(default_factory=dict)


class ConnectionUpdate(BaseModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=120)
    enabled: bool | None = None
    config: dict[str, Any] | None = None


class ConnectionTestIn(BaseModel):
    connection_type: ConnectionType
    config: dict[str, Any]


class FloorUpdate(BaseModel):
    label: str | None = Field(default=None, min_length=1, max_length=80)
    managed: bool | None = None


class EquipmentUpdate(BaseModel):
    floor_id: uuid.UUID | None = None
    position_x: float | None = Field(default=None, ge=-10.5, le=10.5)
    position_z: float | None = Field(default=None, ge=-6.5, le=6.5)
    port_overrides: dict[str, dict[str, Any]] | None = None


class CollectorCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)


class CollectorHeartbeat(BaseModel):
    version: str = Field(default="", max_length=64)
    queue_depth: int = Field(default=0, ge=0, le=1_000_000)
    sources: dict[str, dict[str, Any]] = Field(default_factory=dict)


class CollectorSnapshot(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    collector_id: uuid.UUID
    source_id: str = Field(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9._:-]+$")
    source_name: str = Field(min_length=1, max_length=120)
    source_type: ConnectionType
    snapshot_id: uuid.UUID
    sequence: int = Field(ge=1)
    collected_at: datetime
    complete: bool
    records: dict[str, Any]
    health: dict[str, Any] = Field(default_factory=dict)


async def _feature_enabled(db: AsyncSession) -> bool:
    value = (await db.execute(select(SystemSettings.network_map_enabled).where(SystemSettings.id == 1))).scalar_one_or_none()
    return bool(value)


async def _require_feature(db: AsyncSession) -> None:
    if not await _feature_enabled(db):
        raise HTTPException(status_code=409, detail="Network Map is disabled in System Settings.")


def _validate_config(connection_type: str, config: dict[str, Any], *, require_secret: bool) -> dict[str, Any]:
    clean = dict(config)
    if connection_type == "cisco_wlc":
        required = ["host", "username"]
        if require_secret:
            required.append("password")
        clean.setdefault("port", 22)
        clean.setdefault("timeout_seconds", 15)
        clean.setdefault("allow_unknown_host_key", False)
    elif connection_type == "fortigate":
        required = ["base_url"]
        if require_secret:
            required.append("api_token")
        clean.setdefault("vdom", "*")
        clean.setdefault("timeout_seconds", 10)
        clean.setdefault("verify_ssl", True)
    else:
        required = ["base_url", "username"]
        if require_secret:
            required.append("password")
        clean.setdefault("timeout_seconds", 10)
        clean.setdefault("verify_ssl", False)
    missing = [field for field in required if not str(clean.get(field) or "").strip()]
    if missing:
        raise HTTPException(422, detail=f"Missing required fields: {', '.join(missing)}")
    if clean.get("base_url"):
        parsed = urlsplit(str(clean["base_url"]))
        if connection_type == "fortigate" and parsed.scheme != "https":
            raise HTTPException(422, detail="FortiGate must use an HTTPS URL.")
        if connection_type == "mikrotik" and parsed.scheme not in {"http", "https"}:
            raise HTTPException(422, detail="MikroTik SwOS must use an HTTP(S) URL.")
    return clean


def _connection_out(item: NetworkMapConnection) -> dict[str, Any]:
    config = dict(item.config or {})
    safe_config = {key: value for key, value in config.items() if key not in SECRET_FIELDS}
    return {
        "id": str(item.id),
        "connection_type": item.connection_type,
        "display_name": item.display_name,
        "enabled": item.enabled,
        "collector_id": str(item.collector_id) if item.collector_id else None,
        "source_identifier": item.source_identifier,
        "managed_by_collector": item.collector_id is not None,
        "config": safe_config,
        "credentials_configured": any(bool(config.get(field)) for field in SECRET_FIELDS),
        "status": item.status,
        "last_tested_at": item.last_tested_at,
        "last_collected_at": item.last_collected_at,
        "last_error": item.last_error,
        "records_synced": item.records_synced,
    }


def _collector_out(item: NetworkMapCollector) -> dict[str, Any]:
    return {
        "id": str(item.id),
        "name": item.name,
        "status": "revoked" if item.revoked_at else item.status,
        "version": item.version,
        "token_prefix": item.token_prefix,
        "last_seen_at": item.last_seen_at,
        "last_ip": item.last_ip,
        "metadata": item.metadata_json or {},
        "revoked_at": item.revoked_at,
        "created_at": item.created_at,
    }


@router.get("/collectors")
async def list_collectors(
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("admin")),
):
    rows = (await db.execute(select(NetworkMapCollector).order_by(NetworkMapCollector.name))).scalars().all()
    return [_collector_out(item) for item in rows]


@router.post("/collectors", status_code=201)
async def create_collector(
    data: CollectorCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(require_role("admin")),
):
    name = data.name.strip()
    if await db.scalar(select(func.count()).select_from(NetworkMapCollector).where(NetworkMapCollector.name == name)):
        raise HTTPException(409, detail="A collector with this name already exists")
    collector_id = uuid.uuid4()
    token, token_hash, token_prefix = issue_collector_token(collector_id)
    item = NetworkMapCollector(
        id=collector_id, name=name, token_hash=token_hash, token_prefix=token_prefix
    )
    db.add(item)
    await db.flush()
    await audit_action("create_network_map_collector", "network_map_collector", str(item.id), request, db, current, {"name": name})
    return {**_collector_out(item), "token": token}


@router.post("/collectors/{collector_id}/rotate-token")
async def rotate_collector_token(
    collector_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(require_role("admin")),
):
    item = await db.get(NetworkMapCollector, collector_id)
    if item is None or item.revoked_at is not None:
        raise HTTPException(404, detail="Active collector not found")
    token, token_hash, token_prefix = issue_collector_token(item.id)
    item.token_hash = token_hash
    item.token_prefix = token_prefix
    await audit_action("rotate_network_map_collector_token", "network_map_collector", str(item.id), request, db, current, {})
    return {**_collector_out(item), "token": token}


@router.delete("/collectors/{collector_id}")
async def revoke_collector(
    collector_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(require_role("admin")),
):
    item = await db.get(NetworkMapCollector, collector_id)
    if item is None:
        raise HTTPException(404, detail="Collector not found")
    item.revoked_at = datetime.now(timezone.utc)
    item.status = "revoked"
    await audit_action("revoke_network_map_collector", "network_map_collector", str(item.id), request, db, current, {})
    return {"ok": True}


@router.post("/collector/heartbeat")
async def collector_heartbeat(
    data: CollectorHeartbeat,
    collector: NetworkMapCollector = Depends(require_network_collector),
):
    collector.version = data.version or collector.version
    metadata = dict(collector.metadata_json or {})
    source_metadata = dict(metadata.get("sources") or {})
    for source_id, health in data.sources.items():
        source_metadata[source_id] = {**source_metadata.get(source_id, {}), **health}
    metadata.update({"queue_depth": data.queue_depth, "sources": source_metadata})
    collector.metadata_json = metadata
    return {"ok": True, "server_time": datetime.now(timezone.utc).isoformat()}


@router.post("/collector/ingest")
async def ingest_collector_data(
    data: CollectorSnapshot,
    collector: NetworkMapCollector = Depends(require_network_collector),
    db: AsyncSession = Depends(get_db),
):
    if data.collector_id != collector.id:
        raise HTTPException(403, detail="Snapshot collector_id does not match the credential")
    try:
        run, disposition = await ingest_collector_snapshot(db, collector, data.model_dump())
    except ValueError as exc:
        raise HTTPException(422, detail=str(exc)) from exc
    return {
        "ok": True,
        "disposition": disposition,
        "run_id": str(run.id) if run else None,
        "records_synced": run.record_count if run else 0,
    }


@router.get("/status")
async def status(
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(get_current_user),
):
    return {"enabled": await _feature_enabled(db)}


@router.get("/connections")
async def list_connections(
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("admin")),
):
    rows = (await db.execute(select(NetworkMapConnection).order_by(
        NetworkMapConnection.connection_type, NetworkMapConnection.display_name
    ))).scalars().all()
    return [_connection_out(item) for item in rows]


@router.post("/connections", status_code=201)
async def create_connection(
    data: ConnectionIn,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(require_role("admin")),
):
    _collector_only()
    if data.connection_type in SINGLETON_TYPES:
        exists = (await db.execute(select(func.count()).select_from(NetworkMapConnection).where(
            NetworkMapConnection.connection_type == data.connection_type
        ))).scalar_one()
        if exists:
            raise HTTPException(409, detail=f"Only one {data.connection_type} connection is allowed.")
    config = _validate_config(data.connection_type, data.config, require_secret=True)
    item = NetworkMapConnection(
        connection_type=data.connection_type,
        display_name=data.display_name.strip(),
        enabled=data.enabled,
        config=config,
        status="configured",
    )
    db.add(item)
    await db.flush()
    await audit_action("create_network_map_connection", "network_map_connection", str(item.id), request, db, current, {
        "connection_type": item.connection_type, "display_name": item.display_name,
    })
    return _connection_out(item)


@router.put("/connections/{connection_id}")
async def update_connection(
    connection_id: uuid.UUID,
    data: ConnectionUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(require_role("admin")),
):
    _collector_only()
    item = await db.get(NetworkMapConnection, connection_id)
    if item is None:
        raise HTTPException(404, detail="Network Map connection not found")
    if data.display_name is not None:
        item.display_name = data.display_name.strip()
    if data.enabled is not None:
        item.enabled = data.enabled
    if data.config is not None:
        merged = dict(item.config or {})
        for key, value in data.config.items():
            # Omitted and blank secrets preserve the encrypted saved value.
            if key in SECRET_FIELDS and not value:
                continue
            merged[key] = value
        item.config = _validate_config(item.connection_type, merged, require_secret=True)
    item.status = "configured"
    await db.flush()
    await audit_action("update_network_map_connection", "network_map_connection", str(item.id), request, db, current, {
        "display_name": item.display_name, "enabled": item.enabled,
    })
    return _connection_out(item)


@router.delete("/connections/{connection_id}")
async def delete_connection(
    connection_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(require_role("admin")),
):
    item = await db.get(NetworkMapConnection, connection_id)
    if item is None:
        raise HTTPException(404, detail="Network Map connection not found")
    details = {"connection_type": item.connection_type, "display_name": item.display_name}
    await db.delete(item)
    await audit_action("delete_network_map_connection", "network_map_connection", str(item.id), request, db, current, details)
    return {"ok": True}


async def _test(connection_type: str, config: dict[str, Any]) -> dict[str, Any]:
    result = await asyncio.wait_for(collect_for_type(connection_type, config), timeout=45)
    return {
        "ok": True,
        "counts": {
            "access_points": len(result.get("aps", [])),
            "wireless_clients": len(result.get("clients", [])),
            "dhcp_leases": len(result.get("leases", [])),
            "switch_hosts": len(result.get("hosts", [])),
        },
    }


@router.post("/connections/test")
async def test_unsaved_connection(
    data: ConnectionTestIn,
    _: AuthUser = Depends(require_role("admin")),
):
    _collector_only()
    config = _validate_config(data.connection_type, data.config, require_secret=True)
    try:
        return await _test(data.connection_type, config)
    except Exception as exc:
        raise HTTPException(400, detail=str(exc)) from exc


@router.post("/connections/{connection_id}/test")
async def test_saved_connection(
    connection_id: uuid.UUID,
    data: ConnectionUpdate | None = None,
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("admin")),
):
    _collector_only()
    item = await db.get(NetworkMapConnection, connection_id)
    if item is None:
        raise HTTPException(404, detail="Network Map connection not found")
    test_config = dict(item.config or {})
    if data and data.config is not None:
        for key, value in data.config.items():
            if key in SECRET_FIELDS and not value:
                continue
            test_config[key] = value
    test_config = _validate_config(item.connection_type, test_config, require_secret=True)
    try:
        result = await _test(item.connection_type, test_config)
        item.status = "connected"
        item.last_error = None
        item.last_tested_at = datetime.now(timezone.utc)
        return result
    except Exception as exc:
        item.status = "error"
        item.last_error = str(exc)[:4000]
        item.last_tested_at = datetime.now(timezone.utc)
        await db.commit()
        raise HTTPException(400, detail=str(exc)) from exc


@router.post("/connections/{connection_id}/collect")
async def collect_saved_connection(
    connection_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("analyst")),
):
    _collector_only()
    await _require_feature(db)
    item = await db.get(NetworkMapConnection, connection_id)
    if item is None or not item.enabled:
        raise HTTPException(404, detail="Enabled Network Map connection not found")
    if item.collector_id is not None:
        raise HTTPException(409, detail="Collector-managed sources push their own snapshots")
    run = await collect_connection(db, item)
    if run.status == "error":
        raise HTTPException(400, detail=run.error or "Collection failed")
    return {"ok": True, "records_synced": run.record_count}


@router.get("/floors")
async def list_floors(
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("admin")),
):
    floors = await ensure_floors(db)
    return [
        {"id": str(item.id), "ordinal": item.ordinal, "label": item.label, "managed": item.managed}
        for item in floors
    ]


@router.get("/equipment")
async def list_equipment(
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("admin")),
):
    await ensure_floors(db)
    rows = (await db.execute(select(NetworkMapEquipment).order_by(
        NetworkMapEquipment.kind, NetworkMapEquipment.display_name
    ))).scalars().all()
    return [{
        "id": str(item.id),
        "connection_id": str(item.connection_id),
        "kind": item.kind,
        "name": item.display_name,
        "floor_id": str(item.floor_id) if item.floor_id else None,
        "position_x": item.position_x,
        "position_z": item.position_z,
        "port_overrides": item.port_overrides or {},
        "last_seen": item.last_seen,
    } for item in rows]


@router.put("/floors/{floor_id}")
async def update_floor(
    floor_id: uuid.UUID,
    data: FloorUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(require_role("admin")),
):
    floor = await db.get(NetworkMapFloor, floor_id)
    if floor is None:
        raise HTTPException(404, detail="Network Map floor not found")
    before = {"label": floor.label, "managed": floor.managed}
    if data.label is not None:
        floor.label = data.label.strip()
    if data.managed is not None:
        floor.managed = data.managed
    after = {"label": floor.label, "managed": floor.managed}
    await audit_action(
        "update_network_map_floor", "network_map_floor", str(floor.id), request, db, current,
        {"before": before, "after": after, "ordinal": floor.ordinal},
    )
    return {"id": str(floor.id), "ordinal": floor.ordinal, "label": floor.label, "managed": floor.managed}


@router.put("/equipment/{equipment_id}")
async def update_equipment(
    equipment_id: uuid.UUID,
    data: EquipmentUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(require_role("admin")),
):
    item = await db.get(NetworkMapEquipment, equipment_id)
    if item is None:
        raise HTTPException(404, detail="Network Map equipment not found")
    if data.floor_id is not None:
        target_floor = await db.get(NetworkMapFloor, data.floor_id)
        if target_floor is None:
            raise HTTPException(422, detail="Unknown floor")
        if not target_floor.managed:
            raise HTTPException(422, detail="Equipment can only be assigned to a managed floor")
    changes = data.model_dump(exclude_unset=True)
    if data.port_overrides is not None:
        if len(data.port_overrides) > 512:
            raise HTTPException(422, detail="At most 512 switch port overrides are allowed")
        normalized_overrides: dict[str, dict[str, Any]] = {}
        for port, override in data.port_overrides.items():
            clean_port = str(port).strip()
            if not clean_port or len(clean_port) > 80:
                raise HTTPException(422, detail="Each port override needs a valid port name")
            role = str(override.get("role") or "endpoint")
            if role not in {"endpoint", "uplink", "infrastructure"}:
                raise HTTPException(422, detail=f"Unsupported port role for {clean_port}")
            floor_value = override.get("floor_id")
            if floor_value:
                try:
                    override_floor_id = uuid.UUID(str(floor_value))
                except ValueError as exc:
                    raise HTTPException(422, detail=f"Invalid floor for port {clean_port}") from exc
                override_floor = await db.get(NetworkMapFloor, override_floor_id)
                if override_floor is None:
                    raise HTTPException(422, detail=f"Unknown floor for port {clean_port}")
                if not override_floor.managed:
                    raise HTTPException(422, detail=f"Port {clean_port} can only be assigned to a managed floor")
            normalized_overrides[clean_port] = {"role": role, **({"floor_id": str(floor_value)} if floor_value else {})}
        changes["port_overrides"] = normalized_overrides
    for key, value in changes.items():
        setattr(item, key, value)
    await audit_action("update_network_map_equipment", "network_map_equipment", str(item.id), request, db, current, changes)
    return {"ok": True}


@router.get("")
async def get_network_map(
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(get_current_user),
):
    await _require_feature(db)
    return await build_map_payload(db)
