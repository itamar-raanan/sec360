from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.change_event import ChangeEvent, EntityStateSnapshot
from app.models.endpoint import Endpoint
from app.models.user import User
from app.services.compliance_agents import load_required_compliance_agents
from app.services.siem import queue_change_event


TRACKING_MARKER_TYPE = "system"
TRACKING_MARKER_ID = "inventory-change-tracking-v1"


async def record_change_event(
    db: AsyncSession,
    *,
    event_type: str,
    entity_type: str,
    entity_id: str,
    entity_name: str | None,
    action: str,
    severity: str = "info",
    source: str = "sec360",
    actor_email: str | None = None,
    before: dict | None = None,
    after: dict | None = None,
    details: dict | None = None,
) -> ChangeEvent:
    event = ChangeEvent(
        event_type=event_type,
        entity_type=entity_type,
        entity_id=entity_id,
        entity_name=entity_name,
        action=action,
        severity=severity,
        source=source,
        actor_email=actor_email,
        before=before,
        after=after,
        details=details,
    )
    db.add(event)
    await queue_change_event(db, event)
    return event


def _endpoint_state(endpoint: Endpoint, required_keys: set[str]) -> dict[str, Any]:
    compliance = endpoint.compliance_status
    presence = dict(compliance.agent_presence or {}) if compliance else {}
    products = {key: bool(presence.get(key, False)) for key in sorted(required_keys)}
    controls = {
        "edr_version_ok": compliance.edr_version_ok if compliance else None,
        "dlp_version_ok": compliance.dlp_version_ok if compliance else None,
        "wss_version_ok": compliance.wss_version_ok if compliance else None,
        "disk_encrypted": compliance.disk_encrypted if compliance else None,
        "device_control_enabled": compliance.device_control_enabled if compliance else None,
    }
    return {
        "hostname": endpoint.hostname,
        "source": endpoint.source,
        "active": bool(endpoint.is_active and endpoint.lifecycle_state == "active"),
        "lifecycle_state": endpoint.lifecycle_state,
        "owner_user_id": str(endpoint.owner_user_id) if endpoint.owner_user_id else None,
        "compliance_status": compliance.status if compliance else "not_evaluated",
        "products": products,
        "controls": controls,
    }


def _user_state(user: User) -> dict[str, Any]:
    return {
        "email": user.email,
        "full_name": user.full_name,
        "enabled": user.employment_status == "active" and not user.suspended,
        "employment_status": user.employment_status,
        "suspended": bool(user.suspended),
        "mfa_enabled": bool(user.mfa_enabled),
        "sources": user.sources or {},
    }


async def _emit_endpoint_changes(
    db: AsyncSession,
    endpoint_id: str,
    old: dict | None,
    new: dict,
) -> int:
    count = 0
    common = {
        "entity_type": "endpoint",
        "entity_id": endpoint_id,
        "entity_name": new["hostname"],
        "source": new.get("source") or "sec360",
    }
    if old is None:
        await record_change_event(
            db, event_type="endpoint.detected", action="detected", after=new,
            details={"message": "New endpoint detected"}, **common,
        )
        count += 1
        for product, present in new["products"].items():
            # An absent product on a newly discovered endpoint is an initial
            # state, not a transition. Only record products actually detected.
            if not present:
                continue
            await record_change_event(
                db,
                event_type="endpoint.product_added",
                action="added",
                severity="info",
                after={"product": product, "present": present},
                details={"product": product, "initial_observation": True},
                **common,
            )
            count += 1
        return count

    if old.get("active") != new.get("active"):
        enabled = new["active"]
        await record_change_event(
            db,
            event_type=f"endpoint.{'enabled' if enabled else 'disabled'}",
            action="enabled" if enabled else "disabled",
            severity="info" if enabled else "warning",
            before={"active": old.get("active"), "lifecycle_state": old.get("lifecycle_state")},
            after={"active": enabled, "lifecycle_state": new.get("lifecycle_state")},
            **common,
        )
        count += 1
    old_products = old.get("products", {})
    for product in sorted(new["products"]):
        was_present = bool(old_products.get(product, False))
        is_present = bool(new["products"].get(product, False))
        newly_tracked = product not in old_products
        # Adding a product to the compliance scope establishes a baseline. It
        # must not report every endpoint as newly missing that product.
        if newly_tracked and not is_present:
            continue
        if was_present == is_present and not newly_tracked:
            continue
        await record_change_event(
            db,
            event_type="endpoint.product_added" if is_present else "endpoint.product_missing",
            action="added" if is_present else "missing",
            severity="info" if is_present else "warning",
            before={"product": product, "present": None if newly_tracked else was_present},
            after={"product": product, "present": is_present},
            details={"product": product, "newly_tracked": newly_tracked},
            **common,
        )
        count += 1
    if old.get("compliance_status") != new.get("compliance_status"):
        await record_change_event(
            db,
            event_type="endpoint.compliance_changed",
            action="changed",
            severity="info" if new["compliance_status"] == "compliant" else "warning",
            before={"status": old.get("compliance_status")},
            after={"status": new.get("compliance_status")},
            **common,
        )
        count += 1
    old_controls = old.get("controls", {})
    for control, value in new.get("controls", {}).items():
        previous_value = old_controls.get(control)
        if control in old_controls and previous_value == value:
            continue
        await record_change_event(
            db,
            event_type="endpoint.compliance_control_changed",
            action="changed",
            severity="warning" if value is False else "info",
            before={"control": control, "value": previous_value},
            after={"control": control, "value": value},
            details={"control": control},
            **common,
        )
        count += 1
    if old.get("owner_user_id") != new.get("owner_user_id"):
        await record_change_event(
            db,
            event_type="endpoint.owner_changed",
            action="changed",
            before={"owner_user_id": old.get("owner_user_id")},
            after={"owner_user_id": new.get("owner_user_id")},
            **common,
        )
        count += 1
    changed_fields = {
        field: {"before": old.get(field), "after": new.get(field)}
        for field in ("hostname", "source", "lifecycle_state")
        if old.get(field) != new.get(field)
    }
    if changed_fields:
        await record_change_event(
            db,
            event_type="endpoint.inventory_changed",
            action="changed",
            before={key: value["before"] for key, value in changed_fields.items()},
            after={key: value["after"] for key, value in changed_fields.items()},
            details={"changed_fields": sorted(changed_fields)},
            **common,
        )
        count += 1
    return count


async def _emit_user_changes(db: AsyncSession, user_id: str, old: dict | None, new: dict) -> int:
    count = 0
    common = {
        "entity_type": "user",
        "entity_id": user_id,
        "entity_name": new["email"],
        "source": "directory",
    }
    if old is None:
        await record_change_event(
            db, event_type="user.detected", action="detected", after=new,
            details={"message": "New user detected"}, **common,
        )
        return 1
    if old.get("enabled") != new.get("enabled"):
        enabled = new["enabled"]
        await record_change_event(
            db,
            event_type=f"user.{'enabled' if enabled else 'disabled'}",
            action="enabled" if enabled else "disabled",
            severity="info" if enabled else "warning",
            before={
                "enabled": old.get("enabled"),
                "employment_status": old.get("employment_status"),
                "suspended": old.get("suspended"),
            },
            after={
                "enabled": enabled,
                "employment_status": new.get("employment_status"),
                "suspended": new.get("suspended"),
            },
            **common,
        )
        count += 1
    if old.get("mfa_enabled") != new.get("mfa_enabled"):
        enabled = new["mfa_enabled"]
        await record_change_event(
            db,
            event_type=f"user.mfa_{'enabled' if enabled else 'disabled'}",
            action="enabled" if enabled else "disabled",
            severity="info" if enabled else "warning",
            before={"mfa_enabled": old.get("mfa_enabled")},
            after={"mfa_enabled": enabled},
            **common,
        )
        count += 1
    old_sources = set((old.get("sources") or {}).keys())
    new_sources = set((new.get("sources") or {}).keys())
    if old_sources != new_sources:
        await record_change_event(
            db,
            event_type="user.sources_changed",
            action="changed",
            before={"sources": sorted(old_sources)},
            after={"sources": sorted(new_sources)},
            details={
                "added": sorted(new_sources - old_sources),
                "removed": sorted(old_sources - new_sources),
            },
            **common,
        )
        count += 1
    changed_fields = {
        field: {"before": old.get(field), "after": new.get(field)}
        for field in ("email", "full_name", "employment_status", "suspended")
        if old.get(field) != new.get(field)
    }
    if changed_fields:
        await record_change_event(
            db,
            event_type="user.compliance_changed",
            action="changed",
            severity="warning" if not new.get("enabled") else "info",
            before={key: value["before"] for key, value in changed_fields.items()},
            after={key: value["after"] for key, value in changed_fields.items()},
            details={"changed_fields": sorted(changed_fields)},
            **common,
        )
        count += 1
    return count


async def capture_inventory_changes(db: AsyncSession) -> int:
    """Compare the current inventory with its last snapshot and emit changes."""
    now = datetime.now(timezone.utc)
    required_keys = {agent.key for agent in await load_required_compliance_agents(db)}
    endpoints = (await db.execute(
        select(Endpoint).options(selectinload(Endpoint.compliance_status))
    )).scalars().all()
    users = (await db.execute(select(User))).scalars().all()
    snapshots = (await db.execute(select(EntityStateSnapshot))).scalars().all()
    by_key = {(item.entity_type, item.entity_id): item for item in snapshots}
    initialized = (TRACKING_MARKER_TYPE, TRACKING_MARKER_ID) in by_key
    current_keys: set[tuple[str, str]] = set()
    emitted = 0

    for endpoint in endpoints:
        entity_id = str(endpoint.id)
        key = ("endpoint", entity_id)
        current_keys.add(key)
        state = _endpoint_state(endpoint, required_keys)
        snapshot = by_key.get(key)
        if initialized:
            emitted += await _emit_endpoint_changes(db, entity_id, snapshot.state if snapshot else None, state)
        if snapshot:
            snapshot.state = state
            snapshot.updated_at = now
        else:
            db.add(EntityStateSnapshot(entity_type="endpoint", entity_id=entity_id, state=state, updated_at=now))

    for user in users:
        entity_id = str(user.id)
        key = ("user", entity_id)
        current_keys.add(key)
        state = _user_state(user)
        snapshot = by_key.get(key)
        if initialized:
            emitted += await _emit_user_changes(db, entity_id, snapshot.state if snapshot else None, state)
        if snapshot:
            snapshot.state = state
            snapshot.updated_at = now
        else:
            db.add(EntityStateSnapshot(entity_type="user", entity_id=entity_id, state=state, updated_at=now))

    if initialized:
        for snapshot in snapshots:
            key = (snapshot.entity_type, snapshot.entity_id)
            if snapshot.entity_type not in {"endpoint", "user"} or key in current_keys:
                continue
            state = snapshot.state or {}
            await record_change_event(
                db,
                event_type=f"{snapshot.entity_type}.removed",
                entity_type=snapshot.entity_type,
                entity_id=snapshot.entity_id,
                entity_name=state.get("hostname") or state.get("email"),
                action="removed",
                severity="warning",
                source=state.get("source") or "sec360",
                before=state,
            )
            await db.delete(snapshot)
            emitted += 1
    else:
        db.add(EntityStateSnapshot(
            entity_type=TRACKING_MARKER_TYPE,
            entity_id=TRACKING_MARKER_ID,
            state={"initialized_at": now.isoformat()},
            updated_at=now,
        ))

    await db.flush()
    return emitted
