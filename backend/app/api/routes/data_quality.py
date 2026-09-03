from datetime import datetime, timezone
from typing import Literal
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import audit_action, get_db, require_role
from app.models.endpoint import Endpoint
from app.models.integration import IntegrationConfig
from app.models.user import AuthUser
from app.services.data_quality import confidence_for, duplicate_candidates, is_current


router = APIRouter(prefix="/data-quality", tags=["data-quality"])


def _endpoint_query():
    return select(Endpoint).options(selectinload(Endpoint.owner), selectinload(Endpoint.agents))


def _endpoint_payload(endpoint: Endpoint, *, now: datetime) -> dict:
    confidence = confidence_for(endpoint, now=now)
    included = is_current(endpoint, now=now)
    if endpoint.lifecycle_state in {"ignored", "decommissioned"}:
        exclusion = f"Lifecycle state is {endpoint.lifecycle_state}"
    elif not endpoint.is_active or endpoint.lifecycle_state == "stale":
        exclusion = "Endpoint is stale or absent from authoritative inventory"
    elif not included:
        exclusion = "No source observation within the current inventory window"
    else:
        exclusion = None
    return {
        "id": str(endpoint.id),
        "hostname": endpoint.hostname,
        "serial_number": endpoint.serial_number,
        "username": endpoint.username,
        "source": endpoint.source,
        "last_seen": endpoint.last_seen,
        "owner": (
            {"id": str(endpoint.owner.id), "full_name": endpoint.owner.full_name, "email": endpoint.owner.email}
            if endpoint.owner else None
        ),
        "lifecycle_state": endpoint.lifecycle_state,
        "lifecycle_reason": endpoint.lifecycle_reason,
        "lifecycle_changed_at": endpoint.lifecycle_changed_at,
        "lifecycle_changed_by": endpoint.lifecycle_changed_by,
        "included_in_compliance": included,
        "compliance_exclusion_reason": exclusion,
        "confidence": confidence,
    }


@router.get("/summary")
async def quality_summary(
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("viewer")),
):
    now = datetime.now(timezone.utc)
    endpoints = (await db.execute(_endpoint_query())).scalars().unique().all()
    quality = [confidence_for(endpoint, now=now) for endpoint in endpoints]
    duplicates = duplicate_candidates(endpoints)
    states = {state: 0 for state in ("active", "stale", "ignored", "decommissioned")}
    for endpoint in endpoints:
        states[endpoint.lifecycle_state] = states.get(endpoint.lifecycle_state, 0) + 1

    integrations = (await db.execute(
        select(IntegrationConfig).order_by(IntegrationConfig.display_name)
    )).scalars().all()
    freshness = []
    for integration in integrations:
        age_hours = None
        if integration.last_sync:
            last_sync = integration.last_sync
            if last_sync.tzinfo is None:
                last_sync = last_sync.replace(tzinfo=timezone.utc)
            age_hours = round((now - last_sync).total_seconds() / 3600, 1)
        freshness.append({
            "integration_type": integration.integration_type,
            "display_name": integration.display_name,
            "is_enabled": integration.is_enabled,
            "status": integration.status,
            "last_sync": integration.last_sync,
            "age_hours": age_hours,
            "records_synced": integration.records_synced,
        })

    return {
        "total": len(endpoints),
        "current_inventory": sum(1 for endpoint in endpoints if is_current(endpoint, now=now)),
        "lifecycle": states,
        "confidence": {
            "high": sum(1 for item in quality if item["tier"] == "high"),
            "medium": sum(1 for item in quality if item["tier"] == "medium"),
            "low": sum(1 for item in quality if item["tier"] == "low"),
        },
        "unassigned": sum(1 for endpoint in endpoints if endpoint.owner is None),
        "duplicate_candidates": len(duplicates),
        "source_freshness": freshness,
        "generated_at": now,
    }


@router.get("/endpoints")
async def quality_endpoints(
    response: Response,
    search: str | None = Query(None),
    lifecycle: str | None = Query(None),
    confidence: Literal["high", "medium", "low"] | None = Query(None),
    issue: Literal["missing_serial", "unassigned", "low_confidence", "not_in_compliance"] | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("viewer")),
):
    query = _endpoint_query()
    if search:
        pattern = f"%{search.strip()}%"
        query = query.where(or_(
            Endpoint.hostname.ilike(pattern),
            Endpoint.serial_number.ilike(pattern),
            Endpoint.username.ilike(pattern),
        ))
    if lifecycle:
        query = query.where(Endpoint.lifecycle_state == lifecycle)
    endpoints = (await db.execute(query.order_by(Endpoint.updated_at.desc()))).scalars().unique().all()
    now = datetime.now(timezone.utc)
    payloads = [_endpoint_payload(endpoint, now=now) for endpoint in endpoints]
    if confidence:
        payloads = [item for item in payloads if item["confidence"]["tier"] == confidence]
    if issue:
        payloads = [item for item in payloads if issue in item["confidence"]["issues"]]
    response.headers["X-Total-Count"] = str(len(payloads))
    return payloads[offset:offset + limit]


@router.get("/duplicates")
async def quality_duplicates(
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("viewer")),
):
    endpoints = (await db.execute(_endpoint_query())).scalars().unique().all()
    now = datetime.now(timezone.utc)
    candidates = duplicate_candidates(endpoints)
    results = []
    for candidate in candidates[:limit]:
        results.append({
            "candidate_id": candidate["candidate_id"],
            "score": candidate["score"],
            "reasons": candidate["reasons"],
            "left": _endpoint_payload(candidate["left"], now=now),
            "right": _endpoint_payload(candidate["right"], now=now),
        })
    return {"items": results, "total": len(candidates)}


class LifecycleUpdate(BaseModel):
    state: Literal["active", "stale", "ignored", "decommissioned"]
    reason: str | None = Field(default=None, max_length=1000)


@router.patch("/endpoints/{endpoint_id}/lifecycle")
async def update_lifecycle(
    endpoint_id: uuid.UUID,
    data: LifecycleUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(require_role("analyst")),
):
    endpoint = (await db.execute(_endpoint_query().where(Endpoint.id == endpoint_id))).scalar_one_or_none()
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    reason = (data.reason or "").strip() or None
    if data.state in {"ignored", "decommissioned"} and not reason:
        raise HTTPException(status_code=422, detail="A reason is required for ignored or decommissioned endpoints")

    previous = endpoint.lifecycle_state
    endpoint.lifecycle_state = data.state
    endpoint.lifecycle_reason = reason
    endpoint.lifecycle_changed_at = datetime.now(timezone.utc)
    endpoint.lifecycle_changed_by = current.email
    endpoint.is_active = data.state == "active"
    await db.flush()
    await audit_action(
        "update_endpoint_lifecycle", "endpoint", str(endpoint.id), request, db, current,
        {"hostname": endpoint.hostname, "previous_state": previous, "state": data.state, "reason": reason},
    )
    return _endpoint_payload(endpoint, now=datetime.now(timezone.utc))
