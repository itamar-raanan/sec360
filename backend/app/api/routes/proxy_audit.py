"""Symantec Management Center policy audit API."""

import uuid
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import case, desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import audit_action, get_current_user, get_db, require_role
from app.models.proxy_audit import ProxyAuditConnection, ProxyAuditEvent
from app.models.system_settings import SystemSettings
from app.models.user import AuthUser
from app.services.proxy_audit import ManagementCenterClient, run_proxy_audit_sync


router = APIRouter(prefix="/proxy-audit", tags=["proxy-audit"])


class ProxyAuditConnectionIn(BaseModel):
    base_url: str = Field(min_length=1, max_length=2000)
    username: str = Field(min_length=1, max_length=255)
    password: str = Field(default="", max_length=4000)
    verify_ssl: bool = True
    timeout_seconds: int = Field(default=60, ge=5, le=120)


async def _ensure_enabled(db: AsyncSession) -> None:
    enabled = await db.scalar(
        select(SystemSettings.proxy_audit_enabled).where(SystemSettings.id == 1)
    )
    if not enabled:
        raise HTTPException(409, "Enable Proxy Audit in Platform Settings to use this feature")


async def _require_enabled(
    _: AuthUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    await _ensure_enabled(db)


def _connection_payload(item: ProxyAuditConnection | None) -> dict:
    config = item.config if item and item.config else {}
    return {
        "configured": bool(config),
        "base_url": config.get("base_url", ""),
        "username": config.get("username", ""),
        "verify_ssl": config.get("verify_ssl", True),
        "timeout_seconds": config.get("timeout_seconds", 60),
        "status": item.status if item else "unconfigured",
        "last_tested_at": item.last_tested_at if item else None,
        "last_sync": item.last_sync if item else None,
        "last_error": item.last_error if item else None,
        "records_synced": item.records_synced if item else 0,
        "sync_in_progress": item.sync_in_progress if item else False,
    }


def _event_payload(item: ProxyAuditEvent, *, include_diff: bool = False) -> dict:
    payload = {
        "id": str(item.id),
        "policy_uuid": item.policy_uuid,
        "policy_name": item.policy_name,
        "object_type": item.object_type,
        "author": item.author,
        "revision_date": item.revision_date,
        "revision_number": item.revision_number,
        "comment": item.comment,
        "change_summary": item.change_summary,
        "additions": item.additions,
        "deletions": item.deletions,
        "synced_at": item.synced_at,
    }
    if include_diff:
        payload["diff_text"] = item.diff_text
    return payload


def _merged_config(data: ProxyAuditConnectionIn, existing: dict | None) -> dict:
    password = data.password or str((existing or {}).get("password") or "")
    if not password:
        raise HTTPException(422, "Management Center password is required")
    base_url = data.base_url.strip().rstrip("/")
    if base_url.endswith("/api"):
        base_url = base_url[:-4]
    config = {
        "base_url": base_url,
        "username": data.username.strip(),
        "password": password,
        "verify_ssl": data.verify_ssl,
        "timeout_seconds": data.timeout_seconds,
    }
    ManagementCenterClient(config).validate()
    return config


@router.get("/status")
async def proxy_audit_status(
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(get_current_user),
):
    enabled = await db.scalar(
        select(SystemSettings.proxy_audit_enabled).where(SystemSettings.id == 1)
    )
    return {"enabled": bool(enabled)}


@router.get("/connection", dependencies=[Depends(_require_enabled)])
async def get_proxy_audit_connection(
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("viewer")),
):
    return _connection_payload(await db.get(ProxyAuditConnection, 1))


@router.put("/connection", dependencies=[Depends(_require_enabled)])
async def save_proxy_audit_connection(
    data: ProxyAuditConnectionIn,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(require_role("admin")),
):
    item = await db.get(ProxyAuditConnection, 1)
    config = _merged_config(data, item.config if item else None)
    if item is None:
        item = ProxyAuditConnection(id=1)
        db.add(item)
    item.config = config
    item.status = "configured"
    item.last_error = None
    await db.flush()
    await audit_action(
        "save_proxy_audit_connection",
        "proxy_audit_connection",
        "1",
        request,
        db,
        current,
        {
            "base_url": config["base_url"],
            "username": config["username"],
            "verify_ssl": config["verify_ssl"],
        },
    )
    return _connection_payload(item)


@router.post("/connection/test", dependencies=[Depends(_require_enabled)])
async def test_proxy_audit_connection(
    data: ProxyAuditConnectionIn,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(require_role("admin")),
):
    item = await db.get(ProxyAuditConnection, 1)
    config = _merged_config(data, item.config if item else None)
    try:
        result = await ManagementCenterClient(config).test_connection()
    except Exception as exc:
        result = {"success": False, "message": str(exc)}
    if item:
        item.last_tested_at = datetime.now(timezone.utc)
    await audit_action(
        "test_proxy_audit_connection",
        "proxy_audit_connection",
        "1",
        request,
        db,
        current,
        {"success": result["success"], "base_url": config["base_url"]},
    )
    return result


@router.post("/sync", status_code=status.HTTP_202_ACCEPTED, dependencies=[Depends(_require_enabled)])
async def sync_proxy_audit(
    background_tasks: BackgroundTasks,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(require_role("admin")),
):
    item = await db.get(ProxyAuditConnection, 1)
    if not item or not item.config:
        raise HTTPException(409, "Configure the Management Center connection before syncing")
    if item.sync_in_progress:
        return {"started": False, "message": "A Proxy Audit sync is already running"}
    item.sync_in_progress = True
    item.last_error = None
    await db.flush()
    await audit_action(
        "sync_proxy_audit",
        "proxy_audit_connection",
        "1",
        request,
        db,
        current,
        {},
    )
    # BackgroundTasks run outside this request's DB lifecycle. Commit the
    # running state first so the isolated sync session can see the connection.
    await db.commit()
    background_tasks.add_task(run_proxy_audit_sync)
    return {"started": True, "message": "Proxy Audit sync started"}


@router.get("/summary", dependencies=[Depends(_require_enabled)])
async def proxy_audit_summary(
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("viewer")),
):
    row = (await db.execute(select(
        func.count(ProxyAuditEvent.id),
        func.count(func.distinct(ProxyAuditEvent.policy_uuid)),
        func.sum(case((ProxyAuditEvent.object_type == "shared_object", 1), else_=0)),
        func.count(func.distinct(ProxyAuditEvent.author)),
        func.max(ProxyAuditEvent.revision_date),
    ))).one()
    return {
        "revisions": row[0] or 0,
        "objects": row[1] or 0,
        "shared_revisions": row[2] or 0,
        "authors": row[3] or 0,
        "last_change": row[4],
    }


@router.get("", dependencies=[Depends(_require_enabled)])
async def list_proxy_audit_events(
    response: Response,
    search: str | None = Query(None, max_length=255),
    object_type: Literal["policy", "shared_object"] | None = None,
    author: str | None = Query(None, max_length=255),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("viewer")),
):
    query = select(ProxyAuditEvent)
    if search:
        pattern = f"%{search.strip()}%"
        query = query.where(or_(
            ProxyAuditEvent.policy_name.ilike(pattern),
            ProxyAuditEvent.policy_uuid.ilike(pattern),
            ProxyAuditEvent.author.ilike(pattern),
            ProxyAuditEvent.comment.ilike(pattern),
            ProxyAuditEvent.change_summary.ilike(pattern),
        ))
    if object_type:
        query = query.where(ProxyAuditEvent.object_type == object_type)
    if author:
        query = query.where(ProxyAuditEvent.author == author)
    total = await db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = (await db.execute(
        query.order_by(desc(ProxyAuditEvent.revision_date), desc(ProxyAuditEvent.synced_at))
        .offset(offset)
        .limit(limit)
    )).scalars().all()
    response.headers["X-Total-Count"] = str(total)
    return [_event_payload(item) for item in rows]


@router.get("/{event_id}", dependencies=[Depends(_require_enabled)])
async def get_proxy_audit_event(
    event_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("viewer")),
):
    item = await db.get(ProxyAuditEvent, event_id)
    if not item:
        raise HTTPException(404, "Proxy audit revision not found")
    return _event_payload(item, include_diff=True)
