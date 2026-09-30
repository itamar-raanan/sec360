import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.change_event import ChangeEvent, SiemDelivery
from app.models.system_settings import SystemSettings


logger = logging.getLogger(__name__)
ECS_VERSION = "8.11.0"


def _iso(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _event_type(action: str) -> list[str]:
    if action in {"created", "detected", "added", "enabled"}:
        return ["creation"]
    if action in {"removed", "deleted", "disabled"}:
        return ["deletion"]
    return ["change"]


def change_event_to_ecs(event: ChangeEvent) -> dict[str, Any]:
    category = "host" if event.entity_type == "endpoint" else "iam"
    message = f"{event.event_type} for {event.entity_name or event.entity_id}"
    document: dict[str, Any] = {
        "@timestamp": _iso(event.timestamp),
        "ecs": {"version": ECS_VERSION},
        "event": {
            "id": str(event.id),
            "kind": "event",
            "category": [category],
            "type": _event_type(event.action),
            "action": event.event_type,
            "outcome": "success",
            "provider": "sec360",
        },
        "service": {"name": "sec360"},
        "observer": {"vendor": "SEC360", "product": "SEC360"},
        "log": {"level": event.severity},
        "message": message,
        "labels": {
            "sec360_entity_type": event.entity_type,
            "sec360_source": event.source,
        },
        "sec360": {
            "change": {
                "entity_id": event.entity_id,
                "entity_name": event.entity_name,
                "before": event.before,
                "after": event.after,
                "details": event.details,
            }
        },
    }
    if event.entity_type == "endpoint":
        document["host"] = {"id": event.entity_id, "name": event.entity_name or event.entity_id}
    elif event.entity_type == "user":
        document["user"] = {"id": event.entity_id, "email": event.entity_name}
    if event.actor_email:
        document["user"] = {**document.get("user", {}), "email": event.actor_email}
        document["user"]["target"] = {"id": event.entity_id, "name": event.entity_name}
    return document


def audit_log_to_ecs(log) -> dict[str, Any]:
    details = log.details or {}
    document: dict[str, Any] = {
        "@timestamp": _iso(log.timestamp),
        "ecs": {"version": ECS_VERSION},
        "event": {
            "id": str(log.id),
            "kind": "event",
            "category": ["configuration"],
            "type": ["change"],
            "action": log.action,
            "outcome": "success",
            "provider": "sec360",
        },
        "service": {"name": "sec360"},
        "observer": {"vendor": "SEC360", "product": "SEC360"},
        "message": f"{log.action} on {log.resource_type or 'system'}",
        "sec360": {
            "audit": {
                "resource_type": log.resource_type,
                "resource_id": log.resource_id,
                "details": details,
            }
        },
    }
    if details.get("actor_email"):
        document["user"] = {
            "id": details.get("actor_id"),
            "email": details.get("actor_email"),
        }
    if log.ip_address and log.ip_address != "unknown":
        document["source"] = {"ip": log.ip_address}
    return document


async def queue_change_event(db: AsyncSession, event: ChangeEvent) -> None:
    await db.flush()
    db.add(SiemDelivery(
        source_type="change_event",
        source_id=str(event.id),
        payload=change_event_to_ecs(event),
    ))


async def queue_audit_log(db: AsyncSession, log) -> None:
    await db.flush()
    db.add(SiemDelivery(
        source_type="audit_log",
        source_id=str(log.id),
        payload=audit_log_to_ecs(log),
    ))


def _headers(config: dict) -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    auth_type = config.get("auth_type", "none")
    secret = config.get("secret", "")
    if auth_type == "bearer" and secret:
        headers["Authorization"] = f"Bearer {secret}"
    elif auth_type == "api_key" and secret:
        headers["Authorization"] = f"ApiKey {secret}"
    return headers


async def send_ecs_document(config: dict, document: dict[str, Any]) -> None:
    from app.core.outbound import validate_outbound_url

    url = str(config.get("url", "")).strip()
    if not url:
        raise ValueError("SIEM URL is not configured")
    await validate_outbound_url(url)
    auth = None
    if config.get("auth_type") == "basic":
        auth = (str(config.get("username", "")), str(config.get("secret", "")))
    payload_format = config.get("payload_format", "json")
    content = None
    json_payload = document
    headers = _headers(config)
    if payload_format == "ndjson":
        index_prefix = str(config.get("index_prefix", "sec360")).strip() or "sec360"
        index_name = f"{index_prefix}-{datetime.now(timezone.utc):%Y.%m.%d}"
        content = json.dumps({"create": {"_index": index_name}}) + "\n" + json.dumps(document) + "\n"
        json_payload = None
        headers["Content-Type"] = "application/x-ndjson"
    async with httpx.AsyncClient(
        timeout=float(config.get("timeout_seconds", 10)),
        verify=bool(config.get("verify_ssl", True)),
    ) as client:
        response = await client.post(url, headers=headers, auth=auth, json=json_payload, content=content)
        response.raise_for_status()
        if payload_format == "ndjson":
            try:
                result = response.json()
            except ValueError:
                result = None
            if isinstance(result, dict) and result.get("errors") is True:
                raise RuntimeError("Elastic bulk endpoint reported one or more rejected events")


async def flush_siem_deliveries(*, limit: int = 100) -> dict[str, int]:
    from app.core.database import AsyncSessionLocal

    now = datetime.now(timezone.utc)
    sent = failed = 0
    async with AsyncSessionLocal() as db:
        settings = await db.get(SystemSettings, 1)
        if not settings or not settings.siem_enabled or not settings.siem_config:
            return {"sent": 0, "failed": 0}
        config = settings.siem_config
        deliveries = (await db.execute(
            select(SiemDelivery)
            .where(
                SiemDelivery.status.in_(("pending", "failed")),
                or_(SiemDelivery.next_attempt_at.is_(None), SiemDelivery.next_attempt_at <= now),
            )
            .order_by(SiemDelivery.created_at)
            .limit(limit)
        )).scalars().all()
        for delivery in deliveries:
            try:
                await send_ecs_document(config, delivery.payload)
                delivery.status = "sent"
                delivery.sent_at = datetime.now(timezone.utc)
                delivery.last_error = None
                sent += 1
            except Exception as exc:
                delivery.status = "failed"
                delivery.attempts += 1
                delivery.last_error = str(exc)[:2000]
                delay_minutes = min(2 ** min(delivery.attempts, 6), 60)
                delivery.next_attempt_at = datetime.now(timezone.utc) + timedelta(minutes=delay_minutes)
                failed += 1
                logger.warning("SIEM delivery %s failed: %s", delivery.id, exc)
        await db.commit()
    return {"sent": sent, "failed": failed}
