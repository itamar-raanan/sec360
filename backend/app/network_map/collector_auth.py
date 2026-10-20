"""Authentication helpers for on-premises Network Map collectors."""

import hashlib
import hmac
import secrets
import uuid
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db
from app.core.config import settings
from app.models.network_map import NetworkMapCollector


TOKEN_MARKER = "nmc"


def hash_collector_token(token: str) -> str:
    return hmac.new(settings.JWT_SECRET.encode(), token.encode(), hashlib.sha256).hexdigest()


def issue_collector_token(collector_id: uuid.UUID) -> tuple[str, str, str]:
    secret = secrets.token_urlsafe(32)
    token = f"{TOKEN_MARKER}_{collector_id}_{secret}"
    return token, hash_collector_token(token), token[:20]


def collector_id_from_token(token: str) -> uuid.UUID | None:
    parts = token.split("_", 2)
    if len(parts) != 3 or parts[0] != TOKEN_MARKER:
        return None
    try:
        return uuid.UUID(parts[1])
    except ValueError:
        return None


async def require_network_collector(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> NetworkMapCollector:
    authorization = request.headers.get("Authorization", "")
    scheme, _, token = authorization.partition(" ")
    if scheme.casefold() != "collector" or not token:
        raise HTTPException(401, detail="Collector authentication required")
    collector_id = collector_id_from_token(token)
    collector = await db.get(NetworkMapCollector, collector_id) if collector_id else None
    if (
        collector is None
        or collector.revoked_at is not None
        or not hmac.compare_digest(collector.token_hash, hash_collector_token(token))
    ):
        raise HTTPException(401, detail="Invalid or revoked collector credential")
    collector.last_seen_at = datetime.now(timezone.utc)
    collector.last_ip = request.client.host if request.client else None
    collector.status = "connected"
    return collector
