import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import AuthSession, AuthUser


def hash_refresh_jti(jti: str) -> str:
    return hashlib.sha256(jti.encode("utf-8")).hexdigest()


async def create_session(
    db: AsyncSession,
    user: AuthUser,
    lifetime: timedelta,
) -> tuple[AuthSession, str]:
    jti = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    session = AuthSession(
        id=uuid.uuid4(),
        user_id=user.id,
        refresh_jti_hash=hash_refresh_jti(jti),
        expires_at=now + lifetime,
        last_used_at=now,
    )
    db.add(session)
    await db.flush()
    return session, jti


async def revoke_session(db: AsyncSession, session_id: uuid.UUID) -> None:
    await db.execute(
        update(AuthSession)
        .where(AuthSession.id == session_id, AuthSession.revoked_at.is_(None))
        .values(revoked_at=datetime.now(timezone.utc))
    )


async def revoke_user_sessions(db: AsyncSession, user_id: uuid.UUID) -> None:
    await db.execute(
        update(AuthSession)
        .where(AuthSession.user_id == user_id, AuthSession.revoked_at.is_(None))
        .values(revoked_at=datetime.now(timezone.utc))
    )
