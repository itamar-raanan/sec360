import uuid
from typing import AsyncGenerator
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime, timezone

from app.core.database import AsyncSessionLocal
from app.core.security import decode_token, has_role
from app.models.user import AuthUser
from app.models.audit import AuditLog

security = HTTPBearer(auto_error=False)


def _get_client_ip(request: Request) -> str:
    """Return the real client IP, honouring X-Forwarded-For from a trusted proxy."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


def _extract_token(request: Request, credentials: HTTPAuthorizationCredentials | None) -> str | None:
    """Cookie takes precedence; fall back to Authorization Bearer header."""
    cookie = request.cookies.get("sec360_token")
    if cookie:
        return cookie
    if credentials:
        return credentials.credentials
    return None


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> AuthUser:
    token = _extract_token(request, credentials)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = decode_token(token)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if payload.get("type") == "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token cannot be used as access token",
        )

    user_id_raw = payload.get("sub")
    if not user_id_raw:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")
    try:
        user_id = uuid.UUID(user_id_raw)
    except (ValueError, AttributeError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

    result = await db.execute(select(AuthUser).where(AuthUser.id == user_id))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")

    return user


def require_role(required_role: str):
    async def checker(current_user: AuthUser = Depends(get_current_user)) -> AuthUser:
        if not has_role(current_user.role, required_role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires role: {required_role}",
            )
        return current_user
    return checker


async def audit_action(
    action: str,
    resource_type: str | None,
    resource_id: str | None,
    request: Request,
    db: AsyncSession,
    user: AuthUser,
    details: dict | None = None,
):
    # AuditLog.user_id FK points to the HR users table, not auth_users.
    # Store the auth user identity in details instead.
    merged = {"actor_id": str(user.id), "actor_email": user.email, **(details or {})}
    log = AuditLog(
        user_id=None,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        timestamp=datetime.now(timezone.utc),
        ip_address=_get_client_ip(request),
        details=merged,
    )
    db.add(log)
    await db.flush()
