import uuid
import secrets
from typing import AsyncGenerator
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime, timedelta, timezone

from app.core.database import AsyncSessionLocal
from app.core.security import (
    API_KEY_PREFIX,
    decode_token,
    hash_personal_api_key,
    has_role,
    personal_api_key_prefix,
)
from app.models.api_key import PersonalApiKey
from app.models.user import AuthSession, AuthUser
from app.models.system_settings import SystemSettings
from app.models.audit import AuditLog
from app.core.request import get_client_ip

security = HTTPBearer(auto_error=False)


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
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> AuthUser:
    token = _extract_token(request, credentials)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if token.startswith(API_KEY_PREFIX):
        key_prefix = personal_api_key_prefix(token)
        api_key = None
        if key_prefix:
            api_key = (await db.execute(
                select(PersonalApiKey).where(PersonalApiKey.key_prefix == key_prefix)
            )).scalar_one_or_none()
        now = datetime.now(timezone.utc)
        expires_at = api_key.expires_at if api_key else None
        if expires_at and expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        valid_key = bool(
            api_key
            and api_key.revoked_at is None
            and (expires_at is None or expires_at > now)
            and secrets.compare_digest(api_key.key_hash, hash_personal_api_key(token))
        )
        if not valid_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired API key",
                headers={"WWW-Authenticate": "Bearer"},
            )
        user = (await db.execute(
            select(AuthUser).where(AuthUser.id == api_key.user_id)
        )).scalar_one_or_none()
        if not user or not user.is_active:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")
        if request.method.upper() not in {"GET", "HEAD", "OPTIONS"}:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Personal API keys are read-only",
            )
        last_used_at = api_key.last_used_at
        if last_used_at and last_used_at.tzinfo is None:
            last_used_at = last_used_at.replace(tzinfo=timezone.utc)
        if last_used_at is None or last_used_at < now - timedelta(minutes=5):
            api_key.last_used_at = now
        request.state.authentication_type = "api_key"
        request.state.api_key_id = str(api_key.id)
    else:
        try:
            payload = decode_token(token)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if payload.get("type") != "access":
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

        user = (await db.execute(select(AuthUser).where(AuthUser.id == user_id))).scalar_one_or_none()
        if not user or not user.is_active:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")

        session_id_raw = payload.get("sid")
        if not session_id_raw:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session is no longer valid")
        try:
            session_id = uuid.UUID(session_id_raw)
        except (ValueError, AttributeError):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid session")
        active_session = (await db.execute(
            select(AuthSession).where(
                AuthSession.id == session_id,
                AuthSession.user_id == user.id,
                AuthSession.revoked_at.is_(None),
                AuthSession.expires_at > datetime.now(timezone.utc),
            )
        )).scalar_one_or_none()
        if active_session is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired or revoked")
        request.state.authentication_type = "session"

    password_change_paths = {
        "/api/auth/me",
        "/api/auth/logout",
        "/api/settings/me",
        "/api/settings/me/password",
    }
    if user.must_change_password and request.url.path not in password_change_paths:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Password change required before continuing",
        )

    cfg = (await db.execute(
        select(SystemSettings).where(SystemSettings.id == 1)
    )).scalar_one_or_none()
    mfa_setup_paths = password_change_paths | {
        "/api/settings/me/mfa/setup",
        "/api/settings/me/mfa/enable",
    }
    requires_mfa = bool(
        cfg
        and (cfg.enforce_mfa or (user.auth_method == "sso" and cfg.saml_require_mfa))
    )
    if requires_mfa and not user.mfa_enabled and request.url.path not in mfa_setup_paths:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="MFA setup required before continuing",
        )

    return user


async def require_interactive_user(
    request: Request,
    current_user: AuthUser = Depends(get_current_user),
) -> AuthUser:
    if getattr(request.state, "authentication_type", None) == "api_key":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Use an interactive session to manage API keys",
        )
    return current_user


def require_role(required_role: str):
    async def checker(current_user: AuthUser = Depends(get_current_user)) -> AuthUser:
        if not has_role(current_user.role, required_role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires role: {required_role}",
            )
        return current_user
    return checker


def require_connected_integration(integration_type: str, *, feature: str | None = None):
    """Block an integration-owned feature until its product is connected."""
    async def checker(
        _: AuthUser = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
    ) -> None:
        from app.models.integration import IntegrationConfig

        integration = (await db.execute(
            select(IntegrationConfig).where(
                IntegrationConfig.integration_type == integration_type,
                IntegrationConfig.is_enabled.is_(True),
                IntegrationConfig.status == "connected",
            )
        )).scalar_one_or_none()
        if integration is None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Connect the {integration_type} integration to use this feature.",
            )
        if feature:
            from app.integrations.catalog import available_features

            if feature not in available_features(integration_type, integration.credentials):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"The configured {integration_type} deployment does not provide this feature.",
                )

    return checker


def require_any_connected_integration(*integration_types: str):
    """Block a shared feature until at least one owning product is connected."""
    async def checker(
        _: AuthUser = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
    ) -> None:
        from app.models.integration import IntegrationConfig

        connected = (await db.execute(
            select(IntegrationConfig.integration_type).where(
                IntegrationConfig.integration_type.in_(integration_types),
                IntegrationConfig.is_enabled.is_(True),
                IntegrationConfig.status == "connected",
            )
        )).scalars().first()
        if connected is None:
            display_names = {
                "adfs": "ADFS",
                "active_directory": "Active Directory",
                "google_workspace": "Google Workspace",
            }
            products = ", ".join(display_names.get(item, item) for item in integration_types)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Connect at least one required integration: {products}.",
            )

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
        ip_address=get_client_ip(request),
        details=merged,
    )
    db.add(log)
    await db.flush()
    from app.services.siem import queue_audit_log

    await queue_audit_log(db, log)
