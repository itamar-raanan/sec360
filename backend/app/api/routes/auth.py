import logging
import secrets
import uuid
from datetime import datetime, timezone

import pyotp
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from pydantic import BaseModel
from app.api.deps import get_db, get_current_user, audit_action
from app.core.config import settings
from app.core.security import verify_password, hash_password, create_access_token, create_refresh_token, create_sso_mfa_pending_token, decode_token
from app.core.rate_limit import check_rate_limit, record_failure, clear_failures
from app.models.user import AuthUser
from app.schemas.user import LoginRequest, TokenResponse, AuthUserResponse


class AcceptInviteRequest(BaseModel):
    token: str
    password: str

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["auth"])


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _set_auth_cookies(response: Response, access_token: str, refresh_token: str) -> None:
    common = dict(
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite="lax",
        path="/",
    )
    response.set_cookie(
        key="sec360_token",
        value=access_token,
        max_age=settings.JWT_EXPIRE_MINUTES * 60,
        **common,
    )
    response.set_cookie(
        key="sec360_refresh",
        value=refresh_token,
        max_age=settings.JWT_REFRESH_EXPIRE_HOURS * 3600,
        path="/api/auth/refresh",
        **{k: v for k, v in common.items() if k != "path"},
    )


def _clear_auth_cookies(response: Response) -> None:
    response.delete_cookie("sec360_token", path="/")
    response.delete_cookie("sec360_refresh", path="/api/auth/refresh")


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/login")
async def login(
    data: LoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    ip = _get_client_ip(request)
    await check_rate_limit(data.email, ip)

    result = await db.execute(select(AuthUser).where(AuthUser.email == data.email))
    user = result.scalar_one_or_none()

    if not user or not verify_password(data.password, user.hashed_password):
        await record_failure(data.email, ip)
        logger.warning("Failed login attempt for %s from %s", data.email, ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account disabled")

    # ── 2FA check ──────────────────────────────────────────────────────────────
    if user.mfa_enabled:
        if not data.totp_code:
            return {"mfa_required": True}
        totp = pyotp.TOTP(user.mfa_secret)
        if not totp.verify(data.totp_code, valid_window=1):
            await record_failure(data.email, ip)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid 2FA code",
            )

    await clear_failures(data.email, ip)
    logger.info("Successful login for %s from %s", data.email, ip)
    await audit_action("login", "auth_user", str(user.id), request, db, user)

    token_data = {"sub": str(user.id), "email": user.email, "role": user.role}
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)
    _set_auth_cookies(response, access_token, refresh_token)

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": AuthUserResponse.model_validate(user).model_dump(),
    }


@router.post("/logout")
async def logout(response: Response, _: AuthUser = Depends(get_current_user)):
    _clear_auth_cookies(response)
    return {"message": "Logged out"}


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(request: Request, response: Response, db: AsyncSession = Depends(get_db)):
    """Issue a new access token using the refresh token cookie."""
    token = request.cookies.get("sec360_refresh")
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="No refresh token")

    try:
        payload = decode_token(token)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token")

    if payload.get("type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not a refresh token")

    try:
        user_id = uuid.UUID(payload.get("sub", ""))
    except (ValueError, AttributeError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token payload")
    result = await db.execute(select(AuthUser).where(AuthUser.id == user_id))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")

    token_data = {"sub": str(user.id), "email": user.email, "role": user.role}
    new_access = create_access_token(token_data)
    new_refresh = create_refresh_token(token_data)
    _set_auth_cookies(response, new_access, new_refresh)

    return TokenResponse(
        access_token=new_access,
        user=AuthUserResponse.model_validate(user),
    )


@router.get("/me", response_model=AuthUserResponse)
async def get_me(current_user: AuthUser = Depends(get_current_user)):
    return AuthUserResponse.model_validate(current_user)


# ── Invitation acceptance ─────────────────────────────────────────────────────

@router.get("/invite/{token}")
async def validate_invite(token: str, db: AsyncSession = Depends(get_db)):
    """Public endpoint — check if an invite token is valid and return the email."""
    now = datetime.now(timezone.utc)
    result = await db.execute(
        select(AuthUser).where(
            AuthUser.invitation_token == token,
            AuthUser.invitation_expires_at > now,
            AuthUser.is_active == False,  # noqa: E712
        )
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="Invitation not found or expired")
    return {"email": user.email, "role": user.role, "valid": True}


@router.post("/invite/accept")
async def accept_invite(
    data: AcceptInviteRequest,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """Public endpoint — set password and activate the invited account."""
    if len(data.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")

    now = datetime.now(timezone.utc)
    result = await db.execute(
        select(AuthUser).where(
            AuthUser.invitation_token == data.token,
            AuthUser.invitation_expires_at > now,
            AuthUser.is_active == False,  # noqa: E712
        )
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=400, detail="Invitation not found or expired")

    user.hashed_password = hash_password(data.password)
    user.is_active = True
    user.invitation_token = None
    user.invitation_expires_at = None
    await db.flush()

    logger.info("Invite accepted for %s", user.email)
    token_data = {"sub": str(user.id), "email": user.email, "role": user.role}
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)
    _set_auth_cookies(response, access_token, refresh_token)

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": AuthUserResponse.model_validate(user).model_dump(),
    }


# ── Google SAML SSO ───────────────────────────────────────────────────────────

def _build_saml_request(request: Request, post_data: dict | None = None) -> dict:
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host", request.headers.get("host", request.url.netloc))
    port = request.url.port
    return {
        "https": "on" if scheme == "https" else "off",
        "http_host": host,
        "server_port": str(port or (443 if scheme == "https" else 80)),
        "script_name": request.url.path,
        "get_data": dict(request.query_params),
        "post_data": post_data or {},
    }


async def _load_saml_cfg(db: AsyncSession, request: Request):
    """Load SAML config from DB; raise 503 if not enabled or IdP fields are missing.
    SP Entity ID and ACS URL fall back to the current request origin if not set."""
    from app.models.system_settings import SystemSettings
    cfg = (await db.execute(select(SystemSettings).where(SystemSettings.id == 1))).scalar_one_or_none()
    if not cfg or not cfg.saml_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Google SSO is not enabled. Configure it in Settings → Google SSO.",
        )
    # Derive base URL from the incoming request (respects X-Forwarded-Proto/Host)
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host", request.headers.get("host", request.url.netloc))
    base = f"{scheme}://{host}"
    if not cfg.saml_sp_entity_id or not cfg.saml_sp_entity_id.strip():
        cfg.saml_sp_entity_id = base
    if not cfg.saml_sp_acs_url or not cfg.saml_sp_acs_url.strip():
        cfg.saml_sp_acs_url = f"{base}/api/auth/saml/acs"

    missing = [f for f, v in [
        ("IdP Entity ID", cfg.saml_idp_entity_id),
        ("IdP SSO URL", cfg.saml_idp_sso_url),
        ("IdP Certificate", cfg.saml_idp_cert),
    ] if not v or not v.strip()]
    if missing:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"SSO configuration incomplete. Missing: {', '.join(missing)}. Go to Settings → Google SSO.",
        )
    return cfg


def _saml_settings_dict(cfg) -> dict:
    return {
        "strict": not settings.DEBUG,
        "debug": settings.DEBUG,
        "sp": {
            "entityId": cfg.saml_sp_entity_id,
            "assertionConsumerService": {
                "url": cfg.saml_sp_acs_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            "x509cert": cfg.saml_sp_cert or "",
            "privateKey": cfg.saml_sp_key or "",
        },
        "idp": {
            "entityId": cfg.saml_idp_entity_id,
            "singleSignOnService": {
                "url": cfg.saml_idp_sso_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": cfg.saml_idp_cert,
        },
        "security": {
            "wantAttributeStatement": False,
        },
    }


@router.get("/saml/status")
async def saml_status(db: AsyncSession = Depends(get_db)):
    """Public endpoint — returns whether Google SSO is configured and enabled."""
    from app.models.system_settings import SystemSettings
    cfg = (await db.execute(select(SystemSettings).where(SystemSettings.id == 1))).scalar_one_or_none()
    if not cfg or not cfg.saml_enabled:
        return {"enabled": False}
    missing = [f for f, v in [
        ("idp_entity_id", cfg.saml_idp_entity_id),
        ("idp_sso_url", cfg.saml_idp_sso_url),
        ("idp_cert", cfg.saml_idp_cert),
    ] if not v or not v.strip()]
    return {"enabled": len(missing) == 0}


@router.get("/saml/login")
async def saml_login(request: Request, db: AsyncSession = Depends(get_db)):
    """Initiate Google SAML SSO — redirects the browser to Google's sign-in page."""
    from onelogin.saml2.auth import OneLogin_Saml2_Auth

    cfg = await _load_saml_cfg(db, request)
    auth = OneLogin_Saml2_Auth(_build_saml_request(request), old_settings=_saml_settings_dict(cfg))
    redirect_url = auth.login()
    return RedirectResponse(url=redirect_url, status_code=302)


@router.post("/saml/acs")
async def saml_acs(request: Request, db: AsyncSession = Depends(get_db)):
    """Assertion Consumer Service — receives and validates Google's SAML response."""
    from onelogin.saml2.auth import OneLogin_Saml2_Auth

    cfg = await _load_saml_cfg(db, request)
    form = dict(await request.form())
    auth = OneLogin_Saml2_Auth(_build_saml_request(request, post_data=form), old_settings=_saml_settings_dict(cfg))
    auth.process_response()

    errors = auth.get_errors()
    if errors or not auth.is_authenticated():
        reason = auth.get_last_error_reason() or str(errors)
        logger.warning("SAML ACS error: %s", reason)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"SSO authentication failed: {reason}")

    email = auth.get_nameid()
    if not email:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="SAML response missing email (NameID)")

    saml_subject = auth.get_nameid()

    # Build the frontend base URL early — needed for error redirects below
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host", request.headers.get("host", request.url.netloc))
    frontend_base = f"{scheme}://{host}"

    result = await db.execute(select(AuthUser).where(AuthUser.email == email))
    user = result.scalar_one_or_none()

    if user is None:
        logger.warning("SSO login rejected — no invitation found for %s", email)
        return RedirectResponse(
            url=f"{frontend_base}/login?sso_error=not_invited",
            status_code=302,
        )

    if not user.is_active:
        # Pending invitation: auto-activate on first SSO login (identity proven via Google)
        if user.invitation_token:
            user.is_active = True
            user.invitation_token = None
            user.invitation_expires_at = None
            logger.info("SSO auto-activated invited user %s", email)
        else:
            logger.warning("SSO login rejected — account disabled for %s", email)
            return RedirectResponse(
                url=f"{frontend_base}/login?sso_error=account_disabled",
                status_code=302,
            )

    if not user.saml_subject:
        user.saml_subject = saml_subject

    # If MFA is required globally or enabled on this account, redirect to TOTP step
    if cfg.saml_require_mfa or user.mfa_enabled:
        pending = create_sso_mfa_pending_token(
            {"sub": str(user.id), "email": user.email, "role": user.role}
        )
        return RedirectResponse(url=f"{frontend_base}/sso-mfa?token={pending}", status_code=302)

    await audit_action("saml_login", "auth_user", str(user.id), request, db, user)
    logger.info("Successful SSO login for %s", email)

    token_data = {"sub": str(user.id), "email": user.email, "role": user.role}
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)

    redirect_resp = RedirectResponse(url=f"{frontend_base}/dashboard", status_code=302)
    _set_auth_cookies(redirect_resp, access_token, refresh_token)
    return redirect_resp


class SsoMfaVerifyRequest(BaseModel):
    token: str
    code: str


@router.post("/saml/mfa-verify")
async def saml_mfa_verify(
    data: SsoMfaVerifyRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """Verify TOTP after SSO login when MFA is required."""
    try:
        payload = decode_token(data.token)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired — please sign in again.")

    if payload.get("type") != "sso_mfa_pending":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type.")

    try:
        user_id = uuid.UUID(payload.get("sub", ""))
    except (ValueError, AttributeError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload.")
    result = await db.execute(select(AuthUser).where(AuthUser.id == user_id))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found.")

    if not user.mfa_enabled or not user.mfa_secret:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="2FA is not set up on this account.")

    if not pyotp.TOTP(user.mfa_secret).verify(data.code, valid_window=1):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid 2FA code.")

    await audit_action("saml_login", "auth_user", str(user.id), request, db, user)
    logger.info("Successful SSO+MFA login for %s", user.email)

    token_data = {"sub": str(user.id), "email": user.email, "role": user.role}
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)
    _set_auth_cookies(response, access_token, refresh_token)
    return {"access_token": access_token, "token_type": "bearer", "user": AuthUserResponse.model_validate(user).model_dump()}


@router.get("/saml/metadata")
async def saml_metadata(request: Request, db: AsyncSession = Depends(get_db)):
    """Return this service provider's SAML metadata XML (upload to Google Admin)."""
    from onelogin.saml2.auth import OneLogin_Saml2_Auth

    cfg = await _load_saml_cfg(db, request)
    auth = OneLogin_Saml2_Auth(_build_saml_request(request), old_settings=_saml_settings_dict(cfg))
    sp_settings = auth.get_settings()
    metadata = sp_settings.get_sp_metadata()
    errors = sp_settings.validate_metadata(metadata)
    if errors:
        raise HTTPException(status_code=500, detail=f"SP metadata validation failed: {errors}")
    return Response(content=metadata, media_type="application/xml")
