import asyncio
import copy
import logging
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import pyotp
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import func, select

from pydantic import BaseModel
from app.api.deps import get_db, get_current_user, audit_action
from app.core.config import settings
from app.core.security import verify_password, hash_password, create_access_token, create_refresh_token, create_sso_mfa_pending_token, decode_token
from app.core.rate_limit import check_rate_limit, record_failure, clear_failures
from app.core.request import get_client_ip
from app.models.user import AuthSession, AuthUser
from app.models.system_settings import SystemSettings
from app.services.auth_sessions import create_session, hash_refresh_jti, revoke_session
from app.schemas.user import LoginRequest, TokenResponse, AuthUserResponse


class AcceptInviteRequest(BaseModel):
    token: str
    password: str


class RadiusLoginRequest(BaseModel):
    email: str
    password: str
    totp_code: str | None = None

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["auth"])


def _set_auth_cookies(
    response: Response,
    access_token: str,
    refresh_token: str,
    access_seconds: int,
    session_seconds: int,
) -> None:
    common = dict(
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite="lax",
        path="/",
    )
    response.set_cookie(
        key="sec360_token",
        value=access_token,
        max_age=access_seconds,
        **common,
    )
    response.set_cookie(
        key="sec360_refresh",
        value=refresh_token,
        max_age=session_seconds,
        path="/api/auth/refresh",
        **{k: v for k, v in common.items() if k != "path"},
    )


def _clear_auth_cookies(response: Response) -> None:
    response.delete_cookie("sec360_token", path="/")
    response.delete_cookie("sec360_refresh", path="/api/auth/refresh")


async def _auth_policy(db: AsyncSession) -> tuple[SystemSettings | None, timedelta, timedelta]:
    cfg = (await db.execute(
        select(SystemSettings).where(SystemSettings.id == 1)
    )).scalar_one_or_none()
    timeout_hours = max(1, min(int(cfg.session_timeout_hours if cfg else settings.JWT_REFRESH_EXPIRE_HOURS), 720))
    session_lifetime = timedelta(hours=timeout_hours)
    access_lifetime = min(timedelta(minutes=settings.JWT_EXPIRE_MINUTES), session_lifetime)
    return cfg, access_lifetime, session_lifetime


def _user_response(user: AuthUser, cfg: SystemSettings | None) -> AuthUserResponse:
    result = AuthUserResponse.model_validate(user)
    result.mfa_setup_required = bool(
        cfg
        and (cfg.enforce_mfa or (user.auth_method == "sso" and cfg.saml_require_mfa))
        and not user.mfa_enabled
    )
    return result


async def _issue_login_response(
    user: AuthUser,
    response: Response,
    db: AsyncSession,
) -> TokenResponse:
    cfg, access_lifetime, session_lifetime = await _auth_policy(db)
    session, refresh_jti = await create_session(db, user, session_lifetime)
    token_data = {
        "sub": str(user.id),
        "email": user.email,
        "role": user.role,
        "sid": str(session.id),
    }
    access_token = create_access_token(token_data, expires_delta=access_lifetime)
    refresh_token = create_refresh_token(
        {**token_data, "jti": refresh_jti}, expires_delta=session_lifetime
    )
    _set_auth_cookies(
        response,
        access_token,
        refresh_token,
        int(access_lifetime.total_seconds()),
        int(session_lifetime.total_seconds()),
    )
    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        user=_user_response(user, cfg),
    )


async def _authenticate_radius_user(
    data: LoginRequest | RadiusLoginRequest,
    user: AuthUser,
    request: Request,
    response: Response,
    db: AsyncSession,
    ip: str,
):
    from app.models.system_settings import SystemSettings
    from app.services.radius_auth import RadiusError, authenticate_radius

    cfg = (await db.execute(
        select(SystemSettings).where(SystemSettings.id == 1)
    )).scalar_one_or_none()
    radius = cfg.radius_config if cfg and cfg.radius_config else {}
    if not cfg or not cfg.radius_enabled or not radius.get("host") or not radius.get("shared_secret"):
        raise HTTPException(status_code=503, detail="RADIUS authentication is not available")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account disabled")

    username = data.email.strip()
    if radius.get("username_format") == "local_part":
        username = username.split("@", 1)[0]
    try:
        accepted, reason = await asyncio.to_thread(
            authenticate_radius,
            host=radius["host"],
            port=int(radius.get("port", 1812)),
            secret=radius["shared_secret"],
            username=username,
            password=data.password,
            nas_identifier=radius.get("nas_identifier", "SEC360"),
            timeout_seconds=float(radius.get("timeout_seconds", 5)),
        )
    except RadiusError as exc:
        logger.error("RADIUS authentication service error for %s: %s", data.email, exc)
        raise HTTPException(status_code=503, detail="RADIUS authentication service unavailable") from exc

    if not accepted:
        await record_failure(data.email, ip)
        logger.warning("RADIUS login rejected for %s from %s: %s", data.email, ip, reason)
        raise HTTPException(status_code=401, detail="Invalid email or password")

    require_mfa = bool(radius.get("require_mfa")) or bool(cfg.enforce_mfa) or user.mfa_enabled
    if require_mfa:
        if not user.mfa_enabled or not user.mfa_secret:
            # The authenticated session is restricted to MFA enrollment routes.
            await clear_failures(data.email, ip)
            await audit_action("radius_login_mfa_enrollment_required", "auth_user", str(user.id), request, db, user)
            return await _issue_login_response(user, response, db)
        if not data.totp_code:
            return {"mfa_required": True}
        if not pyotp.TOTP(user.mfa_secret).verify(data.totp_code, valid_window=1):
            await record_failure(data.email, ip)
            raise HTTPException(status_code=401, detail="Invalid 2FA code")

    await clear_failures(data.email, ip)
    await audit_action("radius_login", "auth_user", str(user.id), request, db, user)
    logger.info("Successful RADIUS login for %s from %s", user.email, ip)
    return await _issue_login_response(user, response, db)


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/login")
async def login(
    data: LoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    ip = get_client_ip(request)
    await check_rate_limit(data.email, ip)

    result = await db.execute(
        select(AuthUser).where(func.lower(AuthUser.email) == data.email.strip().lower())
    )
    user = result.scalar_one_or_none()

    if not user:
        await record_failure(data.email, ip)
        logger.warning("Failed login attempt for %s from %s", data.email, ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if user.auth_method == "radius":
        return await _authenticate_radius_user(data, user, request, response, db, ip)
    if user.auth_method == "sso":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="This account uses SSO. Continue with the configured SSO provider.",
        )
    if not verify_password(data.password, user.hashed_password):
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

    return await _issue_login_response(user, response, db)


@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(get_current_user),
):
    token = request.cookies.get("sec360_token")
    if not token:
        authorization = request.headers.get("authorization", "")
        if authorization.lower().startswith("bearer "):
            token = authorization[7:].strip()
    if token:
        try:
            session_id = uuid.UUID(decode_token(token).get("sid", ""))
            await revoke_session(db, session_id)
        except (ValueError, AttributeError):
            pass
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
    try:
        session_id = uuid.UUID(payload.get("sid", ""))
        refresh_jti = payload["jti"]
    except (ValueError, TypeError, KeyError, AttributeError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token payload")

    session = (await db.execute(
        select(AuthSession).where(
            AuthSession.id == session_id,
            AuthSession.user_id == user_id,
            AuthSession.revoked_at.is_(None),
            AuthSession.expires_at > datetime.now(timezone.utc),
        ).with_for_update()
    )).scalar_one_or_none()
    if session is None or not secrets.compare_digest(session.refresh_jti_hash, hash_refresh_jti(refresh_jti)):
        _clear_auth_cookies(response)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired or already used")

    result = await db.execute(select(AuthUser).where(AuthUser.id == user_id))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")

    cfg, access_lifetime, _ = await _auth_policy(db)
    expires_at = session.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    remaining = expires_at - datetime.now(timezone.utc)
    if remaining <= timedelta(0):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired")
    new_jti = secrets.token_urlsafe(32)
    session.refresh_jti_hash = hash_refresh_jti(new_jti)
    session.last_used_at = datetime.now(timezone.utc)
    token_data = {"sub": str(user.id), "email": user.email, "role": user.role, "sid": str(session.id)}
    new_access = create_access_token(token_data, expires_delta=min(access_lifetime, remaining))
    new_refresh = create_refresh_token({**token_data, "jti": new_jti}, expires_delta=remaining)
    _set_auth_cookies(
        response,
        new_access,
        new_refresh,
        int(min(access_lifetime, remaining).total_seconds()),
        int(remaining.total_seconds()),
    )

    return TokenResponse(
        access_token=new_access,
        user=_user_response(user, cfg),
    )


@router.get("/radius/status")
async def radius_status(db: AsyncSession = Depends(get_db)):
    """Public capability endpoint; never exposes RADIUS connection details."""
    from app.models.system_settings import SystemSettings

    cfg = (await db.execute(
        select(SystemSettings).where(SystemSettings.id == 1)
    )).scalar_one_or_none()
    radius = cfg.radius_config if cfg and cfg.radius_config else {}
    return {
        "enabled": bool(
            cfg
            and cfg.radius_enabled
            and radius.get("host")
            and radius.get("shared_secret")
        ),
        "provider_label": "RADIUS",
    }


@router.post("/radius/login")
async def radius_login(
    data: RadiusLoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """Backward-compatible endpoint for explicitly provisioned RADIUS users."""
    ip = get_client_ip(request)
    await check_rate_limit(data.email, ip)
    user = (await db.execute(
        select(AuthUser).where(func.lower(AuthUser.email) == data.email.strip().lower())
    )).scalar_one_or_none()
    if not user or user.auth_method != "radius":
        await record_failure(data.email, ip)
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return await _authenticate_radius_user(data, user, request, response, db, ip)


@router.get("/me", response_model=AuthUserResponse)
async def get_me(
    db: AsyncSession = Depends(get_db),
    current_user: AuthUser = Depends(get_current_user),
):
    cfg, _, _ = await _auth_policy(db)
    return _user_response(current_user, cfg)


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
            AuthUser.auth_method == "local",
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
    cfg, _, _ = await _auth_policy(db)
    minimum_length = max(8, min(int(cfg.min_password_length if cfg else 8), 128))
    if len(data.password) < minimum_length:
        raise HTTPException(400, f"Password must be at least {minimum_length} characters")

    now = datetime.now(timezone.utc)
    result = await db.execute(
        select(AuthUser).where(
            AuthUser.invitation_token == data.token,
            AuthUser.invitation_expires_at > now,
            AuthUser.is_active == False,  # noqa: E712
            AuthUser.auth_method == "local",
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
    return await _issue_login_response(user, response, db)


# ── SAML SSO ──────────────────────────────────────────────────────────────────

SAML_PROVIDER_LABELS = {
    "generic": "SSO",
    "google": "Google Workspace",
    "adfs": "ADFS",
    "azure_ad": "Azure AD",
    "entra": "Microsoft Entra ID",
}


def _saml_provider_label(provider: str | None) -> str:
    return SAML_PROVIDER_LABELS.get(provider or "", "SSO")


def _first_saml_value(value) -> str:
    if isinstance(value, (list, tuple)):
        value = value[0] if value else ""
    return str(value or "").strip()


def _canonical_frontend_base() -> str:
    base = settings.APP_URL.rstrip("/")
    parsed = urlsplit(base)
    if not parsed.netloc or parsed.scheme not in {"http", "https"}:
        raise HTTPException(status_code=503, detail="APP_URL must be an absolute URL before SSO can be used")
    if settings.ENVIRONMENT.strip().lower() == "production" and parsed.scheme != "https":
        raise HTTPException(status_code=503, detail="APP_URL must use HTTPS before SSO can be used in production")
    return base


def _extract_saml_email(auth) -> str:
    """Resolve the login email across common Google, ADFS and Entra claims."""
    attributes = auth.get_attributes() or {}
    by_lower_name = {str(key).lower(): value for key, value in attributes.items()}
    claim_names = (
        "email",
        "mail",
        "emailaddress",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
        "userprincipalname",
        "upn",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn",
        "preferred_username",
    )
    for claim_name in claim_names:
        candidate = _first_saml_value(by_lower_name.get(claim_name.lower()))
        if candidate:
            return candidate.lower()

    # Email NameID is the standard configuration and remains the fallback for
    # existing Google Workspace installations.
    name_id = _first_saml_value(auth.get_nameid())
    return name_id.lower()

def _build_saml_request(request: Request, post_data: dict | None = None) -> dict:
    canonical = urlsplit(_canonical_frontend_base())
    scheme = canonical.scheme
    host = canonical.netloc
    port = canonical.port
    return {
        "https": "on" if scheme == "https" else "off",
        "http_host": host,
        "server_port": str(port or (443 if scheme == "https" else 80)),
        "script_name": request.url.path,
        "get_data": dict(request.query_params),
        "post_data": post_data or {},
    }


async def _load_saml_cfg(db: AsyncSession):
    """Load SAML config from DB; raise 503 if not enabled or IdP fields are missing.
    SP Entity ID and ACS URL fall back to the current request origin if not set."""
    from app.models.system_settings import SystemSettings
    cfg = (await db.execute(select(SystemSettings).where(SystemSettings.id == 1))).scalar_one_or_none()
    if not cfg or not cfg.saml_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="SSO is not enabled. Configure it in Settings → SSO.",
        )
    # Use the configured canonical origin. Host headers are client-controlled and
    # must never influence SAML entity IDs, ACS URLs, or browser redirects.
    base = _canonical_frontend_base()
    cfg = copy.copy(cfg)
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
            detail=f"SSO configuration incomplete. Missing: {', '.join(missing)}. Go to Settings → SSO.",
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
    """Public endpoint — returns whether SAML SSO is configured and enabled."""
    from app.models.system_settings import SystemSettings
    cfg = (await db.execute(select(SystemSettings).where(SystemSettings.id == 1))).scalar_one_or_none()
    provider = cfg.saml_provider if cfg else "generic"
    status_payload = {
        "provider": provider or "generic",
        "provider_label": _saml_provider_label(provider),
    }
    if not cfg or not cfg.saml_enabled:
        return {"enabled": False, **status_payload}
    missing = [f for f, v in [
        ("idp_entity_id", cfg.saml_idp_entity_id),
        ("idp_sso_url", cfg.saml_idp_sso_url),
        ("idp_cert", cfg.saml_idp_cert),
    ] if not v or not v.strip()]
    return {"enabled": len(missing) == 0, **status_payload}


@router.get("/saml/login")
async def saml_login(request: Request, db: AsyncSession = Depends(get_db)):
    """Initiate SAML SSO — redirects the browser to the configured IdP."""
    from onelogin.saml2.auth import OneLogin_Saml2_Auth

    cfg = await _load_saml_cfg(db)
    auth = OneLogin_Saml2_Auth(_build_saml_request(request), old_settings=_saml_settings_dict(cfg))
    redirect_url = auth.login()
    return RedirectResponse(url=redirect_url, status_code=302)


@router.post("/saml/acs")
async def saml_acs(request: Request, db: AsyncSession = Depends(get_db)):
    """Assertion Consumer Service — receives and validates the IdP SAML response."""
    from onelogin.saml2.auth import OneLogin_Saml2_Auth

    cfg = await _load_saml_cfg(db)
    form = dict(await request.form())
    auth = OneLogin_Saml2_Auth(_build_saml_request(request, post_data=form), old_settings=_saml_settings_dict(cfg))
    auth.process_response()

    errors = auth.get_errors()
    if errors or not auth.is_authenticated():
        reason = auth.get_last_error_reason() or str(errors)
        logger.warning("SAML ACS error: %s", reason)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"SSO authentication failed: {reason}")

    email = _extract_saml_email(auth)
    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="SAML response is missing a supported email or UPN claim",
        )

    saml_subject = _first_saml_value(auth.get_nameid()) or email

    frontend_base = _canonical_frontend_base()

    result = await db.execute(select(AuthUser).where(func.lower(AuthUser.email) == email))
    user = result.scalar_one_or_none()

    if user is None:
        logger.warning("SSO login rejected — no provisioned account found for %s", email)
        return RedirectResponse(
            url=f"{frontend_base}/login?sso_error=not_invited",
            status_code=302,
        )

    if user.auth_method != "sso":
        logger.warning("SSO login rejected — account %s uses %s authentication", email, user.auth_method)
        return RedirectResponse(
            url=f"{frontend_base}/login?sso_error=wrong_auth_method",
            status_code=302,
        )

    if not user.is_active:
        logger.warning("SSO login rejected — account disabled for %s", email)
        return RedirectResponse(
            url=f"{frontend_base}/login?sso_error=account_disabled",
            status_code=302,
        )

    if user.saml_subject and not secrets.compare_digest(user.saml_subject, saml_subject):
        logger.warning("SSO subject mismatch for provisioned account %s", email)
        return RedirectResponse(
            url=f"{frontend_base}/login?sso_error=subject_mismatch",
            status_code=302,
        )
    if not user.saml_subject:
        user.saml_subject = saml_subject

    # If MFA is required globally or enabled on this account, redirect to TOTP step
    if user.mfa_enabled:
        pending = create_sso_mfa_pending_token(
            {"sub": str(user.id), "email": user.email, "role": user.role}
        )
        redirect_resp = RedirectResponse(url=f"{frontend_base}/sso-mfa", status_code=302)
        redirect_resp.set_cookie(
            "sec360_sso_pending",
            pending,
            max_age=600,
            httponly=True,
            secure=settings.COOKIE_SECURE,
            samesite="lax",
            path="/api/auth/saml/mfa-verify",
        )
        return redirect_resp

    await audit_action("saml_login", "auth_user", str(user.id), request, db, user)
    logger.info("Successful SSO login for %s", email)

    redirect_resp = RedirectResponse(url=f"{frontend_base}/dashboard", status_code=302)
    await _issue_login_response(user, redirect_resp, db)
    return redirect_resp


class SsoMfaVerifyRequest(BaseModel):
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
        payload = decode_token(request.cookies.get("sec360_sso_pending", ""))
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

    ip = get_client_ip(request)
    await check_rate_limit(f"sso-mfa:{user.email}", ip)
    if not pyotp.TOTP(user.mfa_secret).verify(data.code, valid_window=1):
        await record_failure(f"sso-mfa:{user.email}", ip)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid 2FA code.")

    await clear_failures(f"sso-mfa:{user.email}", ip)
    await audit_action("saml_login", "auth_user", str(user.id), request, db, user)
    logger.info("Successful SSO+MFA login for %s", user.email)

    result = await _issue_login_response(user, response, db)
    response.delete_cookie("sec360_sso_pending", path="/api/auth/saml/mfa-verify")
    return result


@router.get("/saml/metadata")
async def saml_metadata(request: Request, db: AsyncSession = Depends(get_db)):
    """Return this service provider's SAML metadata XML for the configured IdP."""
    from onelogin.saml2.auth import OneLogin_Saml2_Auth

    cfg = await _load_saml_cfg(db)
    auth = OneLogin_Saml2_Auth(_build_saml_request(request), old_settings=_saml_settings_dict(cfg))
    sp_settings = auth.get_settings()
    metadata = sp_settings.get_sp_metadata()
    errors = sp_settings.validate_metadata(metadata)
    if errors:
        raise HTTPException(status_code=500, detail=f"SP metadata validation failed: {errors}")
    return Response(content=metadata, media_type="application/xml")
