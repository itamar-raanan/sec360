"""
Settings routes — user management, 2FA, system config, audit log.
All write operations require admin role.
"""
import asyncio
import io
import base64
import logging
import secrets
from typing import Literal, Optional
from datetime import datetime, timezone, timedelta

import pyotp
import qrcode
import qrcode.image.svg

from fastapi import APIRouter, Depends, File, HTTPException, Request, status, Query, UploadFile
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import and_, func, not_, or_, select
from pydantic import BaseModel, Field

from app.api.deps import get_db, get_current_user, require_role, audit_action
from app.core.security import hash_password, verify_password
from app.models.user import AuthUser
from app.models.system_settings import SystemSettings
from app.models.audit import AuditLog
from app.models.change_event import ChangeEvent, SiemDelivery
from app.services.product_scope import normalize_product_tags

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/settings", tags=["settings"])


# ─── Pydantic schemas ────────────────────────────────────────────────────────

class AuthUserOut(BaseModel):
    model_config = {"from_attributes": True}
    id: str
    email: str
    role: str
    auth_method: str
    is_active: bool
    mfa_enabled: bool
    invitation_pending: bool
    created_at: datetime

    @classmethod
    def from_orm(cls, u: AuthUser):
        return cls(
            id=str(u.id),
            email=u.email,
            role=u.role,
            auth_method=u.auth_method,
            is_active=u.is_active,
            mfa_enabled=u.mfa_enabled,
            invitation_pending=bool(u.invitation_token),
            created_at=u.created_at,
        )


class CreateUserRequest(BaseModel):
    email: str
    password: str
    role: str = "analyst"


class InviteUserRequest(BaseModel):
    email: str
    role: str = "analyst"


class ProvisionUserRequest(BaseModel):
    email: str
    role: str = "analyst"
    auth_method: Literal["local", "sso", "radius"] = "local"


class UpdateUserRequest(BaseModel):
    role: Optional[str] = None
    is_active: Optional[bool] = None


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class MfaVerifyRequest(BaseModel):
    code: str


class SystemSettingsIn(BaseModel):
    offline_threshold_hours: Optional[int] = None
    risk_weight_no_edr: Optional[float] = None
    risk_weight_edr_version: Optional[float] = None
    risk_weight_no_dlp: Optional[float] = None
    risk_weight_dlp_version: Optional[float] = None
    risk_weight_no_wss: Optional[float] = None
    risk_weight_wss_version: Optional[float] = None
    risk_weight_no_user: Optional[float] = None
    risk_weight_no_encryption: Optional[float] = None
    risk_weight_offline: Optional[float] = None
    risk_weight_outdated_agent: Optional[float] = None
    risk_weight_outdated_os: Optional[float] = None
    auto_correlation: Optional[bool] = None
    enforce_mfa: Optional[bool] = None
    min_password_length: Optional[int] = None
    session_timeout_hours: Optional[int] = None
    platform_name: Optional[str] = None
    min_s1_version: Optional[str] = None
    min_dlp_version: Optional[str] = None
    min_wss_version: Optional[str] = None
    endpoint_product_tags: Optional[list[Literal["S1", "DLP", "WSS"]]] = None


class SamlSettingsIn(BaseModel):
    saml_provider: Literal["generic", "google", "adfs", "azure_ad", "entra"] = "google"
    saml_enabled: bool = False
    saml_sp_entity_id: str = ""
    saml_sp_acs_url: str = ""
    saml_idp_entity_id: str = ""
    saml_idp_sso_url: str = ""
    saml_idp_cert: str = ""
    saml_default_role: str = "viewer"
    saml_allowed_emails: str = ""
    saml_require_mfa: bool = False
    saml_sp_cert: str = ""
    saml_sp_key: str = ""
    radius_enabled: bool = False
    radius_host: str = ""
    radius_port: int = Field(default=1812, ge=1, le=65535)
    radius_shared_secret: str = ""
    radius_nas_identifier: str = Field(default="SEC360", max_length=253)
    radius_timeout_seconds: int = Field(default=5, ge=1, le=30)
    radius_username_format: Literal["email", "local_part"] = "email"
    radius_require_mfa: bool = False


class RadiusTestRequest(BaseModel):
    radius_host: str
    radius_port: int = Field(default=1812, ge=1, le=65535)
    radius_shared_secret: str = ""
    radius_nas_identifier: str = Field(default="SEC360", max_length=253)
    radius_timeout_seconds: int = Field(default=5, ge=1, le=30)
    radius_username_format: Literal["email", "local_part"] = "email"
    username: str
    password: str


class SiemSettingsIn(BaseModel):
    enabled: bool = False
    url: str = Field(default="", max_length=2000)
    auth_type: Literal["none", "basic", "bearer", "api_key"] = "none"
    username: str = Field(default="", max_length=255)
    secret: str = Field(default="", max_length=4000)
    verify_ssl: bool = True
    payload_format: Literal["json", "ndjson"] = "json"
    index_prefix: str = Field(default="sec360", max_length=100)
    timeout_seconds: int = Field(default=10, ge=1, le=60)


async def _read_upload(upload: UploadFile) -> bytes:
    from app.services.tls_certificate import MAX_CERTIFICATE_BYTES

    data = await upload.read(MAX_CERTIFICATE_BYTES + 1)
    if not data:
        raise HTTPException(400, f"{upload.filename or 'Uploaded file'} is empty")
    if len(data) > MAX_CERTIFICATE_BYTES:
        raise HTTPException(413, "Certificate files must be 512 KB or smaller")
    return data


# ─── User management (admin) ─────────────────────────────────────────────────

@router.get("/users")
async def list_auth_users(
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("admin")),
):
    result = await db.execute(select(AuthUser).order_by(AuthUser.created_at))
    users = result.scalars().all()
    return [AuthUserOut.from_orm(u) for u in users]


@router.post("/users", status_code=201)
async def create_auth_user(
    data: CreateUserRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(require_role("admin")),
):
    if data.role not in ("admin", "analyst", "viewer"):
        raise HTTPException(400, "role must be admin, analyst, or viewer")
    if len(data.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")

    existing = (await db.execute(select(AuthUser).where(AuthUser.email == data.email))).scalar_one_or_none()
    if existing:
        raise HTTPException(409, "Email already in use")

    user = AuthUser(
        email=data.email.strip().lower(),
        hashed_password=hash_password(data.password),
        role=data.role,
        auth_method="local",
        is_active=True,
        mfa_enabled=False,
    )
    db.add(user)
    await db.flush()
    await audit_action("create_user", "auth_user", str(user.id), request, db, current, {"email": data.email, "role": data.role})
    logger.info("Admin %s created user %s (%s)", current.email, data.email, data.role)
    return AuthUserOut.from_orm(user)


async def _invite_local_user(
    email: str,
    role: str,
    request: Request,
    db: AsyncSession,
    current: AuthUser,
):
    from app.services.email import send_invitation_email

    normalized_email = email.strip().lower()
    existing = (await db.execute(
        select(AuthUser).where(func.lower(AuthUser.email) == normalized_email)
    )).scalar_one_or_none()
    if existing:
        raise HTTPException(409, "Email already in use")

    token = secrets.token_urlsafe(32)
    user = AuthUser(
        email=normalized_email,
        hashed_password="",
        role=role,
        auth_method="local",
        is_active=False,
        mfa_enabled=False,
        invitation_token=token,
        invitation_expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        invited_by=current.email,
    )
    db.add(user)
    await db.flush()

    sent = send_invitation_email(normalized_email, role, token, current.email)
    await audit_action(
        "invite_user", "auth_user", str(user.id), request, db, current,
        {"email": normalized_email, "role": role, "auth_method": "local", "email_sent": sent},
    )
    logger.info("Invited local user %s (%s) by %s — email_sent=%s", normalized_email, role, current.email, sent)
    return {
        "message": "Invitation sent",
        "email": normalized_email,
        "email_sent": sent,
        "auth_method": "local",
    }


@router.post("/users/provision", status_code=201)
async def provision_auth_user(
    data: ProvisionUserRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(require_role("admin")),
):
    """Provision a Local, SSO, or RADIUS account using the appropriate lifecycle."""
    if data.role not in ("admin", "analyst", "viewer"):
        raise HTTPException(400, "role must be admin, analyst, or viewer")
    if data.auth_method == "local":
        return await _invite_local_user(data.email, data.role, request, db, current)

    normalized_email = data.email.strip().lower()
    existing = (await db.execute(
        select(AuthUser).where(func.lower(AuthUser.email) == normalized_email)
    )).scalar_one_or_none()
    if existing:
        raise HTTPException(409, "Email already in use")

    user = AuthUser(
        email=normalized_email,
        hashed_password="",
        role=data.role,
        auth_method=data.auth_method,
        is_active=True,
        mfa_enabled=False,
    )
    db.add(user)
    await db.flush()
    await audit_action(
        "provision_user", "auth_user", str(user.id), request, db, current,
        {"email": normalized_email, "role": data.role, "auth_method": data.auth_method},
    )
    logger.info(
        "Admin %s provisioned %s user %s (%s)",
        current.email, data.auth_method, normalized_email, data.role,
    )
    return {
        "message": f"{data.auth_method.upper()} user created",
        "email": normalized_email,
        "email_sent": False,
        "auth_method": data.auth_method,
    }


@router.post("/users/invite", status_code=201)
async def invite_user(
    data: InviteUserRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(require_role("admin")),
):
    """Create a pending Local account and send an invitation email."""
    if data.role not in ("admin", "analyst", "viewer"):
        raise HTTPException(400, "role must be admin, analyst, or viewer")
    return await _invite_local_user(data.email, data.role, request, db, current)


@router.patch("/users/{user_id}")
async def update_auth_user(
    user_id: str,
    data: UpdateUserRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(require_role("admin")),
):
    user = (await db.execute(select(AuthUser).where(AuthUser.id == user_id))).scalar_one_or_none()
    if not user:
        raise HTTPException(404, "User not found")
    if str(user.id) == str(current.id) and data.is_active is False:
        raise HTTPException(400, "Cannot disable your own account")
    previous = {"role": user.role, "is_active": user.is_active}
    if data.role:
        if data.role not in ("admin", "analyst", "viewer"):
            raise HTTPException(400, "Invalid role")
        user.role = data.role
    if data.is_active is not None:
        user.is_active = data.is_active
    await db.flush()
    updated = {"role": user.role, "is_active": user.is_active}
    if previous != updated:
        from app.services.change_tracking import record_change_event

        active_changed = previous["is_active"] != updated["is_active"]
        await record_change_event(
            db,
            event_type=(
                f"user.{'enabled' if updated['is_active'] else 'disabled'}"
                if active_changed else "user.access_changed"
            ),
            entity_type="user",
            entity_id=str(user.id),
            entity_name=user.email,
            action=("enabled" if updated["is_active"] else "disabled") if active_changed else "changed",
            severity="warning" if active_changed and not updated["is_active"] else "info",
            source="sec360_access",
            actor_email=current.email,
            before=previous,
            after=updated,
        )
    await audit_action(
        "update_user", "auth_user", user_id, request, db, current,
        {"before": previous, "after": updated},
    )
    return AuthUserOut.from_orm(user)


@router.delete("/users/{user_id}", status_code=204)
async def delete_auth_user(
    user_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(require_role("admin")),
):
    if str(current.id) == user_id:
        raise HTTPException(400, "Cannot delete your own account")
    user = (await db.execute(select(AuthUser).where(AuthUser.id == user_id))).scalar_one_or_none()
    if not user:
        raise HTTPException(404, "User not found")
    await audit_action("delete_user", "auth_user", user_id, request, db, current, {"email": user.email})
    await db.delete(user)


@router.post("/users/{user_id}/reset-mfa")
async def admin_reset_mfa(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("admin")),
):
    user = (await db.execute(select(AuthUser).where(AuthUser.id == user_id))).scalar_one_or_none()
    if not user:
        raise HTTPException(404, "User not found")
    user.mfa_secret = None
    user.mfa_enabled = False
    await db.flush()
    return {"message": "2FA reset successfully"}


# ─── My account ──────────────────────────────────────────────────────────────

@router.get("/me")
async def get_my_settings(current: AuthUser = Depends(get_current_user)):
    return AuthUserOut.from_orm(current)


@router.post("/me/password")
async def change_password(
    data: ChangePasswordRequest,
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(get_current_user),
):
    if current.auth_method != "local":
        raise HTTPException(400, f"Password changes are managed by {current.auth_method.upper()}")
    if not verify_password(data.current_password, current.hashed_password):
        raise HTTPException(400, "Current password is incorrect")
    if len(data.new_password) < 8:
        raise HTTPException(400, "New password must be at least 8 characters")
    current.hashed_password = hash_password(data.new_password)
    await db.flush()
    return {"message": "Password changed successfully"}


@router.get("/me/mfa/setup")
async def mfa_setup(
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(get_current_user),
):
    """Generate a new TOTP secret and return the provisioning URI + QR code."""
    if current.mfa_enabled:
        raise HTTPException(400, "2FA is already enabled")

    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=current.email, issuer_name="SEC360")

    # Generate QR code as SVG → base64 data URL
    factory = qrcode.image.svg.SvgImage
    img = qrcode.make(uri, image_factory=factory)
    buf = io.BytesIO()
    img.save(buf)
    qr_b64 = base64.b64encode(buf.getvalue()).decode()
    qr_data_url = f"data:image/svg+xml;base64,{qr_b64}"

    # Store secret temporarily (not yet enabled — user must verify)
    current.mfa_secret = secret
    await db.flush()

    return {"secret": secret, "uri": uri, "qr_code": qr_data_url}


@router.post("/me/mfa/enable")
async def mfa_enable(
    data: MfaVerifyRequest,
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(get_current_user),
):
    """Verify the TOTP code and activate 2FA."""
    if current.mfa_enabled:
        raise HTTPException(400, "2FA is already enabled")
    if not current.mfa_secret:
        raise HTTPException(400, "No MFA setup in progress — call /me/mfa/setup first")

    totp = pyotp.TOTP(current.mfa_secret)
    if not totp.verify(data.code, valid_window=1):
        raise HTTPException(400, "Invalid verification code")

    current.mfa_enabled = True
    await db.flush()
    return {"message": "2FA enabled successfully"}


@router.delete("/me/mfa")
async def mfa_disable(
    data: MfaVerifyRequest,
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(get_current_user),
):
    """Disable 2FA — requires a valid TOTP code to confirm."""
    if not current.mfa_enabled:
        raise HTTPException(400, "2FA is not enabled")

    totp = pyotp.TOTP(current.mfa_secret)
    if not totp.verify(data.code, valid_window=1):
        raise HTTPException(400, "Invalid verification code")

    current.mfa_secret = None
    current.mfa_enabled = False
    await db.flush()
    return {"message": "2FA disabled"}


# ─── System settings (admin) ──────────────────────────────────────────────────

@router.get("/endpoint-product-tags")
async def get_endpoint_product_tags(
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(get_current_user),
):
    """Return the endpoint badge selection to every authenticated role."""
    cfg = (await db.execute(select(SystemSettings).where(SystemSettings.id == 1))).scalar_one_or_none()
    tags = normalize_product_tags(cfg.endpoint_product_tags if cfg else None)
    return {"tags": list(tags)}

@router.get("/system")
async def get_system_settings(
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("admin")),
):
    cfg = (await db.execute(select(SystemSettings).where(SystemSettings.id == 1))).scalar_one_or_none()
    if not cfg:
        cfg = SystemSettings(id=1)
        db.add(cfg)
        await db.flush()
    return cfg


@router.put("/system")
async def update_system_settings(
    data: SystemSettingsIn,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(require_role("admin")),
):
    cfg = (await db.execute(select(SystemSettings).where(SystemSettings.id == 1))).scalar_one_or_none()
    if not cfg:
        cfg = SystemSettings(id=1)
        db.add(cfg)

    changes = data.model_dump(exclude_none=True)
    if "endpoint_product_tags" in changes:
        changes["endpoint_product_tags"] = list(
            normalize_product_tags(changes["endpoint_product_tags"])
        )
    product_scope_changed = (
        "endpoint_product_tags" in changes
        and normalize_product_tags(cfg.endpoint_product_tags)
        != normalize_product_tags(changes["endpoint_product_tags"])
    )
    compliance_changed = product_scope_changed or any(
        field in changes for field in ("min_s1_version", "min_dlp_version", "min_wss_version")
    )
    risk_changed = compliance_changed or any(
        field.startswith("risk_weight_") for field in changes
    )
    for field, val in changes.items():
        setattr(cfg, field, val)

    await db.flush()
    await audit_action("update_system_settings", "system_settings", "1", request, db, current, changes)
    if compliance_changed:
        # Compliance and risk are derived data. Rebuild before confirming the
        # update so every page observes one consistent configuration.
        from app.engines.compliance import run_full_compliance

        await run_full_compliance(db)
        await db.flush()

    if risk_changed:
        from app.engines.risk import update_all_risk_scores

        await update_all_risk_scores(db)
    return cfg


# ─── SAML SSO settings (admin) ───────────────────────────────────────────────

@router.get("/saml")
async def get_saml_settings(
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("admin")),
):
    cfg = (await db.execute(select(SystemSettings).where(SystemSettings.id == 1))).scalar_one_or_none()
    if not cfg:
        cfg = SystemSettings(id=1)
        db.add(cfg)
        await db.flush()
    radius = cfg.radius_config or {}
    return {
        "saml_provider": cfg.saml_provider or "google",
        "saml_enabled": cfg.saml_enabled,
        "saml_sp_entity_id": cfg.saml_sp_entity_id or "",
        "saml_sp_acs_url": cfg.saml_sp_acs_url or "",
        "saml_idp_entity_id": cfg.saml_idp_entity_id or "",
        "saml_idp_sso_url": cfg.saml_idp_sso_url or "",
        "saml_idp_cert": cfg.saml_idp_cert or "",
        "saml_default_role": cfg.saml_default_role or "viewer",
        "saml_allowed_emails": cfg.saml_allowed_emails or "",
        "saml_require_mfa": cfg.saml_require_mfa if hasattr(cfg, "saml_require_mfa") else False,
        "saml_sp_cert": cfg.saml_sp_cert or "",
        "has_sp_key": bool(cfg.saml_sp_key),
        "radius_enabled": cfg.radius_enabled,
        "radius_host": radius.get("host", ""),
        "radius_port": radius.get("port", 1812),
        "radius_nas_identifier": radius.get("nas_identifier", "SEC360"),
        "radius_timeout_seconds": radius.get("timeout_seconds", 5),
        "radius_username_format": radius.get("username_format", "email"),
        "radius_require_mfa": radius.get("require_mfa", False),
        "has_radius_shared_secret": bool(radius.get("shared_secret")),
    }


@router.put("/saml")
async def update_saml_settings(
    data: SamlSettingsIn,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(require_role("admin")),
):
    if data.saml_default_role not in ("admin", "analyst", "viewer"):
        raise HTTPException(400, "saml_default_role must be admin, analyst, or viewer")

    cfg = (await db.execute(select(SystemSettings).where(SystemSettings.id == 1))).scalar_one_or_none()
    if not cfg:
        cfg = SystemSettings(id=1)
        db.add(cfg)

    cfg.saml_provider = data.saml_provider
    cfg.saml_enabled = data.saml_enabled
    cfg.saml_sp_entity_id = data.saml_sp_entity_id.strip()
    cfg.saml_sp_acs_url = data.saml_sp_acs_url.strip()
    cfg.saml_idp_entity_id = data.saml_idp_entity_id.strip()
    cfg.saml_idp_sso_url = data.saml_idp_sso_url.strip()
    cfg.saml_idp_cert = data.saml_idp_cert.strip()
    cfg.saml_default_role = data.saml_default_role
    cfg.saml_allowed_emails = data.saml_allowed_emails.strip()
    cfg.saml_require_mfa = data.saml_require_mfa
    cfg.saml_sp_cert = data.saml_sp_cert.strip()
    if data.saml_sp_key:
        cfg.saml_sp_key = data.saml_sp_key.strip()

    current_radius = cfg.radius_config or {}
    shared_secret = data.radius_shared_secret or current_radius.get("shared_secret", "")
    if data.radius_enabled and (not data.radius_host.strip() or not shared_secret):
        raise HTTPException(400, "RADIUS server and shared secret are required when RADIUS is enabled")
    cfg.radius_enabled = data.radius_enabled
    cfg.radius_config = {
        "host": data.radius_host.strip(),
        "port": data.radius_port,
        "shared_secret": shared_secret,
        "nas_identifier": data.radius_nas_identifier.strip() or "SEC360",
        "timeout_seconds": data.radius_timeout_seconds,
        "username_format": data.radius_username_format,
        "require_mfa": data.radius_require_mfa,
    }

    await db.flush()
    await audit_action("update_saml_settings", "system_settings", "1", request, db, current,
                       {
                           "saml_enabled": data.saml_enabled,
                           "saml_provider": data.saml_provider,
                           "radius_enabled": data.radius_enabled,
                           "radius_host": data.radius_host.strip(),
                       })
    logger.info(
        "Admin %s updated authentication settings (SAML provider=%s, SAML enabled=%s, RADIUS enabled=%s)",
        current.email,
        data.saml_provider,
        data.saml_enabled,
        data.radius_enabled,
    )
    return {"message": "Authentication settings saved"}


@router.post("/radius/test")
async def test_radius_settings(
    data: RadiusTestRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(require_role("admin")),
):
    """Test the complete RADIUS exchange using explicit administrator credentials."""
    from app.services.radius_auth import RadiusError, authenticate_radius

    cfg = (await db.execute(select(SystemSettings).where(SystemSettings.id == 1))).scalar_one_or_none()
    saved_radius = cfg.radius_config if cfg and cfg.radius_config else {}
    host = data.radius_host.strip()
    secret = data.radius_shared_secret or saved_radius.get("shared_secret", "")
    username = data.username.strip()
    if not host or not secret:
        return {"success": False, "message": "RADIUS server and shared secret are required"}
    if not username or not data.password:
        return {"success": False, "message": "Test username and password are required"}
    if data.radius_username_format == "local_part":
        username = username.split("@", 1)[0]

    try:
        accepted, reason = await asyncio.to_thread(
            authenticate_radius,
            host=host,
            port=data.radius_port,
            secret=secret,
            username=username,
            password=data.password,
            nas_identifier=data.radius_nas_identifier.strip() or "SEC360",
            timeout_seconds=float(data.radius_timeout_seconds),
        )
        message = (
            "RADIUS authentication succeeded"
            if accepted
            else f"RADIUS rejected the test credentials ({reason})"
        )
    except RadiusError as exc:
        accepted = False
        message = str(exc)

    await audit_action(
        "test_radius", "system_settings", "1", request, db, current,
        {"success": accepted, "host": host, "port": data.radius_port},
    )
    return {"success": accepted, "message": message}


# ─── HTTPS certificate management (admin) ───────────────────────────────────

@router.get("/tls-certificate")
async def get_tls_certificate_status(
    _: AuthUser = Depends(require_role("admin")),
):
    from app.services.tls_certificate import certificate_status

    return certificate_status()


@router.post("/tls-certificate")
async def upload_tls_certificate(
    request: Request,
    certificate: UploadFile = File(...),
    private_key: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(require_role("admin")),
):
    from app.services.tls_certificate import install_certificate

    certificate_data = await _read_upload(certificate)
    private_key_data = await _read_upload(private_key)
    try:
        info = install_certificate(certificate_data, private_key_data)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(503, str(exc)) from exc
    except OSError as exc:
        logger.error("TLS certificate installation failed: %s", exc, exc_info=True)
        raise HTTPException(500, "The certificate could not be stored safely") from exc

    await audit_action(
        "update_tls_certificate",
        "tls_certificate",
        info["serial_number"],
        request,
        db,
        current,
        {
            "subject": info["subject"],
            "issuer": info["issuer"],
            "not_after": info["not_after"],
            "fingerprint_sha256": info["fingerprint_sha256"],
        },
    )
    logger.info("Admin %s installed HTTPS certificate %s", current.email, info["serial_number"])
    return {
        **info,
        "message": "Certificate installed. HTTPS will reload automatically within 10 seconds.",
    }


# ─── Audit log (admin) ───────────────────────────────────────────────────────

@router.get("/audit")
async def get_audit_log(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("admin")),
):
    total = (await db.execute(select(func.count()).select_from(AuditLog))).scalar_one()
    result = await db.execute(
        select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit).offset(offset)
    )
    logs = result.scalars().all()
    return {
        "total": total,
        "items": [
            {
                "id": str(l.id),
                "action": l.action,
                "resource_type": l.resource_type,
                "resource_id": l.resource_id,
                "timestamp": l.timestamp.isoformat(),
                "ip_address": l.ip_address,
                "details": l.details,
            }
            for l in logs
        ],
    }


@router.get("/change-events")
async def get_change_events(
    entity_type: Optional[str] = Query(None, pattern="^(endpoint|user)$"),
    event_type: Optional[str] = Query(None, max_length=100),
    category: Optional[Literal["agents", "users", "dlp"]] = Query(None),
    severity: Optional[str] = Query(None, pattern="^(info|warning|error)$"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("admin")),
):
    query = select(ChangeEvent)
    visible_event_types = {
        "agents": {"endpoint.product_added", "endpoint.product_missing"},
        "users": {"user.enabled", "user.disabled"},
        "dlp": {
            "endpoint.dlp_exclusion_added",
            "endpoint.dlp_exclusion_removed",
            "endpoint.compliance_exclusions_changed",
        },
    }
    selected_event_types = (
        visible_event_types[category]
        if category
        else set().union(*visible_event_types.values())
    )
    query = query.where(ChangeEvent.event_type.in_(selected_event_types))
    # Older tracker versions emitted product-missing rows while establishing a
    # baseline. Keep them stored for audit integrity, but do not present them as
    # real changes because the product never transitioned from present to absent.
    baseline_product_missing = and_(
        ChangeEvent.event_type == "endpoint.product_missing",
        or_(
            ChangeEvent.before.is_(None),
            ChangeEvent.details["initial_observation"].as_boolean().is_(True),
            ChangeEvent.details["newly_tracked"].as_boolean().is_(True),
        ),
    )
    query = query.where(not_(baseline_product_missing))
    if entity_type:
        query = query.where(ChangeEvent.entity_type == entity_type)
    if event_type:
        query = query.where(ChangeEvent.event_type == event_type)
    if severity:
        query = query.where(ChangeEvent.severity == severity)
    total = await db.scalar(select(func.count()).select_from(query.subquery())) or 0
    items = (await db.execute(
        query.order_by(ChangeEvent.timestamp.desc()).limit(limit).offset(offset)
    )).scalars().all()
    return {
        "total": total,
        "items": [
            {
                "id": str(item.id),
                "event_type": item.event_type,
                "entity_type": item.entity_type,
                "entity_id": item.entity_id,
                "entity_name": item.entity_name,
                "action": item.action,
                "severity": item.severity,
                "source": item.source,
                "actor_email": item.actor_email,
                "before": item.before,
                "after": item.after,
                "details": item.details,
                "timestamp": item.timestamp.isoformat(),
            }
            for item in items
        ],
    }


@router.get("/siem")
async def get_siem_settings(
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("admin")),
):
    cfg = await db.get(SystemSettings, 1)
    config = cfg.siem_config if cfg and cfg.siem_config else {}
    pending = await db.scalar(
        select(func.count()).select_from(SiemDelivery).where(SiemDelivery.status == "pending")
    ) or 0
    failed = await db.scalar(
        select(func.count()).select_from(SiemDelivery).where(SiemDelivery.status == "failed")
    ) or 0
    return {
        "enabled": bool(cfg and cfg.siem_enabled),
        "url": config.get("url", ""),
        "auth_type": config.get("auth_type", "none"),
        "username": config.get("username", ""),
        "has_secret": bool(config.get("secret")),
        "verify_ssl": config.get("verify_ssl", True),
        "payload_format": config.get("payload_format", "json"),
        "index_prefix": config.get("index_prefix", "sec360"),
        "timeout_seconds": config.get("timeout_seconds", 10),
        "pending_deliveries": pending,
        "failed_deliveries": failed,
    }


def _validated_siem_config(
    data: SiemSettingsIn,
    previous: dict | None = None,
    *,
    require_connection: bool = False,
) -> dict:
    url = data.url.strip()
    connection_required = data.enabled or require_connection
    if connection_required and not (url.startswith("https://") or url.startswith("http://")):
        raise HTTPException(400, "SIEM URL must start with http:// or https://")
    secret = data.secret or (previous or {}).get("secret", "")
    if connection_required and data.auth_type != "none" and not secret:
        raise HTTPException(400, "Authentication secret is required")
    if connection_required and data.auth_type == "basic" and not data.username.strip():
        raise HTTPException(400, "Username is required for basic authentication")
    return {
        "url": url,
        "auth_type": data.auth_type,
        "username": data.username.strip(),
        "secret": secret,
        "verify_ssl": data.verify_ssl,
        "payload_format": data.payload_format,
        "index_prefix": data.index_prefix.strip() or "sec360",
        "timeout_seconds": data.timeout_seconds,
    }


@router.put("/siem")
async def update_siem_settings(
    data: SiemSettingsIn,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(require_role("admin")),
):
    cfg = await db.get(SystemSettings, 1)
    if not cfg:
        cfg = SystemSettings(id=1)
        db.add(cfg)
    config = _validated_siem_config(data, cfg.siem_config)
    cfg.siem_enabled = data.enabled
    cfg.siem_config = config
    await db.flush()
    await audit_action(
        "update_siem_settings", "system_settings", "1", request, db, current,
        {
            "enabled": data.enabled,
            "url": config["url"],
            "auth_type": config["auth_type"],
            "payload_format": config["payload_format"],
            "verify_ssl": config["verify_ssl"],
        },
    )
    return {"message": "SIEM settings saved"}


@router.post("/siem/test")
async def test_siem_settings(
    data: SiemSettingsIn,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(require_role("admin")),
):
    cfg = await db.get(SystemSettings, 1)
    config = _validated_siem_config(
        data,
        cfg.siem_config if cfg else None,
        require_connection=True,
    )
    from app.services.siem import ECS_VERSION, send_ecs_document

    sample = {
        "@timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "ecs": {"version": ECS_VERSION},
        "event": {
            "kind": "event", "category": ["configuration"], "type": ["info"],
            "action": "siem_connection_test", "outcome": "success", "provider": "sec360",
        },
        "service": {"name": "sec360"},
        "observer": {"vendor": "SEC360", "product": "SEC360"},
        "message": "SEC360 SIEM connection test",
        "user": {"email": current.email},
    }
    try:
        await send_ecs_document(config, sample)
    except Exception as exc:
        raise HTTPException(502, f"SIEM connection failed: {str(exc)[:500]}") from exc
    await audit_action("test_siem_connection", "system_settings", "1", request, db, current, {"url": config["url"]})
    return {"success": True, "message": "ECS test event delivered successfully"}
