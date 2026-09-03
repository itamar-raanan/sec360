"""
Settings routes — user management, 2FA, system config, audit log.
All write operations require admin role.
"""
import io
import base64
import logging
import secrets
from typing import Optional
from datetime import datetime, timezone, timedelta

import pyotp
import qrcode
import qrcode.image.svg

from fastapi import APIRouter, Depends, HTTPException, Request, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from pydantic import BaseModel

from app.api.deps import get_db, get_current_user, require_role, audit_action
from app.core.security import hash_password, verify_password
from app.models.user import AuthUser
from app.models.system_settings import SystemSettings
from app.models.audit import AuditLog

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/settings", tags=["settings"])


# ─── Pydantic schemas ────────────────────────────────────────────────────────

class AuthUserOut(BaseModel):
    model_config = {"from_attributes": True}
    id: str
    email: str
    role: str
    is_active: bool
    mfa_enabled: bool
    created_at: datetime

    @classmethod
    def from_orm(cls, u: AuthUser):
        return cls(
            id=str(u.id),
            email=u.email,
            role=u.role,
            is_active=u.is_active,
            mfa_enabled=u.mfa_enabled,
            created_at=u.created_at,
        )


class CreateUserRequest(BaseModel):
    email: str
    password: str
    role: str = "analyst"


class InviteUserRequest(BaseModel):
    email: str
    role: str = "analyst"


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


class SamlSettingsIn(BaseModel):
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
        email=data.email,
        hashed_password=hash_password(data.password),
        role=data.role,
        is_active=True,
        mfa_enabled=False,
    )
    db.add(user)
    await db.flush()
    await audit_action("create_user", "auth_user", str(user.id), request, db, current, {"email": data.email, "role": data.role})
    logger.info("Admin %s created user %s (%s)", current.email, data.email, data.role)
    return AuthUserOut.from_orm(user)


@router.post("/users/invite", status_code=201)
async def invite_user(
    data: InviteUserRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(require_role("admin")),
):
    """Create a pending user account and send an invitation email."""
    from app.services.email import send_invitation_email

    if data.role not in ("admin", "analyst", "viewer"):
        raise HTTPException(400, "role must be admin, analyst, or viewer")

    existing = (await db.execute(select(AuthUser).where(AuthUser.email == data.email))).scalar_one_or_none()
    if existing:
        raise HTTPException(409, "Email already in use")

    token = secrets.token_urlsafe(32)
    user = AuthUser(
        email=data.email,
        hashed_password="",          # set during acceptance
        role=data.role,
        is_active=False,             # activated when invite is accepted
        mfa_enabled=False,
        invitation_token=token,
        invitation_expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        invited_by=current.email,
    )
    db.add(user)
    await db.flush()

    sent = send_invitation_email(data.email, data.role, token, current.email)
    await audit_action("invite_user", "auth_user", str(user.id), request, db, current,
                       {"email": data.email, "role": data.role, "email_sent": sent})
    logger.info("Invited user %s (%s) by %s — email_sent=%s", data.email, data.role, current.email, sent)
    return {"message": "Invitation sent", "email": data.email, "email_sent": sent}


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
    if data.role:
        if data.role not in ("admin", "analyst", "viewer"):
            raise HTTPException(400, "Invalid role")
        user.role = data.role
    if data.is_active is not None:
        user.is_active = data.is_active
    await db.flush()
    await audit_action("update_user", "auth_user", user_id, request, db, current, data.model_dump(exclude_none=True))
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
    for field, val in changes.items():
        setattr(cfg, field, val)

    await db.flush()
    await audit_action("update_system_settings", "system_settings", "1", request, db, current, changes)
    return cfg


# ─── Google SAML SSO settings (admin) ────────────────────────────────────────

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
    return {
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

    await db.flush()
    await audit_action("update_saml_settings", "system_settings", "1", request, db, current,
                       {"saml_enabled": data.saml_enabled})
    logger.info("Admin %s updated SAML settings (enabled=%s)", current.email, data.saml_enabled)
    return {"message": "SAML settings saved"}


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
