from sqlalchemy import Integer, Boolean, Float, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base


class SystemSettings(Base):
    """Single-row configuration table (id is always 1)."""
    __tablename__ = "system_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)

    # Compliance / risk weights (must sum ≤ 100)
    offline_threshold_hours: Mapped[int] = mapped_column(Integer, default=24)
    risk_weight_no_edr: Mapped[float] = mapped_column(Float, default=30.0)
    risk_weight_edr_version: Mapped[float] = mapped_column(Float, default=20.0)
    risk_weight_no_dlp: Mapped[float] = mapped_column(Float, default=25.0)
    risk_weight_dlp_version: Mapped[float] = mapped_column(Float, default=15.0)
    risk_weight_no_user: Mapped[float] = mapped_column(Float, default=10.0)
    # Legacy columns kept for DB compatibility — no longer used in scoring
    risk_weight_no_encryption: Mapped[float] = mapped_column(Float, default=0.0)
    risk_weight_offline: Mapped[float] = mapped_column(Float, default=0.0)
    risk_weight_outdated_agent: Mapped[float] = mapped_column(Float, default=0.0)
    risk_weight_outdated_os: Mapped[float] = mapped_column(Float, default=0.0)

    # Automation
    auto_correlation: Mapped[bool] = mapped_column(Boolean, default=True)

    # Security policies
    enforce_mfa: Mapped[bool] = mapped_column(Boolean, default=False)
    min_password_length: Mapped[int] = mapped_column(Integer, default=8)
    session_timeout_hours: Mapped[int] = mapped_column(Integer, default=168)

    # Branding
    platform_name: Mapped[str] = mapped_column(String(100), default="SEC360")

    # Minimum agent versions for compliance (empty string = don't check)
    min_s1_version: Mapped[str] = mapped_column(String(50), default="")
    min_dlp_version: Mapped[str] = mapped_column(String(50), default="")
    min_gp_version: Mapped[str] = mapped_column(String(50), default="")
    min_wss_version: Mapped[str] = mapped_column(String(50), default="")

    # Google SAML SSO
    saml_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    saml_sp_entity_id: Mapped[str] = mapped_column(String(500), default="")
    saml_sp_acs_url: Mapped[str] = mapped_column(String(500), default="")
    saml_idp_entity_id: Mapped[str] = mapped_column(String(500), default="")
    saml_idp_sso_url: Mapped[str] = mapped_column(String(500), default="")
    saml_idp_cert: Mapped[str] = mapped_column(Text, default="")
    saml_default_role: Mapped[str] = mapped_column(String(20), default="viewer")
    saml_sp_cert: Mapped[str] = mapped_column(Text, default="")
    saml_sp_key: Mapped[str] = mapped_column(Text, default="")
    saml_allowed_emails: Mapped[str] = mapped_column(Text, default="")
    saml_require_mfa: Mapped[bool] = mapped_column(Boolean, default=False)
