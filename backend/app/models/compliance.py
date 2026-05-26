import uuid
from datetime import datetime, timezone
from sqlalchemy import Boolean, DateTime, ForeignKey, Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base


class ComplianceStatus(Base):
    __tablename__ = "compliance_statuses"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    endpoint_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("endpoints.id", ondelete="CASCADE"), unique=True, index=True
    )
    # Core compliance checks
    edr_installed: Mapped[bool] = mapped_column(Boolean, default=False)
    edr_version_ok: Mapped[bool] = mapped_column(Boolean, default=False)
    dlp_installed: Mapped[bool] = mapped_column(Boolean, default=False)
    dlp_version_ok: Mapped[bool] = mapped_column(Boolean, default=False)
    # GlobalProtect VPN app (detected via S1 application inventory)
    gp_installed: Mapped[bool] = mapped_column(Boolean, default=False)
    gp_version_ok: Mapped[bool] = mapped_column(Boolean, default=False)
    # Symantec WSS Agent (detected via S1 application inventory)
    wss_installed: Mapped[bool] = mapped_column(Boolean, default=False)
    wss_version_ok: Mapped[bool] = mapped_column(Boolean, default=False)
    # S1 enrichment — populated by compliance engine from S1 agent data
    disk_encrypted: Mapped[bool | None] = mapped_column(Boolean, default=None)
    device_control_enabled: Mapped[bool | None] = mapped_column(Boolean, default=None)
    # Legacy columns — kept for DB compat, no longer evaluated
    agent_up_to_date: Mapped[bool] = mapped_column(Boolean, default=False)
    os_up_to_date: Mapped[bool] = mapped_column(Boolean, default=False)
    last_seen_recent: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(
        SAEnum("compliant", "partial", "non_compliant", name="compliance_status_enum"),
        default="non_compliant",
        index=True,
    )
    last_evaluated: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    endpoint: Mapped["Endpoint"] = relationship(back_populates="compliance_status")  # noqa: F821
