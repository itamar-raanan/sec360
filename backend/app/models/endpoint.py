import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Float, DateTime, ForeignKey, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base


class Endpoint(Base):
    __tablename__ = "endpoints"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    hostname: Mapped[str] = mapped_column(String(255), index=True)
    serial_number: Mapped[str | None] = mapped_column(String(100), index=True)
    os_version: Mapped[str | None] = mapped_column(String(255))
    username: Mapped[str | None] = mapped_column(String(255))
    ip_address: Mapped[str | None] = mapped_column(String(45))
    location: Mapped[str | None] = mapped_column(String(255))
    source: Mapped[str | None] = mapped_column(String(50), default="jumpcloud")
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    tags: Mapped[str | None] = mapped_column(String(500), default=None)
    last_reboot: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    all_ips: Mapped[str | None] = mapped_column(String(500), default=None)   # comma-separated IPv4s from S1
    external_ip: Mapped[str | None] = mapped_column(String(45), default=None)  # public/external IP from S1
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_score_override: Mapped[float | None] = mapped_column(Float, nullable=True, default=None)
    risk_score_note: Mapped[str | None] = mapped_column(String(500), nullable=True, default=None)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    owner_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    owner: Mapped["User | None"] = relationship(back_populates="endpoints")  # noqa: F821
    agents: Mapped[list["SecurityAgent"]] = relationship(back_populates="endpoint")  # noqa: F821
    compliance_status: Mapped["ComplianceStatus | None"] = relationship(back_populates="endpoint")  # noqa: F821
