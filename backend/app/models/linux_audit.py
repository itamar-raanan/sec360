import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Index, Integer, JSON, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class LinuxAuditReport(Base):
    """A source-faithful CIS audit upload with searchable server metadata."""

    __tablename__ = "linux_audit_reports"
    __table_args__ = (
        UniqueConstraint("content_hash", name="uq_linux_audit_reports_content_hash"),
        Index("ix_linux_audit_reports_host_generated", "hostname", "generated_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    hostname: Mapped[str] = mapped_column(String(255), index=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    endpoint_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("endpoints.id", ondelete="SET NULL"), nullable=True, index=True
    )
    os_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    profile: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    benchmark_name: Mapped[str] = mapped_column(String(255))
    benchmark_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)

    total_count: Mapped[int] = mapped_column(Integer, default=0)
    pass_count: Mapped[int] = mapped_column(Integer, default=0)
    fail_count: Mapped[int] = mapped_column(Integer, default=0)
    review_count: Mapped[int] = mapped_column(Integer, default=0)
    excluded_count: Mapped[int] = mapped_column(Integer, default=0)
    error_count: Mapped[int] = mapped_column(Integer, default=0)

    filename: Mapped[str] = mapped_column(String(500))
    content_hash: Mapped[str] = mapped_column(String(64))
    report_data: Mapped[dict[str, Any]] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql")
    )
    uploaded_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("auth_users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    uploaded_by_email: Mapped[str] = mapped_column(String(255))
    uploaded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )
