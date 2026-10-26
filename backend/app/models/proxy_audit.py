import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base
from app.core.encryption import EncryptedJSON


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ProxyAuditConnection(Base):
    """Singleton Management Center connection with encrypted credentials."""

    __tablename__ = "proxy_audit_connections"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    config: Mapped[dict | None] = mapped_column(EncryptedJSON, nullable=True)
    status: Mapped[str] = mapped_column(String(24), default="unconfigured", index=True)
    last_tested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_sync: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    last_error: Mapped[str | None] = mapped_column(Text)
    records_synced: Mapped[int] = mapped_column(Integer, default=0)
    sync_in_progress: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class ProxyAuditEvent(Base):
    """A source-faithful Management Center policy revision and calculated diff."""

    __tablename__ = "proxy_audit_events"
    __table_args__ = (
        UniqueConstraint("policy_uuid", "revision_number", name="uq_proxy_audit_policy_revision"),
        Index("ix_proxy_audit_policy_date", "policy_uuid", "revision_date"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    policy_uuid: Mapped[str] = mapped_column(String(255), index=True)
    policy_name: Mapped[str] = mapped_column(String(500), index=True)
    object_type: Mapped[str] = mapped_column(String(24), index=True)
    author: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    revision_date: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    revision_number: Mapped[str] = mapped_column(String(100))
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    change_summary: Mapped[str] = mapped_column(Text)
    diff_text: Mapped[str] = mapped_column(Text, default="")
    additions: Mapped[int] = mapped_column(Integer, default=0)
    deletions: Mapped[int] = mapped_column(Integer, default=0)
    content_hash: Mapped[str] = mapped_column(String(64))
    synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
