import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Index, JSON, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class PuppetNode(Base):
    __tablename__ = "puppet_nodes"

    certname: Mapped[str] = mapped_column(String(500), primary_key=True)
    endpoint_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("endpoints.id", ondelete="SET NULL"), nullable=True, index=True
    )
    environment: Mapped[str | None] = mapped_column(String(255), index=True)
    latest_report_status: Mapped[str | None] = mapped_column(String(100), index=True)
    report_timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    catalog_timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    facts_timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    synced_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )


class PuppetFact(Base):
    __tablename__ = "puppet_facts"
    __table_args__ = (
        UniqueConstraint("certname", "name", name="uq_puppet_fact_certname_name"),
        Index("ix_puppet_facts_name_certname", "name", "certname"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    certname: Mapped[str] = mapped_column(
        ForeignKey("puppet_nodes.certname", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(500), index=True)
    value: Mapped[Any] = mapped_column(JSON().with_variant(JSONB(), "postgresql"))
    environment: Mapped[str | None] = mapped_column(String(255), index=True)
    synced_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )
