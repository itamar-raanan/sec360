import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, JSON, String, UniqueConstraint
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
    value_type: Mapped[str] = mapped_column(String(20), default="string", index=True)
    environment: Mapped[str | None] = mapped_column(String(255), index=True)
    synced_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )


class PuppetFactFavorite(Base):
    __tablename__ = "puppet_fact_favorites"
    __table_args__ = (
        UniqueConstraint("user_id", "fact_name", name="uq_puppet_fact_favorite_user_name"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("auth_users.id", ondelete="CASCADE"), index=True
    )
    fact_name: Mapped[str] = mapped_column(String(500), index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


class PuppetFactSavedView(Base):
    __tablename__ = "puppet_fact_saved_views"
    __table_args__ = (
        UniqueConstraint("user_id", "name", name="uq_puppet_fact_saved_view_user_name"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("auth_users.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(120))
    definition: Mapped[dict] = mapped_column(JSON().with_variant(JSONB(), "postgresql"))
    is_default: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
