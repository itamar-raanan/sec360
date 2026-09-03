import uuid
from datetime import datetime, timezone
from sqlalchemy import String, DateTime, ForeignKey, Enum as SAEnum, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base


class SecurityAgent(Base):
    __tablename__ = "security_agents"
    __table_args__ = (
        Index("ix_security_agents_endpoint_product", "endpoint_id", "product_name"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    endpoint_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("endpoints.id", ondelete="CASCADE")
    )
    product_name: Mapped[str] = mapped_column(
        SAEnum("sentinelone", "symantec", "prisma", "symantec_wss", "other", name="agent_product_enum")
    )
    status: Mapped[str] = mapped_column(
        SAEnum("active", "inactive", "unknown", name="agent_status_enum"), default="unknown"
    )
    version: Mapped[str | None] = mapped_column(String(100))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # S1-specific enrichment fields (NULL for non-S1 agents)
    disk_encrypted: Mapped[bool | None] = mapped_column(default=None)
    encryption_status: Mapped[str | None] = mapped_column(String(50), default=None)
    device_control_enabled: Mapped[bool | None] = mapped_column(default=None)
    agent_group: Mapped[str | None] = mapped_column(String(255), default=None)
    agent_state: Mapped[str | None] = mapped_column(String(255), default=None)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    endpoint: Mapped["Endpoint"] = relationship(back_populates="agents")  # noqa: F821
