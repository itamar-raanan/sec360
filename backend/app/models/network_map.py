import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import BigInteger, Boolean, DateTime, Float, ForeignKey, Index, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base
from app.core.encryption import EncryptedJSON


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class NetworkMapCollector(Base):
    __tablename__ = "network_map_collectors"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    token_prefix: Mapped[str] = mapped_column(String(24))
    status: Mapped[str] = mapped_column(String(24), default="enrolled", index=True)
    version: Mapped[str | None] = mapped_column(String(64))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    last_ip: Mapped[str | None] = mapped_column(String(64))
    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSON().with_variant(JSONB(), "postgresql"), default=dict
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class NetworkMapConnection(Base):
    __tablename__ = "network_map_connections"
    __table_args__ = (
        UniqueConstraint("collector_id", "source_identifier", name="uq_network_map_collector_source"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    connection_type: Mapped[str] = mapped_column(String(32), index=True)
    display_name: Mapped[str] = mapped_column(String(120))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    collector_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("network_map_collectors.id", ondelete="CASCADE"), nullable=True, index=True
    )
    source_identifier: Mapped[str | None] = mapped_column(String(160), nullable=True)
    config: Mapped[dict[str, Any]] = mapped_column(EncryptedJSON, default=dict)
    status: Mapped[str] = mapped_column(String(24), default="unconfigured")
    last_tested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_collected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    records_synced: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class NetworkMapFloor(Base):
    __tablename__ = "network_map_floors"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    ordinal: Mapped[int] = mapped_column(Integer, unique=True, index=True)
    label: Mapped[str] = mapped_column(String(80))
    managed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class NetworkMapEquipment(Base):
    __tablename__ = "network_map_equipment"
    __table_args__ = (
        UniqueConstraint("connection_id", "source_key", name="uq_network_map_equipment_source"),
        Index("ix_network_map_equipment_floor_kind", "floor_id", "kind"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    connection_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("network_map_connections.id", ondelete="CASCADE"), index=True
    )
    source_key: Mapped[str] = mapped_column(String(255))
    kind: Mapped[str] = mapped_column(String(20), index=True)
    display_name: Mapped[str] = mapped_column(String(255))
    floor_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("network_map_floors.id", ondelete="SET NULL"), nullable=True, index=True
    )
    position_x: Mapped[float] = mapped_column(Float, default=0)
    position_z: Mapped[float] = mapped_column(Float, default=0)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSON().with_variant(JSONB(), "postgresql"), default=dict
    )
    port_overrides: Mapped[dict[str, Any]] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"), default=dict
    )
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class NetworkMapCollectionRun(Base):
    __tablename__ = "network_map_collection_runs"
    __table_args__ = (
        UniqueConstraint("collector_id", "external_snapshot_id", name="uq_network_map_collector_snapshot"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    connection_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("network_map_connections.id", ondelete="CASCADE"), index=True
    )
    collector_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("network_map_collectors.id", ondelete="SET NULL"), nullable=True, index=True
    )
    external_snapshot_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    sequence: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    received_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(24), default="running")
    complete_snapshot: Mapped[bool] = mapped_column(Boolean, default=False)
    record_count: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class NetworkMapObservation(Base):
    __tablename__ = "network_map_observations"
    __table_args__ = (
        Index("ix_network_map_observation_current", "connection_id", "is_current", "mac_address"),
        Index("ix_network_map_observation_equipment", "equipment_id", "is_current"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    run_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("network_map_collection_runs.id", ondelete="CASCADE"), index=True
    )
    connection_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("network_map_connections.id", ondelete="CASCADE"), index=True
    )
    equipment_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("network_map_equipment.id", ondelete="SET NULL"), nullable=True, index=True
    )
    observation_type: Mapped[str] = mapped_column(String(24), index=True)
    mac_address: Mapped[str] = mapped_column(String(17), index=True)
    hostname: Mapped[str | None] = mapped_column(String(255))
    ip_address: Mapped[str | None] = mapped_column(String(45))
    ssid: Mapped[str | None] = mapped_column(String(255))
    interface: Mapped[str | None] = mapped_column(String(255))
    port: Mapped[str | None] = mapped_column(String(80))
    vlan: Mapped[str | None] = mapped_column(String(80))
    vdom: Mapped[str | None] = mapped_column(String(255))
    state: Mapped[str | None] = mapped_column(String(80))
    raw: Mapped[dict[str, Any]] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"), default=dict
    )
    is_current: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
