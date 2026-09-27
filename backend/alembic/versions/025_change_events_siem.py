"""add compliance change events and SIEM delivery outbox

Revision ID: 025
Revises: 024
Create Date: 2026-09-27
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "025"
down_revision = "024"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "change_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("event_type", sa.String(length=100), nullable=False),
        sa.Column("entity_type", sa.String(length=50), nullable=False),
        sa.Column("entity_id", sa.String(length=255), nullable=False),
        sa.Column("entity_name", sa.String(length=255), nullable=True),
        sa.Column("action", sa.String(length=50), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False, server_default="info"),
        sa.Column("source", sa.String(length=50), nullable=False, server_default="sec360"),
        sa.Column("actor_email", sa.String(length=255), nullable=True),
        sa.Column("before", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("after", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in ("event_type", "entity_type", "entity_id", "action", "severity", "actor_email", "timestamp"):
        op.create_index(f"ix_change_events_{column}", "change_events", [column])

    op.create_table(
        "entity_state_snapshots",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("entity_type", sa.String(length=50), nullable=False),
        sa.Column("entity_id", sa.String(length=255), nullable=False),
        sa.Column("state", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("entity_type", "entity_id", name="uq_entity_state_snapshot"),
    )
    op.create_index("ix_entity_state_snapshots_entity_type", "entity_state_snapshots", ["entity_type"])
    op.create_index("ix_entity_state_snapshots_entity_id", "entity_state_snapshots", ["entity_id"])

    op.create_table(
        "siem_deliveries",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("source_type", sa.String(length=30), nullable=False),
        sa.Column("source_id", sa.String(length=255), nullable=False),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="pending"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("source_type", "source_id", name="uq_siem_delivery_source"),
    )
    for column in ("source_type", "source_id", "status", "next_attempt_at", "created_at"):
        op.create_index(f"ix_siem_deliveries_{column}", "siem_deliveries", [column])

    op.add_column("system_settings", sa.Column("siem_enabled", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("system_settings", sa.Column("siem_config", postgresql.JSONB(astext_type=sa.Text()), nullable=True))


def downgrade() -> None:
    op.drop_column("system_settings", "siem_config")
    op.drop_column("system_settings", "siem_enabled")
    op.drop_table("siem_deliveries")
    op.drop_table("entity_state_snapshots")
    op.drop_table("change_events")
