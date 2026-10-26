"""add Symantec Management Center proxy policy audit

Revision ID: 031
Revises: 030
Create Date: 2026-10-26
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "031"
down_revision = "030"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "system_settings",
        sa.Column("proxy_audit_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.create_table(
        "proxy_audit_connections",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("config", sa.JSON()),
        sa.Column("status", sa.String(24), nullable=False, server_default="unconfigured"),
        sa.Column("last_tested_at", sa.DateTime(timezone=True)),
        sa.Column("last_sync", sa.DateTime(timezone=True)),
        sa.Column("last_error", sa.Text()),
        sa.Column("records_synced", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("sync_in_progress", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_proxy_audit_connections_status", "proxy_audit_connections", ["status"])
    op.create_index("ix_proxy_audit_connections_last_sync", "proxy_audit_connections", ["last_sync"])
    op.create_table(
        "proxy_audit_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("policy_uuid", sa.String(255), nullable=False),
        sa.Column("policy_name", sa.String(500), nullable=False),
        sa.Column("object_type", sa.String(24), nullable=False),
        sa.Column("author", sa.String(255)),
        sa.Column("revision_date", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revision_number", sa.String(100), nullable=False),
        sa.Column("comment", sa.Text()),
        sa.Column("change_summary", sa.Text(), nullable=False),
        sa.Column("diff_text", sa.Text(), nullable=False, server_default=""),
        sa.Column("additions", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("deletions", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("synced_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("policy_uuid", "revision_number", name="uq_proxy_audit_policy_revision"),
    )
    for column in ("policy_uuid", "policy_name", "object_type", "author", "revision_date", "synced_at"):
        op.create_index(f"ix_proxy_audit_events_{column}", "proxy_audit_events", [column])
    op.create_index(
        "ix_proxy_audit_policy_date",
        "proxy_audit_events",
        ["policy_uuid", "revision_date"],
    )


def downgrade() -> None:
    op.drop_table("proxy_audit_events")
    op.drop_table("proxy_audit_connections")
    op.drop_column("system_settings", "proxy_audit_enabled")
