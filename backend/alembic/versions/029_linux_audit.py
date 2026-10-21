"""add Linux audit reports and feature switch

Revision ID: 029
Revises: 028
Create Date: 2026-10-21
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "029"
down_revision = "028"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "system_settings",
        sa.Column("linux_audit_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.create_table(
        "linux_audit_reports",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("schema_version", sa.String(20)),
        sa.Column("hostname", sa.String(255), nullable=False),
        sa.Column("fqdn", sa.String(255)),
        sa.Column("ip_address", sa.String(45)),
        sa.Column("ip_addresses", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("endpoint_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("endpoints.id", ondelete="SET NULL")),
        sa.Column("os_name", sa.String(255)),
        sa.Column("kernel", sa.String(255)),
        sa.Column("architecture", sa.String(100)),
        sa.Column("virtualization_type", sa.String(100)),
        sa.Column("machine_id_hash", sa.String(64)),
        sa.Column("profile", sa.String(100)),
        sa.Column("benchmark_name", sa.String(255), nullable=False),
        sa.Column("benchmark_version", sa.String(100)),
        sa.Column("audit_tool_version", sa.String(100)),
        sa.Column("audit_tool_git_commit", sa.String(64)),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("total_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("pass_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("fail_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("review_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("excluded_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("filename", sa.String(500), nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("report_data", postgresql.JSONB(), nullable=False),
        sa.Column("uploaded_by_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("auth_users.id", ondelete="SET NULL")),
        sa.Column("uploaded_by_email", sa.String(255), nullable=False),
        sa.Column("uploaded_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("content_hash", name="uq_linux_audit_reports_content_hash"),
    )
    for column in ("hostname", "fqdn", "ip_address", "endpoint_id", "machine_id_hash", "profile", "generated_at", "uploaded_by_id", "uploaded_at"):
        op.create_index(f"ix_linux_audit_reports_{column}", "linux_audit_reports", [column])
    op.create_index(
        "ix_linux_audit_reports_host_generated",
        "linux_audit_reports",
        ["hostname", "generated_at"],
    )


def downgrade() -> None:
    op.drop_table("linux_audit_reports")
    op.drop_column("system_settings", "linux_audit_enabled")
