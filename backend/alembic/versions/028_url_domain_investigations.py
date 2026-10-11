"""add URL and domain investigations

Revision ID: 028
Revises: 027
Create Date: 2026-10-11
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "028"
down_revision = "027"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "url_investigations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("indicator_data", sa.JSON(), nullable=False),
        sa.Column("indicator_hash", sa.String(64), nullable=False),
        sa.Column("indicator_preview", sa.String(1000), nullable=False),
        sa.Column("indicator_type", sa.String(20), nullable=False),
        sa.Column("hostname", sa.String(253), nullable=False),
        sa.Column("registrable_domain", sa.String(253), nullable=False),
        sa.Column("status", sa.String(30), nullable=False, server_default="queued"),
        sa.Column("is_sensitive", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("sensitive_reasons", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("options", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("requested_by_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("auth_users.id", ondelete="SET NULL")),
        sa.Column("requested_by_email", sa.String(255), nullable=False),
        sa.Column("risk_score", sa.Integer()),
        sa.Column("risk_level", sa.String(30), nullable=False, server_default="unknown"),
        sa.Column("evidence_confidence", sa.String(20), nullable=False, server_default="low"),
        sa.Column("coverage", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("reasons", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("provider_contributions", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("scoring_version", sa.String(50), nullable=False, server_default="url-risk-v1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
    )
    for column in ("indicator_hash", "hostname", "status", "created_at"):
        op.create_index(f"ix_url_investigations_{column}", "url_investigations", [column])
    op.create_index(
        "uq_url_investigations_active_hash",
        "url_investigations",
        ["indicator_hash"],
        unique=True,
        postgresql_where=sa.text("status IN ('queued', 'running')"),
    )

    op.create_table(
        "url_investigation_provider_results",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("investigation_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("url_investigations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("provider", sa.String(60), nullable=False),
        sa.Column("operation", sa.String(30), nullable=False, server_default="lookup"),
        sa.Column("queried_scope", sa.String(30), nullable=False),
        sa.Column("queried_indicator_preview", sa.String(1000), nullable=False),
        sa.Column("status", sa.String(30), nullable=False, server_default="queued"),
        sa.Column("native_verdict", sa.String(100)),
        sa.Column("native_metrics", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("assessment", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("findings", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("evidence", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("report_url", sa.String(2000)),
        sa.Column("observed_at", sa.DateTime(timezone=True)),
        sa.Column("fetched_at", sa.DateTime(timezone=True)),
        sa.Column("cache_status", sa.String(30), nullable=False, server_default="live"),
        sa.Column("error_code", sa.String(80)),
        sa.Column("error_message", sa.Text()),
        sa.Column("raw_response", sa.JSON()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("investigation_id", "provider", "operation", name="uq_url_investigation_provider_operation"),
    )
    for column in ("investigation_id", "provider", "status"):
        op.create_index(f"ix_url_investigation_provider_results_{column}", "url_investigation_provider_results", [column])

    op.create_table(
        "url_investigation_artifacts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("investigation_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("url_investigations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("provider", sa.String(60), nullable=False),
        sa.Column("artifact_type", sa.String(30), nullable=False, server_default="screenshot"),
        sa.Column("content_type", sa.String(100), nullable=False),
        sa.Column("content", sa.LargeBinary(), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("target_data", sa.JSON(), nullable=False),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_url_investigation_artifacts_investigation_id", "url_investigation_artifacts", ["investigation_id"])


def downgrade() -> None:
    op.drop_table("url_investigation_artifacts")
    op.drop_table("url_investigation_provider_results")
    op.drop_table("url_investigations")
