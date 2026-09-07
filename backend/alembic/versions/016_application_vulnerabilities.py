"""add SentinelOne application vulnerability findings

Revision ID: 016
Revises: 015
Create Date: 2026-09-07
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "016"
down_revision = "015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "application_vulnerabilities",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("sentinelone_id", sa.String(100), nullable=False),
        sa.Column("endpoint_id", sa.UUID(), nullable=True),
        sa.Column("sentinelone_endpoint_id", sa.String(100), nullable=True),
        sa.Column("application", sa.String(500), nullable=False),
        sa.Column("application_name", sa.String(255), nullable=False),
        sa.Column("application_vendor", sa.String(500), nullable=True),
        sa.Column("application_version", sa.String(255), nullable=True),
        sa.Column("cve_id", sa.String(50), nullable=False),
        sa.Column("cvss_version", sa.String(20), nullable=True),
        sa.Column("nvd_cvss_version", sa.String(20), nullable=True),
        sa.Column("nvd_base_score", sa.Float(), nullable=True),
        sa.Column("risk_score", sa.Float(), nullable=True),
        sa.Column("severity", sa.String(20), nullable=True),
        sa.Column("endpoint_name", sa.String(255), nullable=False),
        sa.Column("endpoint_type", sa.String(100), nullable=True),
        sa.Column("os_type", sa.String(50), nullable=True),
        sa.Column("days_detected", sa.Integer(), nullable=True),
        sa.Column("detection_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column("published_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_scan_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_scan_result", sa.String(100), nullable=True),
        sa.Column("exploit_code_maturity", sa.String(100), nullable=True),
        sa.Column("remediation_level", sa.String(100), nullable=True),
        sa.Column("report_confidence", sa.String(100), nullable=True),
        sa.Column("mitigation_status", sa.String(100), nullable=True),
        sa.Column("mitigation_status_change_time", sa.DateTime(timezone=True), nullable=True),
        sa.Column("mitigation_status_changed_by", sa.String(255), nullable=True),
        sa.Column("mitigation_status_reason", sa.Text(), nullable=True),
        sa.Column("status", sa.String(100), nullable=True),
        sa.Column("mark_type", sa.String(100), nullable=True),
        sa.Column("marked_by", sa.String(255), nullable=True),
        sa.Column("marked_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("raw_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("synced_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["endpoint_id"], ["endpoints.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("sentinelone_id"),
    )
    for column in ("sentinelone_id", "endpoint_id", "sentinelone_endpoint_id", "application_name", "cve_id", "severity", "endpoint_name", "exploit_code_maturity", "mitigation_status", "status", "synced_at"):
        op.create_index(f"ix_application_vulnerabilities_{column}", "application_vulnerabilities", [column])
    op.create_index("ix_app_vuln_severity_status", "application_vulnerabilities", ["severity", "status"])
    op.create_index("ix_app_vuln_application_endpoint", "application_vulnerabilities", ["application_name", "endpoint_name"])


def downgrade() -> None:
    op.drop_table("application_vulnerabilities")
