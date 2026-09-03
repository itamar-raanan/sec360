"""remove GlobalProtect product support

Revision ID: 014
Revises: 013
Create Date: 2026-09-03

Existing GlobalProtect agent and insight rows are intentionally deleted and
cannot be reconstructed by the downgrade.
"""

from alembic import op
import sqlalchemy as sa


revision = "014"
down_revision = "013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("DELETE FROM ai_insights WHERE insight_type = 'endpoints_missing_vpn'")
    op.execute("DELETE FROM security_agents WHERE product_name::text = 'globalprotect'")

    op.drop_column("compliance_statuses", "gp_version_ok")
    op.drop_column("compliance_statuses", "gp_installed")
    op.drop_column("system_settings", "min_gp_version")

    op.execute("ALTER TYPE agent_product_enum RENAME TO agent_product_enum_with_globalprotect")
    op.execute(
        "CREATE TYPE agent_product_enum AS ENUM "
        "('sentinelone', 'symantec', 'prisma', 'symantec_wss', 'other')"
    )
    op.execute(
        "ALTER TABLE security_agents "
        "ALTER COLUMN product_name TYPE agent_product_enum "
        "USING product_name::text::agent_product_enum"
    )
    op.execute("DROP TYPE agent_product_enum_with_globalprotect")


def downgrade() -> None:
    op.execute("ALTER TYPE agent_product_enum ADD VALUE IF NOT EXISTS 'globalprotect'")
    op.add_column(
        "system_settings",
        sa.Column("min_gp_version", sa.String(50), nullable=False, server_default=""),
    )
    op.add_column(
        "compliance_statuses",
        sa.Column("gp_installed", sa.Boolean(), nullable=False, server_default="false"),
    )
    op.add_column(
        "compliance_statuses",
        sa.Column("gp_version_ok", sa.Boolean(), nullable=False, server_default="false"),
    )
