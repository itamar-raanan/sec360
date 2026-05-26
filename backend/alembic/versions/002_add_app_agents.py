"""Add GlobalProtect and Symantec WSS app tracking

Revision ID: 002
Revises: 001
Create Date: 2026-04-29

"""
from alembic import op
import sqlalchemy as sa

revision = "002"
down_revision = "001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Extend agent_product_enum with new app types
    op.execute("ALTER TYPE agent_product_enum ADD VALUE IF NOT EXISTS 'globalprotect'")
    op.execute("ALTER TYPE agent_product_enum ADD VALUE IF NOT EXISTS 'symantec_wss'")

    # Add GP/WSS compliance columns
    op.add_column("compliance_statuses", sa.Column("gp_installed", sa.Boolean(), nullable=False, server_default="false"))
    op.add_column("compliance_statuses", sa.Column("gp_version_ok", sa.Boolean(), nullable=False, server_default="false"))
    op.add_column("compliance_statuses", sa.Column("wss_installed", sa.Boolean(), nullable=False, server_default="false"))
    op.add_column("compliance_statuses", sa.Column("wss_version_ok", sa.Boolean(), nullable=False, server_default="false"))

    # Add min-version thresholds for GP and WSS in system_settings
    op.add_column("system_settings", sa.Column("min_gp_version", sa.String(50), nullable=False, server_default=""))
    op.add_column("system_settings", sa.Column("min_wss_version", sa.String(50), nullable=False, server_default=""))


def downgrade() -> None:
    op.drop_column("system_settings", "min_wss_version")
    op.drop_column("system_settings", "min_gp_version")
    op.drop_column("compliance_statuses", "wss_version_ok")
    op.drop_column("compliance_statuses", "wss_installed")
    op.drop_column("compliance_statuses", "gp_version_ok")
    op.drop_column("compliance_statuses", "gp_installed")
    # Note: PostgreSQL does not support removing enum values without recreating the type
