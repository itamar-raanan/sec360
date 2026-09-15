"""add RADIUS authentication settings

Revision ID: 021
Revises: 020
Create Date: 2026-09-15
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "021"
down_revision = "020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "system_settings",
        sa.Column("radius_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "system_settings",
        sa.Column("radius_config", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("system_settings", "radius_config")
    op.drop_column("system_settings", "radius_enabled")
