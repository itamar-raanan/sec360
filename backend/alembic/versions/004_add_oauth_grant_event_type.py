"""add oauth_grant to event_type_enum

Revision ID: 004_add_oauth_grant
Revises: 003_risk_override
Create Date: 2026-05-04
"""
from alembic import op

revision = '004'
down_revision = '003'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # PostgreSQL requires ALTER TYPE to add enum values
    op.execute("ALTER TYPE event_type_enum ADD VALUE IF NOT EXISTS 'oauth_grant'")


def downgrade() -> None:
    # PostgreSQL does not support removing enum values without recreating the type;
    # downgrade is a no-op to avoid data loss
    pass
