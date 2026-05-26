"""add cloud_access to event_type_enum

Revision ID: 008
Revises: 007
Create Date: 2026-05-04
"""
from alembic import op

revision = '008'
down_revision = '007'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TYPE event_type_enum ADD VALUE IF NOT EXISTS 'cloud_access'")


def downgrade() -> None:
    pass  # PostgreSQL cannot remove enum values without recreating the type
