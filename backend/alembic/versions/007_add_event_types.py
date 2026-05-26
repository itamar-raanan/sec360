"""add saml, user_account, access_eval to event_type_enum

Revision ID: 007
Revises: 006
Create Date: 2026-05-04
"""
from alembic import op

revision = '007'
down_revision = '006'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TYPE event_type_enum ADD VALUE IF NOT EXISTS 'saml'")
    op.execute("ALTER TYPE event_type_enum ADD VALUE IF NOT EXISTS 'user_account'")
    op.execute("ALTER TYPE event_type_enum ADD VALUE IF NOT EXISTS 'access_eval'")


def downgrade() -> None:
    pass  # PostgreSQL cannot remove enum values without recreating the type
