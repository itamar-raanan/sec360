"""convert sources column from JSON to JSONB

Revision ID: 006
Revises: 005
Create Date: 2026-05-04
"""
from alembic import op

revision = '006'
down_revision = '005'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE users ALTER COLUMN sources TYPE JSONB USING sources::jsonb"
    )


def downgrade() -> None:
    op.execute(
        "ALTER TABLE users ALTER COLUMN sources TYPE JSON USING sources::json"
    )
