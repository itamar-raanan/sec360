"""add console_ip to endpoints

Revision ID: 013
Revises: 012
Create Date: 2026-05-13
"""
from alembic import op
import sqlalchemy as sa

revision = "013"
down_revision = "012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "endpoints",
        sa.Column("console_ip", sa.String(45), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("endpoints", "console_ip")
