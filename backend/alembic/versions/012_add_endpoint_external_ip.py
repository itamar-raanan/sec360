"""add external_ip to endpoints

Revision ID: 012
Revises: 011
Create Date: 2026-05-13
"""
from alembic import op
import sqlalchemy as sa

revision = "012"
down_revision = "011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "endpoints",
        sa.Column("external_ip", sa.String(45), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("endpoints", "external_ip")
