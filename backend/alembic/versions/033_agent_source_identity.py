"""add stable product source identity to security agents

Revision ID: 033
Revises: 032
Create Date: 2026-11-17
"""

from alembic import op
import sqlalchemy as sa


revision = "033"
down_revision = "032"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "security_agents",
        sa.Column("source_id", sa.String(length=255), nullable=True),
    )
    op.create_index(
        "uq_security_agents_product_source_id",
        "security_agents",
        ["product_name", "source_id"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index(
        "uq_security_agents_product_source_id",
        table_name="security_agents",
    )
    op.drop_column("security_agents", "source_id")
