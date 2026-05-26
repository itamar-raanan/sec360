"""add is_active to endpoints

Revision ID: 010_add_endpoint_is_active
Revises: 009_ai_insights
Create Date: 2026-05-05
"""
from alembic import op
import sqlalchemy as sa

revision = "010"
down_revision = "009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "endpoints",
        sa.Column(
            "is_active",
            sa.Boolean,
            nullable=False,
            server_default=sa.text("true"),
        ),
    )
    op.create_index("ix_endpoints_is_active", "endpoints", ["is_active"])


def downgrade() -> None:
    op.drop_index("ix_endpoints_is_active", table_name="endpoints")
    op.drop_column("endpoints", "is_active")
