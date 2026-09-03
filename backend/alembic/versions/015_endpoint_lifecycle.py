"""add endpoint lifecycle review fields

Revision ID: 015
Revises: 014
Create Date: 2026-09-03
"""

from alembic import op
import sqlalchemy as sa


revision = "015"
down_revision = "014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "endpoints",
        sa.Column("lifecycle_state", sa.String(32), nullable=False, server_default="active"),
    )
    op.add_column("endpoints", sa.Column("lifecycle_reason", sa.Text(), nullable=True))
    op.add_column("endpoints", sa.Column("lifecycle_changed_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("endpoints", sa.Column("lifecycle_changed_by", sa.String(255), nullable=True))
    op.execute(
        "UPDATE endpoints SET lifecycle_state = 'stale' "
        "WHERE is_active = FALSE AND lifecycle_state = 'active'"
    )
    op.create_index("ix_endpoints_lifecycle_state", "endpoints", ["lifecycle_state"])


def downgrade() -> None:
    op.drop_index("ix_endpoints_lifecycle_state", table_name="endpoints")
    op.drop_column("endpoints", "lifecycle_changed_by")
    op.drop_column("endpoints", "lifecycle_changed_at")
    op.drop_column("endpoints", "lifecycle_reason")
    op.drop_column("endpoints", "lifecycle_state")
