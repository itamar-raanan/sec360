"""add endpoint owner assignment provenance

Revision ID: 034
Revises: 033
Create Date: 2026-11-17
"""

from alembic import op
import sqlalchemy as sa


revision = "034"
down_revision = "033"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("endpoints", sa.Column("owner_assignment_source", sa.String(50)))
    op.add_column("endpoints", sa.Column("owner_assignment_confidence", sa.Float()))
    op.add_column("endpoints", sa.Column("owner_assignment_evidence", sa.String(500)))
    op.add_column("endpoints", sa.Column("owner_assigned_at", sa.DateTime(timezone=True)))
    op.execute(
        "UPDATE endpoints SET owner_assignment_source = 'legacy_unverified', "
        "owner_assignment_confidence = 0.0, "
        "owner_assignment_evidence = "
        "'Assignment predates correlation provenance tracking' "
        "WHERE owner_user_id IS NOT NULL"
    )


def downgrade() -> None:
    op.drop_column("endpoints", "owner_assigned_at")
    op.drop_column("endpoints", "owner_assignment_evidence")
    op.drop_column("endpoints", "owner_assignment_confidence")
    op.drop_column("endpoints", "owner_assignment_source")
