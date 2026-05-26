"""Add risk score override to endpoints

Revision ID: 003
Revises: 002
Create Date: 2026-05-02
"""
from alembic import op
import sqlalchemy as sa

revision = "003"
down_revision = "002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("endpoints", sa.Column("risk_score_override", sa.Float(), nullable=True))
    op.add_column("endpoints", sa.Column("risk_score_note", sa.String(500), nullable=True))


def downgrade() -> None:
    op.drop_column("endpoints", "risk_score_note")
    op.drop_column("endpoints", "risk_score_override")
