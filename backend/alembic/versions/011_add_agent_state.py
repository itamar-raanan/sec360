"""add agent_state to security_agents

Revision ID: 011
Revises: 010
Create Date: 2026-05-13
"""
from alembic import op
import sqlalchemy as sa

revision = "011"
down_revision = "010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "security_agents",
        sa.Column("agent_state", sa.String(255), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("security_agents", "agent_state")
