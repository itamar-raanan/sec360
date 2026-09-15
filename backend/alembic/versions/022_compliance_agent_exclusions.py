"""add dynamic compliance agents and exclusions

Revision ID: 022
Revises: 021
Create Date: 2026-09-15
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "022"
down_revision = "021"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "compliance_statuses",
        sa.Column(
            "agent_presence",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )
    op.create_table(
        "compliance_exclusions",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("endpoint_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("agent_key", sa.String(length=64), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["endpoint_id"], ["endpoints.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("endpoint_id", "agent_key", name="uq_compliance_exclusion_endpoint_agent"),
    )
    op.create_index("ix_compliance_exclusions_endpoint_id", "compliance_exclusions", ["endpoint_id"])
    op.create_index("ix_compliance_exclusions_agent_key", "compliance_exclusions", ["agent_key"])


def downgrade() -> None:
    op.drop_index("ix_compliance_exclusions_agent_key", table_name="compliance_exclusions")
    op.drop_index("ix_compliance_exclusions_endpoint_id", table_name="compliance_exclusions")
    op.drop_table("compliance_exclusions")
    op.drop_column("compliance_statuses", "agent_presence")
