"""add Puppet node and fact inventory

Revision ID: 019
Revises: 018
Create Date: 2026-09-14
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "019"
down_revision = "018"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "puppet_nodes",
        sa.Column("certname", sa.String(500), nullable=False),
        sa.Column("endpoint_id", sa.UUID(), nullable=True),
        sa.Column("environment", sa.String(255), nullable=True),
        sa.Column("latest_report_status", sa.String(100), nullable=True),
        sa.Column("report_timestamp", sa.DateTime(timezone=True), nullable=True),
        sa.Column("catalog_timestamp", sa.DateTime(timezone=True), nullable=True),
        sa.Column("facts_timestamp", sa.DateTime(timezone=True), nullable=True),
        sa.Column("synced_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["endpoint_id"], ["endpoints.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("certname"),
    )
    op.create_index("ix_puppet_nodes_endpoint_id", "puppet_nodes", ["endpoint_id"])
    op.create_index("ix_puppet_nodes_environment", "puppet_nodes", ["environment"])
    op.create_index("ix_puppet_nodes_latest_report_status", "puppet_nodes", ["latest_report_status"])
    op.create_index("ix_puppet_nodes_synced_at", "puppet_nodes", ["synced_at"])

    op.create_table(
        "puppet_facts",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("certname", sa.String(500), nullable=False),
        sa.Column("name", sa.String(500), nullable=False),
        sa.Column("value", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("environment", sa.String(255), nullable=True),
        sa.Column("synced_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["certname"], ["puppet_nodes.certname"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("certname", "name", name="uq_puppet_fact_certname_name"),
    )
    op.create_index("ix_puppet_facts_certname", "puppet_facts", ["certname"])
    op.create_index("ix_puppet_facts_name", "puppet_facts", ["name"])
    op.create_index("ix_puppet_facts_environment", "puppet_facts", ["environment"])
    op.create_index("ix_puppet_facts_synced_at", "puppet_facts", ["synced_at"])
    op.create_index("ix_puppet_facts_name_certname", "puppet_facts", ["name", "certname"])


def downgrade() -> None:
    op.drop_table("puppet_facts")
    op.drop_table("puppet_nodes")
