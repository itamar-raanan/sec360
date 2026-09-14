"""add Puppet fact filters, favourites, and saved views

Revision ID: 020
Revises: 019
Create Date: 2026-09-14
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "020"
down_revision = "019"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("puppet_facts", sa.Column("value_type", sa.String(20), nullable=True))
    op.execute("UPDATE puppet_facts SET value_type = COALESCE(jsonb_typeof(value), 'null')")
    op.alter_column(
        "puppet_facts", "value_type", nullable=False, server_default=sa.text("'string'")
    )
    op.create_index("ix_puppet_facts_value_type", "puppet_facts", ["value_type"])

    op.create_table(
        "puppet_fact_favorites",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("fact_name", sa.String(500), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["auth_users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", "fact_name", name="uq_puppet_fact_favorite_user_name"),
    )
    op.create_index("ix_puppet_fact_favorites_user_id", "puppet_fact_favorites", ["user_id"])
    op.create_index("ix_puppet_fact_favorites_fact_name", "puppet_fact_favorites", ["fact_name"])

    op.create_table(
        "puppet_fact_saved_views",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("definition", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("is_default", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["auth_users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", "name", name="uq_puppet_fact_saved_view_user_name"),
    )
    op.create_index("ix_puppet_fact_saved_views_user_id", "puppet_fact_saved_views", ["user_id"])


def downgrade() -> None:
    op.drop_table("puppet_fact_saved_views")
    op.drop_table("puppet_fact_favorites")
    op.drop_index("ix_puppet_facts_value_type", table_name="puppet_facts")
    op.drop_column("puppet_facts", "value_type")
