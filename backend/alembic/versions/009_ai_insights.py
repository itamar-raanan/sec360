"""create ai_insights table

Revision ID: 009_ai_insights
Revises: 008_add_cloud_access_event_type
Create Date: 2026-05-04
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB

revision = "009"
down_revision = "008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ai_insights",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("insight_type", sa.VARCHAR(50), nullable=False),
        sa.Column("severity", sa.VARCHAR(20), nullable=False),
        sa.Column("title", sa.TEXT, nullable=False),
        sa.Column("description", sa.TEXT, nullable=False),
        sa.Column(
            "user_id",
            UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("evidence", JSONB, nullable=True),
        sa.Column("event_ids", JSONB, nullable=True),
        sa.Column("is_dismissed", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("is_new", sa.Boolean, nullable=False, server_default=sa.text("true")),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("expires_at", sa.TIMESTAMP(timezone=True), nullable=True),
    )

    op.create_index("ix_ai_insights_insight_type", "ai_insights", ["insight_type"])
    op.create_index("ix_ai_insights_severity", "ai_insights", ["severity"])
    op.create_index("ix_ai_insights_user_id", "ai_insights", ["user_id"])
    op.create_index("ix_ai_insights_created_at", "ai_insights", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_ai_insights_created_at", table_name="ai_insights")
    op.drop_index("ix_ai_insights_user_id", table_name="ai_insights")
    op.drop_index("ix_ai_insights_severity", table_name="ai_insights")
    op.drop_index("ix_ai_insights_insight_type", table_name="ai_insights")
    op.drop_table("ai_insights")
