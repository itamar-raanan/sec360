"""add personal read-only API keys

Revision ID: 032
Revises: 031
Create Date: 2026-11-04
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "032"
down_revision = "031"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "personal_api_keys",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("auth_users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("key_prefix", sa.String(32), nullable=False),
        sa.Column("key_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_used_at", sa.DateTime(timezone=True)),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("key_prefix", name="uq_personal_api_keys_prefix"),
        sa.UniqueConstraint("key_hash", name="uq_personal_api_keys_hash"),
    )
    for column in ("user_id", "key_prefix", "key_hash", "last_used_at", "expires_at", "revoked_at"):
        op.create_index(f"ix_personal_api_keys_{column}", "personal_api_keys", [column])


def downgrade() -> None:
    op.drop_table("personal_api_keys")
