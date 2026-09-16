"""add per-user authentication methods

Revision ID: 024
Revises: 023
Create Date: 2026-09-16
"""

from alembic import op
import sqlalchemy as sa


revision = "024"
down_revision = "023"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "auth_users",
        sa.Column(
            "auth_method",
            sa.String(length=20),
            nullable=False,
            server_default="local",
        ),
    )
    op.execute(sa.text("""
        UPDATE auth_users
        SET auth_method = 'sso'
        WHERE saml_subject IS NOT NULL AND saml_subject <> ''
    """))
    op.create_check_constraint(
        "ck_auth_users_auth_method",
        "auth_users",
        "auth_method IN ('local', 'sso', 'radius')",
    )


def downgrade() -> None:
    op.drop_constraint("ck_auth_users_auth_method", "auth_users", type_="check")
    op.drop_column("auth_users", "auth_method")
