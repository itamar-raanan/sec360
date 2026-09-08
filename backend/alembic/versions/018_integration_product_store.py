"""retire HiBob and CloudSOC integration data

Revision ID: 018
Revises: 017
Create Date: 2026-09-08
"""

from alembic import op


revision = "018"
down_revision = "017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "DELETE FROM integration_configs "
        "WHERE integration_type IN ('hibob', 'cloudsoc')"
    )
    op.execute("UPDATE users SET sources = sources - 'hibob' WHERE sources ? 'hibob'")
    op.execute("DELETE FROM activity_events WHERE details->>'app' = 'cloudsoc'")


def downgrade() -> None:
    # Product credentials and source events cannot be reconstructed safely.
    pass
