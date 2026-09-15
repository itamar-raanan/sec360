"""backfill compliance agent presence

Revision ID: 023
Revises: 022
Create Date: 2026-09-15
"""

from alembic import op
import sqlalchemy as sa


revision = "023"
down_revision = "022"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Existing installations already have accurate fixed-product booleans and
    # Puppet node links. Seed the generic map so coverage works immediately
    # after deployment, before the next scheduled evaluation.
    op.execute(sa.text("""
        UPDATE compliance_statuses cs
        SET agent_presence = jsonb_build_object(
            'sentinelone', COALESCE(cs.edr_installed, FALSE),
            'symantec_dlp', COALESCE(cs.dlp_installed, FALSE),
            'symantec_wss', COALESCE(cs.wss_installed, FALSE),
            'puppet', EXISTS (
                SELECT 1 FROM puppet_nodes pn WHERE pn.endpoint_id = cs.endpoint_id
            )
        )
    """))


def downgrade() -> None:
    # The values remain valid cached posture data if the migration is rolled
    # back, so no destructive downgrade is necessary.
    pass
