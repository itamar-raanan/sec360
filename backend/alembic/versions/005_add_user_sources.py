"""add job_title phone sources to users

Revision ID: 005
Revises: 004
Create Date: 2026-05-04
"""
from alembic import op
import sqlalchemy as sa

revision = '005'
down_revision = '004'
branch_labels = None
depends_on = None

def upgrade():
    op.add_column('users', sa.Column('job_title', sa.String(255), nullable=True))
    op.add_column('users', sa.Column('phone', sa.String(50), nullable=True))
    op.add_column('users', sa.Column('sources', sa.JSON(), nullable=True))

def downgrade():
    op.drop_column('users', 'sources')
    op.drop_column('users', 'phone')
    op.drop_column('users', 'job_title')
