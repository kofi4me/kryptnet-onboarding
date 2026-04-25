"""add wifi and risk controls

Revision ID: 7b8d12a0f4e1
Revises: dc40e875d392
Create Date: 2026-04-24 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = "7b8d12a0f4e1"
down_revision = "dc40e875d392"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("client_onboarding", schema=None) as batch_op:
        batch_op.add_column(sa.Column("wifi_aps", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("risk_controls", sa.Text(), nullable=True))


def downgrade():
    with op.batch_alter_table("client_onboarding", schema=None) as batch_op:
        batch_op.drop_column("risk_controls")
        batch_op.drop_column("wifi_aps")
