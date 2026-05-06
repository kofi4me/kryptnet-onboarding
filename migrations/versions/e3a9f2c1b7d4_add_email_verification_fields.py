"""add email verification fields

Revision ID: e3a9f2c1b7d4
Revises: 7b8d12a0f4e1
Create Date: 2026-05-05 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = "e3a9f2c1b7d4"
down_revision = "7b8d12a0f4e1"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("client_onboarding", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "verification_status",
                sa.String(length=50),
                nullable=False,
                server_default="Verified",
            )
        )
        batch_op.add_column(sa.Column("verification_token", sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column("verification_sent_at", sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column("verified_at", sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column("suspicious_reason", sa.String(length=250), nullable=True))
        batch_op.add_column(sa.Column("submitter_ip", sa.String(length=100), nullable=True))
        batch_op.create_unique_constraint(
            "uq_client_onboarding_verification_token",
            ["verification_token"],
        )


def downgrade():
    with op.batch_alter_table("client_onboarding", schema=None) as batch_op:
        batch_op.drop_constraint(
            "uq_client_onboarding_verification_token",
            type_="unique",
        )
        batch_op.drop_column("submitter_ip")
        batch_op.drop_column("suspicious_reason")
        batch_op.drop_column("verified_at")
        batch_op.drop_column("verification_sent_at")
        batch_op.drop_column("verification_token")
        batch_op.drop_column("verification_status")
