"""Add network rate limit tracking.

Revision ID: 0019_network_rate_limits
Revises: 0018_job_scheduling_intelligence
Create Date: 2026-01-27
"""

from alembic import op
import sqlalchemy as sa

revision = "0019_network_rate_limits"
down_revision = "0018_job_scheduling_intelligence"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "network_rate_limits",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("network_id", sa.Integer(), nullable=False),
        sa.Column("window_start_at_utc", sa.DateTime(timezone=True), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.ForeignKeyConstraint(["network_id"], ["networks.id"]),
    )


def downgrade() -> None:
    op.drop_table("network_rate_limits")
