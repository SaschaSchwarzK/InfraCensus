"""add scan schedules

Revision ID: 0011_scan_schedules
Revises: 0010_sites_networks_scan_results
Create Date: 2024-01-11 00:00:00.000000

"""

import sqlalchemy as sa

from alembic import op

revision = "0011_scan_schedules"
down_revision = "0010_sites_networks_scan_results"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scan_schedules",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False
        ),
        sa.Column("site_id", sa.Integer(), sa.ForeignKey("sites.id"), nullable=True),
        sa.Column("name", sa.String(length=200), nullable=True),
        sa.Column("start_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("network_ids", sa.Text(), nullable=True),
        sa.Column("scan_types", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("scan_schedules")
