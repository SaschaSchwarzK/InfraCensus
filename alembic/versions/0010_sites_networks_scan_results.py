"""add sites, networks, and scan result versions

Revision ID: 0010_sites_networks_scan_results
Revises: 0009_tenant_user_roles
Create Date: 2024-01-10 00:00:00.000000

"""

import sqlalchemy as sa

from alembic import op

revision = "0010_sites_networks_scan_results"
down_revision = "0009_tenant_user_roles"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "sites",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False
        ),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("code", sa.String(length=50), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "networks",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False
        ),
        sa.Column("site_id", sa.Integer(), sa.ForeignKey("sites.id"), nullable=True),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("cidr", sa.String(length=64), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "scan_results",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False
        ),
        sa.Column(
            "scan_job_id", sa.Integer(), sa.ForeignKey("scan_jobs.id"), nullable=True
        ),
        sa.Column("label", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "scan_result_versions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "scan_result_id",
            sa.Integer(),
            sa.ForeignKey("scan_results.id"),
            nullable=False,
        ),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("payload", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("scan_result_versions")
    op.drop_table("scan_results")
    op.drop_table("networks")
    op.drop_table("sites")
