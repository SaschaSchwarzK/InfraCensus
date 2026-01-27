"""Add scheduling intelligence fields.

Revision ID: 0018_job_scheduling_intelligence
Revises: 0017_remove_legacy_scan_tables
Create Date: 2026-01-27
"""

from alembic import op
import sqlalchemy as sa

revision = "0018_job_scheduling_intelligence"
down_revision = "0017_remove_legacy_scan_tables"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "collector_affinities",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("collector_id", sa.Integer(), nullable=False),
        sa.Column("network_id", sa.Integer(), nullable=True),
        sa.Column("subnet_cidr", sa.String(length=64), nullable=True),
        sa.Column("scan_type", sa.String(length=100), nullable=True),
        sa.Column("priority", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.ForeignKeyConstraint(["collector_id"], ["collectors.id"]),
        sa.ForeignKeyConstraint(["network_id"], ["networks.id"]),
    )
    with op.batch_alter_table("scan_schedule_types") as batch:
        batch.add_column(sa.Column("priority", sa.Integer(), nullable=False, server_default="0"))
        batch.add_column(sa.Column("assigned_collector_id", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("assigned_at_utc", sa.DateTime(timezone=True), nullable=True))
        batch.create_foreign_key(
            "fk_scan_schedule_types_assigned_collector",
            "collectors",
            ["assigned_collector_id"],
            ["id"],
        )


def downgrade() -> None:
    with op.batch_alter_table("scan_schedule_types") as batch:
        batch.drop_constraint("fk_scan_schedule_types_assigned_collector", type_="foreignkey")
        batch.drop_column("assigned_at_utc")
        batch.drop_column("assigned_collector_id")
        batch.drop_column("priority")
    op.drop_table("collector_affinities")
