"""add schedule timing fields and per-type entries

Revision ID: 0012_scan_schedule_times
Revises: 0011_scan_schedules
Create Date: 2024-01-12 00:00:00.000000

"""

import sqlalchemy as sa

from alembic import op

revision = "0012_scan_schedule_times"
down_revision = "0011_scan_schedules"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("scan_schedules") as batch:
        batch.add_column(
            sa.Column("planned_start_at", sa.DateTime(timezone=True), nullable=True)
        )
        batch.add_column(
            sa.Column("actual_start_at", sa.DateTime(timezone=True), nullable=True)
        )
        batch.add_column(
            sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True)
        )
    op.execute(
        "UPDATE scan_schedules SET planned_start_at = start_at WHERE planned_start_at IS NULL"
    )
    with op.batch_alter_table("scan_schedules") as batch:
        batch.drop_column("start_at")
        batch.alter_column("planned_start_at", nullable=False)

    op.create_table(
        "scan_schedule_types",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "schedule_id",
            sa.Integer(),
            sa.ForeignKey("scan_schedules.id"),
            nullable=False,
        ),
        sa.Column("scan_type", sa.String(length=100), nullable=False),
        sa.Column("planned_start_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actual_start_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("scan_schedule_types")
    with op.batch_alter_table("scan_schedules") as batch:
        batch.add_column(
            sa.Column("start_at", sa.DateTime(timezone=True), nullable=True)
        )
    op.execute(
        "UPDATE scan_schedules SET start_at = planned_start_at WHERE start_at IS NULL"
    )
    with op.batch_alter_table("scan_schedules") as batch:
        batch.drop_column("planned_start_at")
        batch.drop_column("actual_start_at")
        batch.drop_column("finished_at")
        batch.alter_column("start_at", nullable=False)
