"""add site timezone and UTC schedule fields

Revision ID: 0014_site_timezone_and_schedule_utc
Revises: 0013_collectors_enrollment_certs
Create Date: 2024-01-14 00:00:00.000000

"""

import sqlalchemy as sa

from alembic import op

revision = "0014_site_timezone_and_schedule_utc"
down_revision = "0013_collectors_enrollment_certs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("sites") as batch:
        batch.add_column(sa.Column("timezone", sa.String(length=120), nullable=True))
    op.execute("UPDATE sites SET timezone = 'UTC' WHERE timezone IS NULL")
    with op.batch_alter_table("sites") as batch:
        batch.alter_column("timezone", nullable=False)

    with op.batch_alter_table("collectors") as batch:
        batch.add_column(
            sa.Column("last_seen_utc", sa.DateTime(timezone=True), nullable=True)
        )
        batch.add_column(sa.Column("clock_skew_seconds", sa.Integer(), nullable=True))

    with op.batch_alter_table("scan_schedules") as batch:
        batch.add_column(
            sa.Column("scheduled_at_utc", sa.DateTime(timezone=True), nullable=True)
        )
        batch.add_column(
            sa.Column("not_before_utc", sa.DateTime(timezone=True), nullable=True)
        )
        batch.add_column(
            sa.Column("not_after_utc", sa.DateTime(timezone=True), nullable=True)
        )
        batch.add_column(
            sa.Column("actual_start_at_utc", sa.DateTime(timezone=True), nullable=True)
        )
        batch.add_column(
            sa.Column("finished_at_utc", sa.DateTime(timezone=True), nullable=True)
        )
    op.execute(
        "UPDATE scan_schedules SET scheduled_at_utc = planned_start_at WHERE scheduled_at_utc IS NULL"
    )
    with op.batch_alter_table("scan_schedules") as batch:
        batch.alter_column("scheduled_at_utc", nullable=False)
        batch.drop_column("planned_start_at")
        batch.drop_column("actual_start_at")
        batch.drop_column("finished_at")

    with op.batch_alter_table("scan_schedule_types") as batch:
        batch.add_column(
            sa.Column("scheduled_at_utc", sa.DateTime(timezone=True), nullable=True)
        )
        batch.add_column(
            sa.Column("not_before_utc", sa.DateTime(timezone=True), nullable=True)
        )
        batch.add_column(
            sa.Column("not_after_utc", sa.DateTime(timezone=True), nullable=True)
        )
        batch.add_column(
            sa.Column("actual_start_at_utc", sa.DateTime(timezone=True), nullable=True)
        )
        batch.add_column(
            sa.Column("finished_at_utc", sa.DateTime(timezone=True), nullable=True)
        )
    op.execute(
        "UPDATE scan_schedule_types SET scheduled_at_utc = planned_start_at WHERE scheduled_at_utc IS NULL"
    )
    with op.batch_alter_table("scan_schedule_types") as batch:
        batch.alter_column("scheduled_at_utc", nullable=False)
        batch.drop_column("planned_start_at")
        batch.drop_column("actual_start_at")
        batch.drop_column("finished_at")


def downgrade() -> None:
    with op.batch_alter_table("scan_schedule_types") as batch:
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
        "UPDATE scan_schedule_types SET planned_start_at = scheduled_at_utc WHERE planned_start_at IS NULL"
    )
    with op.batch_alter_table("scan_schedule_types") as batch:
        batch.drop_column("scheduled_at_utc")
        batch.drop_column("not_before_utc")
        batch.drop_column("not_after_utc")
        batch.drop_column("actual_start_at_utc")
        batch.drop_column("finished_at_utc")
        batch.alter_column("planned_start_at", nullable=False)

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
        "UPDATE scan_schedules SET planned_start_at = scheduled_at_utc WHERE planned_start_at IS NULL"
    )
    with op.batch_alter_table("scan_schedules") as batch:
        batch.drop_column("scheduled_at_utc")
        batch.drop_column("not_before_utc")
        batch.drop_column("not_after_utc")
        batch.drop_column("actual_start_at_utc")
        batch.drop_column("finished_at_utc")
        batch.alter_column("planned_start_at", nullable=False)

    with op.batch_alter_table("collectors") as batch:
        batch.drop_column("clock_skew_seconds")
        batch.drop_column("last_seen_utc")

    with op.batch_alter_table("sites") as batch:
        batch.drop_column("timezone")
