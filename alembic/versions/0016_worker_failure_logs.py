"""worker failure logs

Revision ID: 0016_worker_failure_logs
Revises: 0015_inventory_snapshots
Create Date: 2026-01-21 00:00:00.000000
"""

import sqlalchemy as sa

from alembic import op

revision = "0016_worker_failure_logs"
down_revision = "0015_inventory_snapshots"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "task_failure_logs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("task_id", sa.String(length=64), nullable=True),
        sa.Column("task_name", sa.String(length=200), nullable=False),
        sa.Column("exception", sa.Text(), nullable=True),
        sa.Column("traceback", sa.Text(), nullable=True),
        sa.Column("args", sa.Text(), nullable=True),
        sa.Column("kwargs", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "permanent_failures",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("task_id", sa.String(length=64), nullable=True),
        sa.Column("task_name", sa.String(length=200), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("args", sa.Text(), nullable=True),
        sa.Column("kwargs", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("permanent_failures")
    op.drop_table("task_failure_logs")
