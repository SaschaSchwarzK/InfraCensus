"""remove legacy scan tables

Revision ID: 0017_remove_legacy_scan_tables
Revises: 0016_worker_failure_logs
Create Date: 2026-01-21 00:00:00.000000
"""
from alembic import op

revision = "0017_remove_legacy_scan_tables"
down_revision = "0016_worker_failure_logs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_table("scan_result_versions")
    op.drop_table("scan_results")
    op.drop_table("devices")
    op.drop_table("scan_jobs")


def downgrade() -> None:
    pass
