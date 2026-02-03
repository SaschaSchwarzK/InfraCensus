"""add tenant settings

Revision ID: 0006_tenant_settings
Revises: 0005_user_password_hash
Create Date: 2024-01-06 00:00:00.000000

"""

import sqlalchemy as sa

from alembic import op

revision = "0006_tenant_settings"
down_revision = "0005_user_password_hash"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("tenants", sa.Column("description", sa.Text(), nullable=True))
    op.add_column(
        "tenants", sa.Column("default_scanner", sa.String(length=120), nullable=True)
    )
    op.add_column(
        "tenants",
        sa.Column("default_scan_interval_minutes", sa.Integer(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("tenants", "default_scan_interval_minutes")
    op.drop_column("tenants", "default_scanner")
    op.drop_column("tenants", "description")
