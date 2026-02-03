"""add device hardware fields

Revision ID: 0002_device_hardware_fields
Revises: 0001_initial
Create Date: 2024-01-02 00:00:00.000000

"""

import sqlalchemy as sa

from alembic import op

revision = "0002_device_hardware_fields"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "devices", sa.Column("manufacturer", sa.String(length=120), nullable=True)
    )
    op.add_column("devices", sa.Column("model", sa.String(length=120), nullable=True))
    op.add_column(
        "devices", sa.Column("os_version", sa.String(length=120), nullable=True)
    )
    op.add_column(
        "devices", sa.Column("serial_number", sa.String(length=120), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("devices", "serial_number")
    op.drop_column("devices", "os_version")
    op.drop_column("devices", "model")
    op.drop_column("devices", "manufacturer")
