"""add users and tenant roles

Revision ID: 0003_users_and_roles
Revises: 0002_device_hardware_fields
Create Date: 2024-01-03 00:00:00.000000

"""

import sqlalchemy as sa

from alembic import op

revision = "0003_users_and_roles"
down_revision = "0002_device_hardware_fields"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("email", sa.String(length=255), nullable=False, unique=True),
        sa.Column("full_name", sa.String(length=255), nullable=True),
        sa.Column(
            "is_superadmin", sa.Boolean(), nullable=False, server_default=sa.text("0")
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "tenant_users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False
        ),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column(
            "role", sa.Enum("ro", "rw", "user_admin", name="userrole"), nullable=False
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("tenant_users")
    op.drop_table("users")
