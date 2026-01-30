"""add tenant user roles list

Revision ID: 0009_tenant_user_roles
Revises: 0008_user_password_nullable
Create Date: 2024-01-09 00:00:00.000000

"""

import sqlalchemy as sa

from alembic import op

revision = "0009_tenant_user_roles"
down_revision = "0008_user_password_nullable"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("tenant_users", sa.Column("roles", sa.Text(), nullable=True))
    op.execute("UPDATE tenant_users SET roles = role WHERE roles IS NULL")


def downgrade() -> None:
    with op.batch_alter_table("tenant_users") as batch:
        batch.drop_column("roles")
