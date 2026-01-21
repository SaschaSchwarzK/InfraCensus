"""add unique tenant user constraint

Revision ID: 0004_tenant_user_unique
Revises: 0003_users_and_roles
Create Date: 2024-01-04 00:00:00.000000

"""

from alembic import op


revision = "0004_tenant_user_unique"
down_revision = "0003_users_and_roles"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("tenant_users") as batch:
        batch.create_unique_constraint("uq_tenant_user", ["tenant_id", "user_id"])


def downgrade() -> None:
    with op.batch_alter_table("tenant_users") as batch:
        batch.drop_constraint("uq_tenant_user", type_="unique")
