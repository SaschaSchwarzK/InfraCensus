"""allow null password hash for oidc

Revision ID: 0008_user_password_nullable
Revises: 0007_audit_logs
Create Date: 2024-01-08 00:00:00.000000

"""

import sqlalchemy as sa

from alembic import op

revision = "0008_user_password_nullable"
down_revision = "0007_audit_logs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.alter_column(
            "password_hash", existing_type=sa.String(length=255), nullable=True
        )


def downgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.alter_column(
            "password_hash", existing_type=sa.String(length=255), nullable=False
        )
