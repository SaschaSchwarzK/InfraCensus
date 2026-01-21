"""add user password hash

Revision ID: 0005_user_password_hash
Revises: 0004_tenant_user_unique
Create Date: 2024-01-05 00:00:00.000000

"""

from alembic import op
import sqlalchemy as sa


revision = "0005_user_password_hash"
down_revision = "0004_tenant_user_unique"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    columns = [row[1] for row in bind.execute(sa.text("PRAGMA table_info(users)"))]
    if "password_hash" not in columns:
        op.add_column("users", sa.Column("password_hash", sa.String(length=255), nullable=True))
        op.execute("UPDATE users SET password_hash = '' WHERE password_hash IS NULL")
        with op.batch_alter_table("users") as batch:
            batch.alter_column(
                "password_hash",
                existing_type=sa.String(length=255),
                nullable=False,
            )


def downgrade() -> None:
    bind = op.get_bind()
    columns = [row[1] for row in bind.execute(sa.text("PRAGMA table_info(users)"))]
    if "password_hash" in columns:
        with op.batch_alter_table("users") as batch:
            batch.drop_column("password_hash")
