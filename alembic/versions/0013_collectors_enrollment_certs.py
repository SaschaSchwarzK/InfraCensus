"""expand collectors and add enrollment/cert tables

Revision ID: 0013_collectors_enrollment_certs
Revises: 0012_scan_schedule_times
Create Date: 2024-01-13 00:00:00.000000

"""

from alembic import op
import sqlalchemy as sa


revision = "0013_collectors_enrollment_certs"
down_revision = "0012_scan_schedule_times"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    columns = [row[1] for row in bind.execute(sa.text("PRAGMA table_info(collectors)"))]
    with op.batch_alter_table("collectors") as batch:
        if "uuid" not in columns:
            batch.add_column(sa.Column("uuid", sa.String(length=36), nullable=True))
        if "status" not in columns:
            batch.add_column(sa.Column("status", sa.String(length=50), nullable=True))
        if "site_id" not in columns:
            batch.add_column(sa.Column("site_id", sa.Integer(), nullable=True))
        if "labels" not in columns:
            batch.add_column(sa.Column("labels", sa.Text(), nullable=True))
        if "capabilities" not in columns:
            batch.add_column(sa.Column("capabilities", sa.Text(), nullable=True))
        if "allowed_scopes" not in columns:
            batch.add_column(sa.Column("allowed_scopes", sa.Text(), nullable=True))
        if "cert_serial" not in columns:
            batch.add_column(sa.Column("cert_serial", sa.String(length=128), nullable=True))
        if "cert_fingerprint" not in columns:
            batch.add_column(sa.Column("cert_fingerprint", sa.String(length=256), nullable=True))
        if "cert_valid_from" not in columns:
            batch.add_column(sa.Column("cert_valid_from", sa.DateTime(timezone=True), nullable=True))
        if "cert_valid_to" not in columns:
            batch.add_column(sa.Column("cert_valid_to", sa.DateTime(timezone=True), nullable=True))
        if "risk_flags" not in columns:
            batch.add_column(sa.Column("risk_flags", sa.Text(), nullable=True))
    op.execute("UPDATE collectors SET uuid = lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-4' || substr(lower(hex(randomblob(2))), 2) || '-' || substr('89ab', abs(random()) % 4 + 1, 1) || substr(lower(hex(randomblob(2))), 2) || '-' || lower(hex(randomblob(6))) WHERE uuid IS NULL")
    op.execute("UPDATE collectors SET status = 'active' WHERE status IS NULL")
    indexes = [row[1] for row in bind.execute(sa.text("PRAGMA index_list(collectors)"))]
    with op.batch_alter_table("collectors") as batch:
        if "uuid" in columns:
            batch.alter_column("uuid", nullable=False)
        if "status" in columns:
            batch.alter_column("status", nullable=False)
        if "uq_collectors_uuid" not in indexes:
            batch.create_unique_constraint("uq_collectors_uuid", ["uuid"])
        # Skip FK constraint in SQLite migrations to avoid ALTER constraint issues.

    tables = {row[0] for row in bind.execute(sa.text("SELECT name FROM sqlite_master WHERE type='table'"))}
    if "collector_certificates" not in tables:
        op.create_table(
            "collector_certificates",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("collector_id", sa.Integer(), sa.ForeignKey("collectors.id"), nullable=False),
            sa.Column("serial", sa.String(length=128), nullable=False),
            sa.Column("fingerprint", sa.String(length=256), nullable=False),
            sa.Column("valid_from", sa.DateTime(timezone=True), nullable=False),
            sa.Column("valid_to", sa.DateTime(timezone=True), nullable=False),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
    if "collector_enrollment_tokens" not in tables:
        op.create_table(
            "collector_enrollment_tokens",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False),
            sa.Column("site_id", sa.Integer(), sa.ForeignKey("sites.id"), nullable=True),
            sa.Column("token_hash", sa.String(length=128), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_by_user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint("token_hash", name="uq_collector_enrollment_token"),
        )


def downgrade() -> None:
    op.drop_constraint("uq_collector_enrollment_token", "collector_enrollment_tokens", type_="unique")
    op.drop_table("collector_enrollment_tokens")
    op.drop_table("collector_certificates")
    with op.batch_alter_table("collectors") as batch:
        batch.drop_constraint("uq_collectors_uuid", type_="unique")
        batch.drop_column("risk_flags")
        batch.drop_column("cert_valid_to")
        batch.drop_column("cert_valid_from")
        batch.drop_column("cert_fingerprint")
        batch.drop_column("cert_serial")
        batch.drop_column("allowed_scopes")
        batch.drop_column("capabilities")
        batch.drop_column("labels")
        batch.drop_column("site_id")
        batch.drop_column("status")
        batch.drop_column("uuid")
