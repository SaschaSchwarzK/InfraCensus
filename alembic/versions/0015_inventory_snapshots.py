"""inventory snapshots

Revision ID: 0015_inventory_snapshots
Revises: 0014_site_timezone_and_schedule_utc
Create Date: 2026-01-21 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa

revision = "0015_inventory_snapshots"
down_revision = "0014_site_timezone_and_schedule_utc"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scan_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("site_id", sa.Integer(), sa.ForeignKey("sites.id"), nullable=True),
        sa.Column("collector_id", sa.Integer(), sa.ForeignKey("collectors.id"), nullable=True),
        sa.Column("started_at_utc", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at_utc", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "trigger",
            sa.Enum("schedule", "manual", "api", name="scantrigger"),
            nullable=False,
            server_default="schedule",
        ),
        sa.Column("scope", sa.Text(), nullable=True),
        sa.Column(
            "status",
            sa.Enum("queued", "running", "finished", "failed", name="scanstatus"),
            nullable=False,
            server_default="queued",
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "inventory_devices",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("site_id", sa.Integer(), sa.ForeignKey("sites.id"), nullable=True),
        sa.Column("device_uuid", sa.String(length=36), nullable=False, unique=True),
        sa.Column("vendor", sa.String(length=120), nullable=True),
        sa.Column("model", sa.String(length=120), nullable=True),
        sa.Column("device_family", sa.String(length=120), nullable=True),
        sa.Column("serial_number", sa.String(length=120), nullable=True),
        sa.Column("asset_tag", sa.String(length=120), nullable=True),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("fqdn", sa.String(length=255), nullable=True),
        sa.Column("device_role", sa.String(length=120), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "observations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_run_id", sa.Integer(), sa.ForeignKey("scan_runs.id"), nullable=False),
        sa.Column("device_id", sa.Integer(), sa.ForeignKey("inventory_devices.id"), nullable=True),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column(
            "protocol",
            sa.Enum("discovery", "snmp", "ssh", "http", "netconf", name="observationprotocol"),
            nullable=False,
        ),
        sa.Column("collected_at_utc", sa.DateTime(timezone=True), nullable=True),
        sa.Column("success", sa.Boolean(), nullable=False, server_default=sa.text("1")),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("raw_payload_ref", sa.Text(), nullable=True),
        sa.Column("parsed_payload_json", sa.Text(), nullable=True),
        sa.Column("evidence_hash", sa.String(length=128), nullable=True),
        sa.Column("parser_version", sa.String(length=50), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "device_identities",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("device_id", sa.Integer(), sa.ForeignKey("inventory_devices.id"), nullable=False),
        sa.Column(
            "identity_type",
            sa.Enum("serial", "mac", "hostname", "sysname", "mgmt_ip", name="identitytype"),
            nullable=False,
        ),
        sa.Column("value", sa.String(length=255), nullable=False),
        sa.Column(
            "first_seen_scan_run_id",
            sa.Integer(),
            sa.ForeignKey("scan_runs.id"),
            nullable=True,
        ),
        sa.Column(
            "last_seen_scan_run_id",
            sa.Integer(),
            sa.ForeignKey("scan_runs.id"),
            nullable=True,
        ),
        sa.Column("confidence", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("device_id", "identity_type", "value", name="uq_device_identity"),
    )

    op.create_table(
        "device_snapshots",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_run_id", sa.Integer(), sa.ForeignKey("scan_runs.id"), nullable=False),
        sa.Column("device_id", sa.Integer(), sa.ForeignKey("inventory_devices.id"), nullable=False),
        sa.Column("vendor", sa.String(length=120), nullable=True),
        sa.Column("model", sa.String(length=120), nullable=True),
        sa.Column("device_family", sa.String(length=120), nullable=True),
        sa.Column("serial_number", sa.String(length=120), nullable=True),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("fqdn", sa.String(length=255), nullable=True),
        sa.Column("os_name", sa.String(length=120), nullable=True),
        sa.Column("os_version", sa.String(length=120), nullable=True),
        sa.Column("firmware_version", sa.String(length=120), nullable=True),
        sa.Column("mgmt_ips", sa.Text(), nullable=True),
        sa.Column("reachable_protocols", sa.Text(), nullable=True),
        sa.Column("auth_method", sa.String(length=120), nullable=True),
        sa.Column("snapshot_hash", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("scan_run_id", "device_id", name="uq_device_snapshot"),
    )

    op.create_table(
        "interface_snapshots",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_run_id", sa.Integer(), sa.ForeignKey("scan_runs.id"), nullable=False),
        sa.Column("device_id", sa.Integer(), sa.ForeignKey("inventory_devices.id"), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("interface_type", sa.String(length=120), nullable=True),
        sa.Column("mac_address", sa.String(length=120), nullable=True),
        sa.Column("mtu", sa.Integer(), nullable=True),
        sa.Column("speed", sa.Integer(), nullable=True),
        sa.Column("admin_status", sa.String(length=50), nullable=True),
        sa.Column("oper_status", sa.String(length=50), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("vlans", sa.Text(), nullable=True),
        sa.Column("vrf", sa.String(length=120), nullable=True),
        sa.Column("snapshot_hash", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("scan_run_id", "device_id", "name", name="uq_interface_snapshot"),
    )

    op.create_table(
        "ip_snapshots",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_run_id", sa.Integer(), sa.ForeignKey("scan_runs.id"), nullable=False),
        sa.Column("device_id", sa.Integer(), sa.ForeignKey("inventory_devices.id"), nullable=False),
        sa.Column("interface_name", sa.String(length=200), nullable=True),
        sa.Column("ip_address", sa.String(length=64), nullable=False),
        sa.Column("prefix_length", sa.Integer(), nullable=False),
        sa.Column("ip_version", sa.String(length=10), nullable=True),
        sa.Column("snapshot_hash", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "scan_run_id",
            "device_id",
            "interface_name",
            "ip_address",
            "prefix_length",
            name="uq_ip_snapshot",
        ),
    )

    op.create_table(
        "neighbor_snapshots",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_run_id", sa.Integer(), sa.ForeignKey("scan_runs.id"), nullable=False),
        sa.Column("device_id", sa.Integer(), sa.ForeignKey("inventory_devices.id"), nullable=False),
        sa.Column("local_interface", sa.String(length=200), nullable=False),
        sa.Column("remote_device_id", sa.Integer(), sa.ForeignKey("inventory_devices.id"), nullable=True),
        sa.Column("remote_chassis_id", sa.String(length=200), nullable=True),
        sa.Column("remote_interface", sa.String(length=200), nullable=True),
        sa.Column("snapshot_hash", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "scan_run_id",
            "device_id",
            "local_interface",
            "remote_chassis_id",
            "remote_interface",
            name="uq_neighbor_snapshot",
        ),
    )

    op.create_table(
        "service_snapshots",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_run_id", sa.Integer(), sa.ForeignKey("scan_runs.id"), nullable=False),
        sa.Column("device_id", sa.Integer(), sa.ForeignKey("inventory_devices.id"), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(length=20), nullable=False),
        sa.Column("service_name", sa.String(length=120), nullable=True),
        sa.Column("banner", sa.Text(), nullable=True),
        sa.Column("tls_subject", sa.Text(), nullable=True),
        sa.Column("tls_issuer", sa.Text(), nullable=True),
        sa.Column("tls_not_before_utc", sa.DateTime(timezone=True), nullable=True),
        sa.Column("tls_not_after_utc", sa.DateTime(timezone=True), nullable=True),
        sa.Column("tls_sans", sa.Text(), nullable=True),
        sa.Column("tls_fingerprint", sa.String(length=128), nullable=True),
        sa.Column("http_title", sa.Text(), nullable=True),
        sa.Column("http_headers", sa.Text(), nullable=True),
        sa.Column("snapshot_hash", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "scan_run_id",
            "device_id",
            "port",
            "protocol",
            name="uq_service_snapshot",
        ),
    )

    op.create_table(
        "config_snapshots",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_run_id", sa.Integer(), sa.ForeignKey("scan_runs.id"), nullable=False),
        sa.Column("device_id", sa.Integer(), sa.ForeignKey("inventory_devices.id"), nullable=False),
        sa.Column("retrieved_at_utc", sa.DateTime(timezone=True), nullable=True),
        sa.Column("config_hash", sa.String(length=128), nullable=True),
        sa.Column("storage_ref", sa.Text(), nullable=True),
        sa.Column("size_bytes", sa.Integer(), nullable=True),
        sa.Column("redacted_hash", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("scan_run_id", "device_id", name="uq_config_snapshot"),
    )


def downgrade() -> None:
    op.drop_table("config_snapshots")
    op.drop_table("service_snapshots")
    op.drop_table("neighbor_snapshots")
    op.drop_table("ip_snapshots")
    op.drop_table("interface_snapshots")
    op.drop_table("device_snapshots")
    op.drop_table("device_identities")
    op.drop_table("observations")
    op.drop_table("inventory_devices")
    op.drop_table("scan_runs")
