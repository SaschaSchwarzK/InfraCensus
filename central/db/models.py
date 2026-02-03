from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from enum import Enum

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy import (
    Enum as SqlEnum,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates

from central.db.base import Base


def utcnow() -> datetime:
    return datetime.now(UTC)


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    default_scanner: Mapped[str] = mapped_column(String(120), nullable=True)
    default_scan_interval_minutes: Mapped[int] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    collectors: Mapped[list[Collector]] = relationship(back_populates="tenant")
    tenant_users: Mapped[list[TenantUser]] = relationship(back_populates="tenant")


class Collector(Base):
    __tablename__ = "collectors"
    __table_args__ = (
        Index("ix_collectors_tenant_id", "tenant_id"),
        Index("ix_collectors_cert_serial", "cert_serial"),
        Index("ix_collectors_cert_fingerprint", "cert_fingerprint"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    uuid: Mapped[str] = mapped_column(String(36), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="active")
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id"), nullable=True)
    location: Mapped[str] = mapped_column(String(200), nullable=True)
    labels: Mapped[dict[str, str] | None] = mapped_column(JSON, nullable=True)
    capabilities: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    allowed_scopes: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    cert_serial: Mapped[str] = mapped_column(String(128), nullable=True)
    cert_fingerprint: Mapped[str] = mapped_column(String(256), nullable=True)
    cert_valid_from: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    cert_valid_to: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_seen_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    clock_skew_seconds: Mapped[int] = mapped_column(Integer, nullable=True)
    risk_flags: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    tenant: Mapped[Tenant] = relationship(back_populates="collectors")


class CollectorAffinity(Base):
    __tablename__ = "collector_affinities"
    __table_args__ = (
        CheckConstraint(
            "subnet_cidr IS NULL OR subnet_cidr LIKE '%/%'",
            name="ck_collector_affinity_subnet_cidr_format",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    collector_id: Mapped[int] = mapped_column(
        ForeignKey("collectors.id"), nullable=False
    )
    network_id: Mapped[int] = mapped_column(ForeignKey("networks.id"), nullable=True)
    subnet_cidr: Mapped[str] = mapped_column(String(64), nullable=True)
    scan_type: Mapped[str] = mapped_column(String(100), nullable=True)
    priority: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    tenant: Mapped[Tenant] = relationship()
    collector: Mapped[Collector] = relationship()
    network: Mapped[Network] = relationship()

    @validates("subnet_cidr")
    def validate_subnet_cidr(self, key, value) -> str | None:
        if value is None:
            return value
        try:
            ipaddress.ip_network(value, strict=False)
            return value
        except ValueError as exc:
            raise ValueError(f"Invalid CIDR format: {value}") from exc


class ScanTrigger(str, Enum):
    schedule = "schedule"
    manual = "manual"
    api = "api"


class ScanStatus(str, Enum):
    queued = "queued"
    running = "running"
    finished = "finished"
    failed = "failed"


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id"), nullable=True)
    collector_id: Mapped[int] = mapped_column(
        ForeignKey("collectors.id"), nullable=True
    )
    started_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    finished_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    trigger: Mapped[ScanTrigger] = mapped_column(
        SqlEnum(ScanTrigger), default=ScanTrigger.schedule
    )
    scope: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    status: Mapped[ScanStatus] = mapped_column(
        SqlEnum(ScanStatus), default=ScanStatus.queued
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    tenant: Mapped[Tenant] = relationship()
    site: Mapped[Site] = relationship()
    collector: Mapped[Collector] = relationship()


class ObservationProtocol(str, Enum):
    discovery = "discovery"
    snmp = "snmp"
    ssh = "ssh"
    http = "http"
    netconf = "netconf"


class Observation(Base):
    __tablename__ = "observations"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_run_id: Mapped[int] = mapped_column(ForeignKey("scan_runs.id"), nullable=False)
    device_id: Mapped[int] = mapped_column(
        ForeignKey("inventory_devices.id"), nullable=True
    )
    ip_address: Mapped[str] = mapped_column(String(64), nullable=True)
    protocol: Mapped[ObservationProtocol] = mapped_column(
        SqlEnum(ObservationProtocol), nullable=False
    )
    collected_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    success: Mapped[bool] = mapped_column(Boolean, default=True)
    error: Mapped[str] = mapped_column(Text, nullable=True)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=True)
    raw_payload_ref: Mapped[str] = mapped_column(Text, nullable=True)
    parsed_payload_json: Mapped[str] = mapped_column(Text, nullable=True)
    evidence_hash: Mapped[str] = mapped_column(String(128), nullable=True)
    parser_version: Mapped[str] = mapped_column(String(50), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    scan_run: Mapped[ScanRun] = relationship()
    device: Mapped[InventoryDevice] = relationship()


class InventoryDevice(Base):
    __tablename__ = "inventory_devices"

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id"), nullable=True)
    device_uuid: Mapped[str] = mapped_column(String(36), unique=True, nullable=False)
    vendor: Mapped[str] = mapped_column(String(120), nullable=True)
    model: Mapped[str] = mapped_column(String(120), nullable=True)
    device_family: Mapped[str] = mapped_column(String(120), nullable=True)
    serial_number: Mapped[str] = mapped_column(String(120), nullable=True)
    asset_tag: Mapped[str] = mapped_column(String(120), nullable=True)
    hostname: Mapped[str] = mapped_column(String(255), nullable=True)
    fqdn: Mapped[str] = mapped_column(String(255), nullable=True)
    device_role: Mapped[str] = mapped_column(String(120), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    tenant: Mapped[Tenant] = relationship()
    site: Mapped[Site] = relationship()


class IdentityType(str, Enum):
    serial = "serial"
    mac = "mac"
    hostname = "hostname"
    sysname = "sysname"
    mgmt_ip = "mgmt_ip"


class DeviceIdentity(Base):
    __tablename__ = "device_identities"
    __table_args__ = (
        UniqueConstraint(
            "device_id", "identity_type", "value", name="uq_device_identity"
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(
        ForeignKey("inventory_devices.id"), nullable=False
    )
    identity_type: Mapped[IdentityType] = mapped_column(
        SqlEnum(IdentityType), nullable=False
    )
    value: Mapped[str] = mapped_column(String(255), nullable=False)
    first_seen_scan_run_id: Mapped[int] = mapped_column(
        ForeignKey("scan_runs.id"), nullable=True
    )
    last_seen_scan_run_id: Mapped[int] = mapped_column(
        ForeignKey("scan_runs.id"), nullable=True
    )
    confidence: Mapped[int] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    device: Mapped[InventoryDevice] = relationship()
    first_seen_scan_run: Mapped[ScanRun] = relationship(
        foreign_keys=[first_seen_scan_run_id]
    )
    last_seen_scan_run: Mapped[ScanRun] = relationship(
        foreign_keys=[last_seen_scan_run_id]
    )


class DeviceSnapshot(Base):
    __tablename__ = "device_snapshots"
    __table_args__ = (
        UniqueConstraint("scan_run_id", "device_id", name="uq_device_snapshot"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_run_id: Mapped[int] = mapped_column(ForeignKey("scan_runs.id"), nullable=False)
    device_id: Mapped[int] = mapped_column(
        ForeignKey("inventory_devices.id"), nullable=False
    )
    vendor: Mapped[str] = mapped_column(String(120), nullable=True)
    model: Mapped[str] = mapped_column(String(120), nullable=True)
    device_family: Mapped[str] = mapped_column(String(120), nullable=True)
    serial_number: Mapped[str] = mapped_column(String(120), nullable=True)
    hostname: Mapped[str] = mapped_column(String(255), nullable=True)
    fqdn: Mapped[str] = mapped_column(String(255), nullable=True)
    os_name: Mapped[str] = mapped_column(String(120), nullable=True)
    os_version: Mapped[str] = mapped_column(String(120), nullable=True)
    firmware_version: Mapped[str] = mapped_column(String(120), nullable=True)
    mgmt_ips: Mapped[str] = mapped_column(Text, nullable=True)
    reachable_protocols: Mapped[str] = mapped_column(Text, nullable=True)
    auth_method: Mapped[str] = mapped_column(String(120), nullable=True)
    snapshot_hash: Mapped[str] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    scan_run: Mapped[ScanRun] = relationship()
    device: Mapped[InventoryDevice] = relationship()


class InterfaceSnapshot(Base):
    __tablename__ = "interface_snapshots"
    __table_args__ = (
        UniqueConstraint(
            "scan_run_id", "device_id", "name", name="uq_interface_snapshot"
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_run_id: Mapped[int] = mapped_column(ForeignKey("scan_runs.id"), nullable=False)
    device_id: Mapped[int] = mapped_column(
        ForeignKey("inventory_devices.id"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    interface_type: Mapped[str] = mapped_column(String(120), nullable=True)
    mac_address: Mapped[str] = mapped_column(String(120), nullable=True)
    mtu: Mapped[int] = mapped_column(Integer, nullable=True)
    speed: Mapped[int] = mapped_column(Integer, nullable=True)
    admin_status: Mapped[str] = mapped_column(String(50), nullable=True)
    oper_status: Mapped[str] = mapped_column(String(50), nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    vlans: Mapped[str] = mapped_column(Text, nullable=True)
    vrf: Mapped[str] = mapped_column(String(120), nullable=True)
    snapshot_hash: Mapped[str] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    scan_run: Mapped[ScanRun] = relationship()
    device: Mapped[InventoryDevice] = relationship()


class IpSnapshot(Base):
    __tablename__ = "ip_snapshots"
    __table_args__ = (
        UniqueConstraint(
            "scan_run_id",
            "device_id",
            "interface_name",
            "ip_address",
            "prefix_length",
            name="uq_ip_snapshot",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_run_id: Mapped[int] = mapped_column(ForeignKey("scan_runs.id"), nullable=False)
    device_id: Mapped[int] = mapped_column(
        ForeignKey("inventory_devices.id"), nullable=False
    )
    interface_name: Mapped[str] = mapped_column(String(200), nullable=True)
    ip_address: Mapped[str] = mapped_column(String(64), nullable=False)
    prefix_length: Mapped[int] = mapped_column(Integer, nullable=False)
    ip_version: Mapped[str] = mapped_column(String(10), nullable=True)
    snapshot_hash: Mapped[str] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    scan_run: Mapped[ScanRun] = relationship()
    device: Mapped[InventoryDevice] = relationship()


class NeighborSnapshot(Base):
    __tablename__ = "neighbor_snapshots"
    __table_args__ = (
        UniqueConstraint(
            "scan_run_id",
            "device_id",
            "local_interface",
            "remote_chassis_id",
            "remote_interface",
            name="uq_neighbor_snapshot",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_run_id: Mapped[int] = mapped_column(ForeignKey("scan_runs.id"), nullable=False)
    device_id: Mapped[int] = mapped_column(
        ForeignKey("inventory_devices.id"), nullable=False
    )
    local_interface: Mapped[str] = mapped_column(String(200), nullable=False)
    remote_device_id: Mapped[int] = mapped_column(
        ForeignKey("inventory_devices.id"), nullable=True
    )
    remote_chassis_id: Mapped[str] = mapped_column(String(200), nullable=True)
    remote_interface: Mapped[str] = mapped_column(String(200), nullable=True)
    snapshot_hash: Mapped[str] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    scan_run: Mapped[ScanRun] = relationship()
    device: Mapped[InventoryDevice] = relationship(foreign_keys=[device_id])
    remote_device: Mapped[InventoryDevice] = relationship(
        foreign_keys=[remote_device_id]
    )


class ServiceSnapshot(Base):
    __tablename__ = "service_snapshots"
    __table_args__ = (
        UniqueConstraint(
            "scan_run_id",
            "device_id",
            "port",
            "protocol",
            name="uq_service_snapshot",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_run_id: Mapped[int] = mapped_column(ForeignKey("scan_runs.id"), nullable=False)
    device_id: Mapped[int] = mapped_column(
        ForeignKey("inventory_devices.id"), nullable=False
    )
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(20), nullable=False)
    service_name: Mapped[str] = mapped_column(String(120), nullable=True)
    banner: Mapped[str] = mapped_column(Text, nullable=True)
    tls_subject: Mapped[str] = mapped_column(Text, nullable=True)
    tls_issuer: Mapped[str] = mapped_column(Text, nullable=True)
    tls_not_before_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    tls_not_after_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    tls_sans: Mapped[str] = mapped_column(Text, nullable=True)
    tls_fingerprint: Mapped[str] = mapped_column(String(128), nullable=True)
    http_title: Mapped[str] = mapped_column(Text, nullable=True)
    http_headers: Mapped[str] = mapped_column(Text, nullable=True)
    snapshot_hash: Mapped[str] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    scan_run: Mapped[ScanRun] = relationship()
    device: Mapped[InventoryDevice] = relationship()


class ConfigSnapshot(Base):
    __tablename__ = "config_snapshots"
    __table_args__ = (
        UniqueConstraint("scan_run_id", "device_id", name="uq_config_snapshot"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_run_id: Mapped[int] = mapped_column(ForeignKey("scan_runs.id"), nullable=False)
    device_id: Mapped[int] = mapped_column(
        ForeignKey("inventory_devices.id"), nullable=False
    )
    retrieved_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    config_hash: Mapped[str] = mapped_column(String(128), nullable=True)
    storage_ref: Mapped[str] = mapped_column(Text, nullable=True)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=True)
    redacted_hash: Mapped[str] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    scan_run: Mapped[ScanRun] = relationship()
    device: Mapped[InventoryDevice] = relationship()


class Site(Base):
    __tablename__ = "sites"
    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_site_tenant_name"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    timezone: Mapped[str] = mapped_column(String(120), nullable=False)
    code: Mapped[str] = mapped_column(String(50), nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    tenant: Mapped[Tenant] = relationship()
    networks: Mapped[list[Network]] = relationship(back_populates="site")


class Network(Base):
    __tablename__ = "networks"
    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_network_tenant_name"),
        CheckConstraint("cidr LIKE '%/%'", name="ck_network_cidr_format"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id"), nullable=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    cidr: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    tenant: Mapped[Tenant] = relationship()
    site: Mapped[Site] = relationship(back_populates="networks")


class NetworkRateLimit(Base):
    __tablename__ = "network_rate_limits"

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    network_id: Mapped[int] = mapped_column(ForeignKey("networks.id"), nullable=False)
    window_start_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    count: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
        onupdate=utcnow,
    )

    tenant: Mapped[Tenant] = relationship()
    network: Mapped[Network] = relationship()


class ScanSchedule(Base):
    __tablename__ = "scan_schedules"
    __table_args__ = (
        Index("ix_scan_schedules_tenant_id", "tenant_id"),
        Index(
            "ix_scan_schedules_tenant_site",
            "tenant_id",
            "site_id",
            postgresql_where=text("site_id IS NOT NULL"),
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id"), nullable=True)
    name: Mapped[str] = mapped_column(String(200), nullable=True)
    scheduled_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    not_before_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    not_after_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    actual_start_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    finished_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    network_ids: Mapped[str] = mapped_column(Text, nullable=True)
    scan_types: Mapped[str] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    tenant: Mapped[Tenant] = relationship()
    site: Mapped[Site] = relationship()


class ExportSchedule(Base):
    __tablename__ = "export_schedules"

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id"), nullable=True)
    name: Mapped[str] = mapped_column(String(200), nullable=True)
    exporter: Mapped[str] = mapped_column(String(120), nullable=False)
    scheduled_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    not_before_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    not_after_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    actual_start_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    finished_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    settings_json: Mapped[str] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    tenant: Mapped[Tenant] = relationship()
    site: Mapped[Site] = relationship()


class CredentialSet(Base):
    __tablename__ = "credential_sets"

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    protocol: Mapped[str] = mapped_column(String(50), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=True)
    vault_index: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    tenant: Mapped[Tenant] = relationship()


class CredentialAssignment(Base):
    __tablename__ = "credential_assignments"
    __table_args__ = (
        CheckConstraint(
            "subnet_cidr LIKE '%/%'", name="ck_credential_assignment_cidr_format"
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    subnet_cidr: Mapped[str] = mapped_column(String(64), nullable=False)
    protocol: Mapped[str] = mapped_column(String(50), nullable=False)
    credential_set_id: Mapped[int] = mapped_column(
        ForeignKey("credential_sets.id"), nullable=False
    )
    priority: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    tenant: Mapped[Tenant] = relationship()
    credential_set: Mapped[CredentialSet] = relationship()


class ScanScheduleType(Base):
    __tablename__ = "scan_schedule_types"
    __table_args__ = (
        Index("ix_scan_schedule_types_schedule_id", "schedule_id"),
        Index("ix_scan_schedule_types_finished_at_utc", "finished_at_utc"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    schedule_id: Mapped[int] = mapped_column(
        ForeignKey("scan_schedules.id"), nullable=False
    )
    scan_type: Mapped[str] = mapped_column(String(100), nullable=False)
    scheduled_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    not_before_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    not_after_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    priority: Mapped[int] = mapped_column(Integer, default=0)
    assigned_collector_id: Mapped[int] = mapped_column(
        ForeignKey("collectors.id"), nullable=True
    )
    assigned_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    actual_start_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    finished_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    schedule: Mapped[ScanSchedule] = relationship()
    assigned_collector: Mapped[Collector] = relationship()


class CollectorCertificate(Base):
    __tablename__ = "collector_certificates"

    id: Mapped[int] = mapped_column(primary_key=True)
    collector_id: Mapped[int] = mapped_column(
        ForeignKey("collectors.id"), nullable=False
    )
    serial: Mapped[str] = mapped_column(String(128), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(256), nullable=False)
    valid_from: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    valid_to: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    collector: Mapped[Collector] = relationship()


class CollectorEnrollmentToken(Base):
    __tablename__ = "collector_enrollment_tokens"

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id"), nullable=True)
    token_hash: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    used_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by_user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    tenant: Mapped[Tenant] = relationship()
    site: Mapped[Site] = relationship()


class UserRole(str, Enum):
    read_only = "ro"
    scan_operator = "scan_operator"
    read_write = "rw"
    user_admin = "user_admin"


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), nullable=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=True)
    is_superadmin: Mapped[bool] = mapped_column(default=False)
    is_auditor: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    tenants: Mapped[list[TenantUser]] = relationship(back_populates="user")


class TenantUser(Base):
    __tablename__ = "tenant_users"
    __table_args__ = (UniqueConstraint("tenant_id", "user_id", name="uq_tenant_user"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    role: Mapped[UserRole] = mapped_column(
        SqlEnum(UserRole), default=UserRole.read_only
    )
    roles: Mapped[str] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    tenant: Mapped[Tenant] = relationship(back_populates="tenant_users")
    user: Mapped[User] = relationship(back_populates="tenants")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    actor_user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(100), nullable=False)
    entity_id: Mapped[int] = mapped_column(Integer, nullable=True)
    details: Mapped[str] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )


class TaskFailureLog(Base):
    __tablename__ = "task_failure_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    task_id: Mapped[str] = mapped_column(String(64), nullable=True)
    task_name: Mapped[str] = mapped_column(String(200), nullable=False)
    exception: Mapped[str] = mapped_column(Text, nullable=True)
    traceback: Mapped[str] = mapped_column(Text, nullable=True)
    args: Mapped[str] = mapped_column(Text, nullable=True)
    kwargs: Mapped[str] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )


class PermanentFailure(Base):
    __tablename__ = "permanent_failures"

    id: Mapped[int] = mapped_column(primary_key=True)
    task_id: Mapped[str] = mapped_column(String(64), nullable=True)
    task_name: Mapped[str] = mapped_column(String(200), nullable=False)
    error: Mapped[str] = mapped_column(Text, nullable=True)
    args: Mapped[str] = mapped_column(Text, nullable=True)
    kwargs: Mapped[str] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
