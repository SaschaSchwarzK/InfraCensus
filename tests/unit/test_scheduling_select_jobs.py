from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from central.core import scheduling
from central.db.base import Base
from central.db.models import (
    Collector,
    CollectorAffinity,
    Network,
    NetworkRateLimit,
    ScanSchedule,
    ScanScheduleType,
    Site,
    Tenant,
)


@pytest.fixture()
def session():
    engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(
        bind=engine, autoflush=False, expire_on_commit=False, future=True
    )
    try:
        with SessionLocal() as session:
            yield session
    finally:
        engine.dispose()


def _seed_basic(session):
    tenant = Tenant(name="tenant-1")
    session.add(tenant)
    session.flush()
    site = Site(tenant_id=tenant.id, name="site-1", timezone="UTC")
    session.add(site)
    session.flush()
    network = Network(
        tenant_id=tenant.id,
        site_id=site.id,
        name="net-1",
        cidr="10.0.0.0/24",
    )
    session.add(network)
    collector = Collector(
        tenant_id=tenant.id,
        uuid="collector-1",
        name="collector-1",
        status="active",
        site_id=site.id,
        capabilities=["snmp"],
    )
    session.add(collector)
    session.flush()
    return tenant, site, network, collector


def _create_schedule(session, tenant_id, site_id, network_id, scan_type, now):
    schedule = ScanSchedule(
        tenant_id=tenant_id,
        site_id=site_id,
        name="sched",
        scheduled_at_utc=now,
        network_ids=str(network_id),
    )
    session.add(schedule)
    session.flush()
    entry = ScanScheduleType(
        schedule_id=schedule.id,
        scan_type=scan_type,
        scheduled_at_utc=now,
        priority=1,
    )
    session.add(entry)
    session.flush()
    return schedule, entry


def test_select_jobs_respects_capacity(monkeypatch, session):
    tenant, site, network, collector = _seed_basic(session)
    now = datetime.now(UTC)
    schedule, entry = _create_schedule(
        session, tenant.id, site.id, network.id, "snmp", now
    )
    # create inflight assignment to consume capacity
    inflight = ScanScheduleType(
        schedule_id=schedule.id,
        scan_type="snmp",
        scheduled_at_utc=now,
        priority=1,
        assigned_collector_id=collector.id,
    )
    session.add(inflight)
    session.flush()
    collector.labels = {"capacity": "1"}

    monkeypatch.setattr(
        scheduling.settings, "scheduler_default_capacity", 1, raising=False
    )
    monkeypatch.setattr(
        scheduling.settings, "scheduler_network_rate_limit_per_minute", 0, raising=False
    )
    monkeypatch.setattr(
        scheduling.settings,
        "scheduler_network_rate_limit_window_seconds",
        60,
        raising=False,
    )
    jobs = scheduling.select_jobs_for_collector(session, collector, now, max_jobs=5)
    assert jobs == []


def test_select_jobs_skips_outside_window(monkeypatch, session):
    tenant, site, network, collector = _seed_basic(session)
    now = datetime.now(UTC)
    schedule = ScanSchedule(
        tenant_id=tenant.id,
        site_id=site.id,
        name="sched",
        scheduled_at_utc=now,
        not_before_utc=now + timedelta(hours=1),
        network_ids=str(network.id),
    )
    session.add(schedule)
    session.flush()
    entry = ScanScheduleType(
        schedule_id=schedule.id,
        scan_type="snmp",
        scheduled_at_utc=now,
        priority=1,
    )
    session.add(entry)
    session.flush()

    monkeypatch.setattr(
        scheduling.settings, "scheduler_default_capacity", 2, raising=False
    )
    monkeypatch.setattr(
        scheduling.settings, "scheduler_network_rate_limit_per_minute", 0, raising=False
    )
    monkeypatch.setattr(
        scheduling.settings,
        "scheduler_network_rate_limit_window_seconds",
        60,
        raising=False,
    )
    jobs = scheduling.select_jobs_for_collector(session, collector, now, max_jobs=5)
    assert jobs == []


def test_select_jobs_requires_capability(monkeypatch, session):
    tenant, site, network, collector = _seed_basic(session)
    collector.capabilities = ["ssh"]
    now = datetime.now(UTC)
    _create_schedule(session, tenant.id, site.id, network.id, "snmp", now)

    monkeypatch.setattr(
        scheduling.settings, "scheduler_default_capacity", 2, raising=False
    )
    monkeypatch.setattr(
        scheduling.settings, "scheduler_network_rate_limit_per_minute", 0, raising=False
    )
    monkeypatch.setattr(
        scheduling.settings,
        "scheduler_network_rate_limit_window_seconds",
        60,
        raising=False,
    )
    jobs = scheduling.select_jobs_for_collector(session, collector, now, max_jobs=5)
    assert jobs == []


def test_select_jobs_rate_limit_blocks(monkeypatch, session):
    tenant, site, network, collector = _seed_basic(session)
    now = datetime.now(UTC)
    _create_schedule(session, tenant.id, site.id, network.id, "snmp", now)
    session.add(
        NetworkRateLimit(
            tenant_id=tenant.id,
            network_id=network.id,
            window_start_at_utc=now,
            count=1,
        )
    )
    session.flush()

    monkeypatch.setattr(
        scheduling.settings, "scheduler_default_capacity", 2, raising=False
    )
    monkeypatch.setattr(
        scheduling.settings, "scheduler_network_rate_limit_per_minute", 1, raising=False
    )
    monkeypatch.setattr(
        scheduling.settings,
        "scheduler_network_rate_limit_window_seconds",
        60,
        raising=False,
    )
    jobs = scheduling.select_jobs_for_collector(session, collector, now, max_jobs=5)
    assert jobs == []


def test_select_jobs_affinity_blocks_lower_priority(monkeypatch, session):
    tenant, site, network, collector = _seed_basic(session)
    other = Collector(
        tenant_id=tenant.id,
        uuid="collector-2",
        name="collector-2",
        status="active",
        site_id=site.id,
        capabilities=["snmp"],
    )
    session.add(other)
    session.flush()
    now = datetime.now(UTC)
    _create_schedule(session, tenant.id, site.id, network.id, "snmp", now)

    session.add(
        CollectorAffinity(
            tenant_id=tenant.id,
            collector_id=other.id,
            network_id=network.id,
            scan_type="snmp",
            priority=10,
        )
    )
    session.add(
        CollectorAffinity(
            tenant_id=tenant.id,
            collector_id=collector.id,
            network_id=network.id,
            scan_type="snmp",
            priority=1,
        )
    )
    session.flush()

    monkeypatch.setattr(
        scheduling.settings, "scheduler_default_capacity", 2, raising=False
    )
    monkeypatch.setattr(
        scheduling.settings, "scheduler_network_rate_limit_per_minute", 0, raising=False
    )
    monkeypatch.setattr(
        scheduling.settings,
        "scheduler_network_rate_limit_window_seconds",
        60,
        raising=False,
    )
    jobs = scheduling.select_jobs_for_collector(session, collector, now, max_jobs=5)
    assert jobs == []


def test_select_jobs_assigns_job(monkeypatch, session):
    tenant, site, network, collector = _seed_basic(session)
    now = datetime.now(UTC)
    _create_schedule(session, tenant.id, site.id, network.id, "snmp", now)

    monkeypatch.setattr(
        scheduling.settings, "scheduler_default_capacity", 2, raising=False
    )
    monkeypatch.setattr(
        scheduling.settings, "scheduler_network_rate_limit_per_minute", 0, raising=False
    )
    monkeypatch.setattr(
        scheduling.settings,
        "scheduler_network_rate_limit_window_seconds",
        60,
        raising=False,
    )
    jobs = scheduling.select_jobs_for_collector(session, collector, now, max_jobs=1)

    assert len(jobs) == 1
    assert jobs[0].scan_type == "snmp"
    assert jobs[0].targets == ["10.0.0.0/24"]
