from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from central.core import scheduling


class DummySession:
    def __init__(self, records=None):
        self.records = records or []
        self.added = []

    def query(self, *_args, **_kwargs):
        return DummyQuery(self.records)

    def add(self, obj):
        self.added.append(obj)


class DummyQuery:
    def __init__(self, records):
        self.records = records

    def filter(self, *_args, **_kwargs):
        return self

    def all(self):
        return list(self.records)


@pytest.mark.parametrize(
    "job_id,expected",
    [
        ("schedule_type:1", 1),
        ("schedule_type:0002", 2),
        ("schedule_type:0", None),
        ("schedule_type:-1", None),
        ("schedule_type:abc", None),
        ("schedule_type:", None),
        ("", None),
        ("invalid:1", None),
    ],
)
def test_parse_job_id_edge_cases(job_id, expected):
    assert scheduling.parse_job_id(job_id) == expected


def test_within_window_edges():
    now = datetime.now(UTC)
    assert scheduling._within_window(None, None, now)
    assert scheduling._within_window(now, None, now)
    assert scheduling._within_window(None, now, now)
    assert not scheduling._within_window(now + timedelta(seconds=1), None, now)
    assert not scheduling._within_window(None, now - timedelta(seconds=1), now)


def test_collector_capacity_prefers_positive_value(monkeypatch):
    monkeypatch.setattr(scheduling.settings, "scheduler_default_capacity", 2)
    assert scheduling._collector_capacity({"capacity": "5"}) == 5
    assert scheduling._collector_capacity({"max_jobs": "0"}) == 2
    assert scheduling._collector_capacity({"max_concurrent_jobs": "-1"}) == 2
    assert scheduling._collector_capacity({"max_jobs": "bad"}) == 2


def test_network_in_subnet_invalid_inputs():
    assert not scheduling._network_in_subnet(None, "10.0.0.0/8")
    assert not scheduling._network_in_subnet("bad", "10.0.0.0/8")
    assert not scheduling._network_in_subnet("10.0.0.0/24", "bad")


def test_rate_limit_allows_empty_networks(monkeypatch):
    monkeypatch.setattr(
        scheduling.settings, "scheduler_network_rate_limit_per_minute", 1
    )
    session = DummySession([])
    assert scheduling._rate_limit_allows(session, 1, [], datetime.now(UTC))


def test_rate_limit_blocks_when_exceeded(monkeypatch):
    monkeypatch.setattr(
        scheduling.settings, "scheduler_network_rate_limit_per_minute", 1
    )
    monkeypatch.setattr(
        scheduling.settings, "scheduler_network_rate_limit_window_seconds", 60
    )
    now = datetime.now(UTC)
    record = SimpleNamespace(
        tenant_id=1,
        network_id=10,
        window_start_at_utc=now,
        count=1,
        updated_at=now,
    )
    session = DummySession([record])
    assert not scheduling._rate_limit_allows(session, 1, [10], now)


def test_rate_limit_resets_window(monkeypatch):
    monkeypatch.setattr(
        scheduling.settings, "scheduler_network_rate_limit_per_minute", 1
    )
    monkeypatch.setattr(
        scheduling.settings, "scheduler_network_rate_limit_window_seconds", 60
    )
    now = datetime.now(UTC)
    past = now - timedelta(seconds=61)
    record = SimpleNamespace(
        tenant_id=1,
        network_id=10,
        window_start_at_utc=past,
        count=1,
        updated_at=past,
    )
    session = DummySession([record])
    assert scheduling._rate_limit_allows(session, 1, [10], now)
    assert record.count == 1
    assert record.window_start_at_utc == now
