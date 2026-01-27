from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable

from central.db.models import Network, ScanSchedule
from central.db.session import get_session


def build_metrics() -> str:
    lines = []
    lines.extend(_build_network_coverage())
    lines.extend(_build_schedule_adherence())
    return "\n".join(lines) + "\n"


def _build_network_coverage() -> list[str]:
    lines = [
        "# HELP central_network_last_scan_timestamp_seconds Last scheduled scan actual start for network",
        "# TYPE central_network_last_scan_timestamp_seconds gauge",
    ]
    with get_session() as session:
        networks = session.query(Network).all()
        schedules = (
            session.query(ScanSchedule)
            .filter(ScanSchedule.actual_start_at_utc.isnot(None))
            .filter(ScanSchedule.network_ids.isnot(None))
            .all()
        )
    last_scan: dict[int, float] = {}
    for schedule in schedules:
        if not schedule.actual_start_at_utc:
            continue
        timestamp = _to_utc(schedule.actual_start_at_utc).timestamp()
        for network_id in _parse_csv(schedule.network_ids):
            last_scan[network_id] = max(last_scan.get(network_id, 0), timestamp)
    for network in networks:
        timestamp = last_scan.get(network.id, 0.0)
        label = _label(
            tenant_id=str(network.tenant_id),
            site_id=str(network.site_id or ""),
            network_id=str(network.id),
        )
        lines.append(f"central_network_last_scan_timestamp_seconds{{{label}}} {timestamp:.0f}")
    return lines


def _build_schedule_adherence() -> list[str]:
    lines = [
        "# HELP central_scan_schedule_lag_seconds Delay between scheduled and actual start",
        "# TYPE central_scan_schedule_lag_seconds gauge",
    ]
    with get_session() as session:
        schedules = (
            session.query(ScanSchedule)
            .filter(ScanSchedule.actual_start_at_utc.isnot(None))
            .all()
        )
    for schedule in schedules:
        if not schedule.actual_start_at_utc or not schedule.scheduled_at_utc:
            continue
        scheduled = _to_utc(schedule.scheduled_at_utc)
        actual = _to_utc(schedule.actual_start_at_utc)
        lag = (actual - scheduled).total_seconds()
        label = _label(
            tenant_id=str(schedule.tenant_id),
            site_id=str(schedule.site_id or ""),
            schedule_id=str(schedule.id),
        )
        lines.append(f"central_scan_schedule_lag_seconds{{{label}}} {lag:.0f}")
    return lines


def _parse_csv(value: str | None) -> list[int]:
    if not value:
        return []
    ids: list[int] = []
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            ids.append(int(item))
        except ValueError:
            continue
    return ids


def _label(**fields: str) -> str:
    return ",".join(f'{key}="{_escape_label(value)}"' for key, value in fields.items())


def _escape_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _to_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
