from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

from central.core.config import settings
from central.core.parsing import parse_int_list
from central.db.models import Collector, Network, ScanSchedule, ScanScheduleType
from central.db.session import get_session

generate_latest: Callable[[], bytes] | None = None
try:
    from prometheus_client import generate_latest
except (ImportError, ModuleNotFoundError):  # pragma: no cover - optional dependency
    generate_latest = None


def build_metrics() -> str:
    lines = []
    lines.extend(_build_network_coverage())
    lines.extend(_build_schedule_adherence())
    lines.extend(_build_schedule_queue_depth())
    lines.extend(_build_collector_health())
    lines.extend(_build_prometheus_metrics())
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
        for network_id in parse_int_list(schedule.network_ids):
            last_scan[network_id] = max(last_scan.get(network_id, 0), timestamp)
    for network in networks:
        timestamp = last_scan.get(network.id, 0.0)
        label = _label(
            tenant_id=str(network.tenant_id),
            site_id=str(network.site_id or ""),
            network_id=str(network.id),
        )
        lines.append(
            f"central_network_last_scan_timestamp_seconds{{{label}}} {timestamp:.0f}"
        )
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


def _build_schedule_queue_depth() -> list[str]:
    lines = [
        "# HELP central_scan_schedule_pending_total Pending schedule types not yet assigned",
        "# TYPE central_scan_schedule_pending_total gauge",
        "# HELP central_scan_schedule_inflight_total Schedule types assigned but not finished",
        "# TYPE central_scan_schedule_inflight_total gauge",
        "# HELP central_scan_schedule_overdue_total Schedule types past not_after_utc without completion",
        "# TYPE central_scan_schedule_overdue_total gauge",
    ]
    now = datetime.now(UTC)
    with get_session() as session:
        schedules = (
            session.query(ScanSchedule)
            .filter(ScanSchedule.finished_at_utc.is_(None))
            .all()
        )
        schedule_ids = [schedule.id for schedule in schedules]
        types = (
            session.query(ScanScheduleType)
            .filter(ScanScheduleType.schedule_id.in_(schedule_ids))
            .all()
            if schedule_ids
            else []
        )
    type_map: dict[int, list[ScanScheduleType]] = {}
    for entry in types:
        type_map.setdefault(entry.schedule_id, []).append(entry)
    for schedule in schedules:
        schedule_id = str(schedule.id)
        label = _label(
            tenant_id=str(schedule.tenant_id),
            site_id=str(schedule.site_id or ""),
            schedule_id=schedule_id,
        )
        pending = 0
        inflight = 0
        overdue = 0
        for entry in type_map.get(schedule.id, []):
            if entry.finished_at_utc is not None:
                continue
            if entry.assigned_collector_id is None:
                pending += 1
            else:
                inflight += 1
            if entry.not_after_utc and entry.not_after_utc < now:
                overdue += 1
        lines.append(f"central_scan_schedule_pending_total{{{label}}} {pending}")
        lines.append(f"central_scan_schedule_inflight_total{{{label}}} {inflight}")
        lines.append(f"central_scan_schedule_overdue_total{{{label}}} {overdue}")
    return lines


def _is_collector_healthy(collector: Collector, now: datetime) -> int:
    """Determine if collector is healthy based on status and last seen time."""
    if collector.status != "active" or not collector.last_seen_utc:
        return 0
    age_seconds = (now - _to_utc(collector.last_seen_utc)).total_seconds()
    return 1 if age_seconds <= settings.collector_quarantine_seconds else 0


def _build_collector_health() -> list[str]:
    lines = [
        "# HELP central_collector_last_seen_timestamp_seconds Last time collector checked in",
        "# TYPE central_collector_last_seen_timestamp_seconds gauge",
        "# HELP central_collector_status Active collectors (1) vs inactive (0)",
        "# TYPE central_collector_status gauge",
        "# HELP central_collector_health Collector health (1=healthy, 0=unhealthy)",
        "# TYPE central_collector_health gauge",
    ]
    with get_session() as session:
        collectors = session.query(Collector).all()
    now = datetime.now(UTC)
    for collector in collectors:
        last_seen = collector.last_seen_utc
        timestamp = _to_utc(last_seen).timestamp() if last_seen else 0.0
        status_value = 1 if collector.status == "active" else 0
        healthy = _is_collector_healthy(collector, now)
        
        label = _label(
            tenant_id=str(collector.tenant_id),
            collector_id=str(collector.uuid),
            status=str(collector.status),
        )
        lines.append(
            f"central_collector_last_seen_timestamp_seconds{{{label}}} {timestamp:.0f}"
        )
        lines.append(f"central_collector_status{{{label}}} {status_value}")
        lines.append(f"central_collector_health{{{label}}} {healthy}")
    return lines


def _build_prometheus_metrics() -> list[str]:
    if generate_latest is None:
        return []
    payload = generate_latest().decode("utf-8")
    return [line for line in payload.splitlines() if line]


def _label(**fields: str) -> str:
    return ",".join(f'{key}="{_escape_label(value)}"' for key, value in fields.items())


def _escape_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _to_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
