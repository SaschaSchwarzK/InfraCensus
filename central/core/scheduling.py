from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
from typing import Iterable

from sqlalchemy.orm import joinedload, Session
from sqlalchemy import or_

from central.core.config import settings
from central.db.models import (
    Collector,
    CollectorAffinity,
    Network,
    NetworkRateLimit,
    ScanSchedule,
    ScanScheduleType,
)


@dataclass(frozen=True)
class JobSpec:
    job_id: str
    scan_type: str
    targets: list[str]
    params: dict[str, str | int | float | bool | None | list[str]]
    expires_at: datetime | None


def select_jobs_for_collector(
    session: Session,
    collector: Collector,
    now: datetime,
    max_jobs: int,
) -> list[JobSpec]:
    if max_jobs <= 0:
        return []
    capabilities = _parse_csv(collector.capabilities)
    labels = _parse_labels(collector.labels)
    capacity = _collector_capacity(labels)
    inflight = _collector_inflight(session, collector.id)
    remaining = min(max_jobs, max(0, capacity - inflight))
    if remaining <= 0:
        return []

    _release_stale_assignments(session, now)
    affinities = (
        session.query(CollectorAffinity)
        .filter(CollectorAffinity.tenant_id == collector.tenant_id)
        .all()
    )

    candidates = (
        session.query(ScanScheduleType)
        .join(ScanSchedule)
        .options(joinedload(ScanScheduleType.schedule))
        .filter(ScanSchedule.tenant_id == collector.tenant_id)
        .filter(ScanSchedule.finished_at_utc.is_(None))
        .filter(ScanScheduleType.finished_at_utc.is_(None))
        .filter(ScanScheduleType.actual_start_at_utc.is_(None))
        .filter(ScanScheduleType.assigned_collector_id.is_(None))
        .filter(ScanScheduleType.scheduled_at_utc <= now)
        .filter(or_(ScanScheduleType.not_before_utc.is_(None), ScanScheduleType.not_before_utc <= now))
        .filter(or_(ScanScheduleType.not_after_utc.is_(None), ScanScheduleType.not_after_utc >= now))
        .order_by(ScanScheduleType.priority.desc(), ScanScheduleType.scheduled_at_utc.asc(), ScanScheduleType.id.asc())
        .all()
    )

    jobs: list[JobSpec] = []
    for entry in candidates:
        schedule = entry.schedule
        if schedule is None:
            continue
        if not _within_window(schedule.not_before_utc, schedule.not_after_utc, now):
            continue
        if schedule.site_id is not None and collector.site_id != schedule.site_id:
            continue
        if capabilities and entry.scan_type not in capabilities:
            continue
        network_ids = _parse_csv(schedule.network_ids)
        if not network_ids:
            continue
        network_map = _load_networks(session, network_ids)
        targets = [net.cidr for net in network_map.values() if net.cidr]
        if not targets:
            continue
        if not _affinity_allows(collector, entry.scan_type, network_map, affinities):
            continue
        network_id_list = [net.id for net in network_map.values()]
        if not _rate_limit_allows(session, schedule.tenant_id, network_id_list, now):
            continue

        job_id = f"schedule_type:{entry.id}"
        entry.assigned_collector_id = collector.id
        entry.assigned_at_utc = now
        params: dict[str, str | int | float | bool | None | list[str]] = {
            "schedule_id": schedule.id,
            "schedule_type_id": entry.id,
            "tenant_id": schedule.tenant_id,
            "site_id": schedule.site_id,
            "network_ids": [str(nid) for nid in network_ids],
            "priority": entry.priority,
            "rate_limit_per_minute": settings.scheduler_network_rate_limit_per_minute,
            "rate_limit_window_seconds": settings.scheduler_network_rate_limit_window_seconds,
        }
        jobs.append(
            JobSpec(
                job_id=job_id,
                scan_type=entry.scan_type,
                targets=targets,
                params=params,
                expires_at=entry.not_after_utc or schedule.not_after_utc,
            )
        )
        if len(jobs) >= remaining:
            break
    return jobs


def parse_job_id(job_id: str) -> int | None:
    if not job_id:
        return None
    prefix = "schedule_type:"
    if not job_id.startswith(prefix):
        return None
    try:
        return int(job_id[len(prefix):])
    except ValueError:
        return None


def _release_stale_assignments(session: Session, now: datetime) -> None:
    cutoff = now.timestamp() - settings.scheduler_job_assignment_ttl_seconds
    stale_before = datetime.fromtimestamp(cutoff, tz=timezone.utc)
    session.query(ScanScheduleType).filter(
        ScanScheduleType.assigned_at_utc.isnot(None),
        ScanScheduleType.assigned_at_utc < stale_before,
        ScanScheduleType.actual_start_at_utc.is_(None),
        ScanScheduleType.finished_at_utc.is_(None),
    ).update(
        {
            ScanScheduleType.assigned_collector_id: None,
            ScanScheduleType.assigned_at_utc: None,
        },
        synchronize_session=False,
    )


def _collector_inflight(session: Session, collector_id: int) -> int:
    return (
        session.query(ScanScheduleType)
        .filter(ScanScheduleType.assigned_collector_id == collector_id)
        .filter(ScanScheduleType.finished_at_utc.is_(None))
        .count()
    )


def _rate_limit_allows(
    session: Session, tenant_id: int, network_ids: list[int], now: datetime
) -> bool:
    if settings.scheduler_network_rate_limit_per_minute <= 0:
        return True
    if not network_ids:
        return True
    records = (
        session.query(NetworkRateLimit)
        .filter(NetworkRateLimit.network_id.in_(network_ids))
        .all()
    )
    record_map = {record.network_id: record for record in records}
    for network_id in network_ids:
        record = record_map.get(network_id)
        if not record:
            continue
        window_start = record.window_start_at_utc
        if (now - window_start).total_seconds() >= settings.scheduler_network_rate_limit_window_seconds:
            record.window_start_at_utc = now
            record.count = 0
        if record.count + 1 > settings.scheduler_network_rate_limit_per_minute:
            return False
    for network_id in network_ids:
        record = record_map.get(network_id)
        if record is None:
            record = NetworkRateLimit(
                tenant_id=tenant_id,
                network_id=network_id,
                window_start_at_utc=now,
                count=1,
                updated_at=now,
            )
            session.add(record)
            record_map[network_id] = record
        else:
            record.count += 1
            record.updated_at = now
    return True


def _collector_capacity(labels: dict[str, str]) -> int:
    for key in ("capacity", "max_jobs", "max_concurrent_jobs"):
        if key in labels:
            try:
                value = int(labels[key])
                if value > 0:
                    return value
            except ValueError:
                continue
    return settings.scheduler_default_capacity


def _parse_csv(value: str | None) -> list[int]:
    if not value:
        return []
    values: list[int] = []
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            values.append(int(item))
        except ValueError:
            continue
    return values


def _parse_labels(raw: str | None) -> dict[str, str]:
    labels: dict[str, str] = {}
    if not raw:
        return labels
    for entry in raw.split(","):
        if not entry.strip():
            continue
        key, _, value = entry.partition("=")
        if not key:
            continue
        labels[key.strip()] = value.strip()
    return labels


def _within_window(not_before: datetime | None, not_after: datetime | None, now: datetime) -> bool:
    if not_before and now < not_before:
        return False
    if not_after and now > not_after:
        return False
    return True


def _load_networks(session: Session, network_ids: list[int]) -> dict[int, Network]:
    if not network_ids:
        return {}
    records = (
        session.query(Network)
        .filter(Network.id.in_(network_ids))
        .all()
    )
    return {record.id: record for record in records}


def _affinity_allows(
    collector: Collector,
    scan_type: str,
    networks: dict[int, Network],
    affinities: list[CollectorAffinity],
) -> bool:
    if not affinities:
        return True
    for network in networks.values():
        matches = []
        for affinity in affinities:
            if affinity.scan_type and affinity.scan_type != scan_type:
                continue
            if affinity.network_id is not None and affinity.network_id == network.id:
                matches.append(affinity)
                continue
            if affinity.subnet_cidr:
                if _network_in_subnet(network.cidr, affinity.subnet_cidr):
                    matches.append(affinity)
        if not matches:
            continue
        max_priority = max(entry.priority for entry in matches)
        if not any(
            entry.collector_id == collector.id and entry.priority == max_priority
            for entry in matches
        ):
            return False
    return True


def _network_in_subnet(network_cidr: str | None, affinity_cidr: str) -> bool:
    if not network_cidr:
        return False
    try:
        network = ipaddress.ip_network(network_cidr, strict=False)
        affinity_net = ipaddress.ip_network(affinity_cidr, strict=False)
    except ValueError:
        return False
    return network.subnet_of(affinity_net)
