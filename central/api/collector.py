from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from central.db.models import (
    Collector,
    CollectorCertificate,
    CollectorEnrollmentToken,
    ScanSchedule,
    ScanScheduleType,
    Site,
)
from central.db.session import get_session
from central.core.logging import log_info, log_warning
from central.core.scheduling import parse_job_id, select_jobs_for_collector
from central.core.rate_limit import CollectorRateLimiter
from central.core.config import settings
from central.api.job_status import job_status_hub
from central.core.ca import CASettings, CertificateAuthority
from central.core.credentials import resolve_credentials

router = APIRouter(prefix="/collectors", tags=["collectors"])
logger = logging.getLogger(__name__)
rate_limiter = CollectorRateLimiter(settings.collector_rate_limit_per_hour)
ca = CertificateAuthority(
    CASettings(
        key_path=settings.ca_key_path,
        cert_path=settings.ca_cert_path,
        ca_valid_days=settings.ca_cert_valid_days,
        cert_valid_days=settings.collector_cert_valid_days,
    )
)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _get_mtls_identity(request: Request) -> dict[str, str]:
    # Expect the reverse proxy to inject verified client cert details.
    serial = request.headers.get("x-client-cert-serial", "")
    fingerprint = request.headers.get("x-client-cert-fingerprint", "")
    return {"serial": serial, "fingerprint": fingerprint}


def _resolve_collector(request: Request) -> Collector | None:
    identity = _get_mtls_identity(request)
    if not identity["serial"] and not identity["fingerprint"]:
        return None
    with get_session() as session:
        query = session.query(Collector)
        if identity["serial"]:
            query = query.filter(Collector.cert_serial == identity["serial"])
        elif identity["fingerprint"]:
            query = query.filter(Collector.cert_fingerprint == identity["fingerprint"])
        return query.one_or_none()


def _apply_rate_limit_key(key: object) -> bool:
    if not rate_limiter.allow(key):
        log_warning(logger, "collector.rate_limited", rate_limit_key=str(key))
        return False
    return True


def _apply_rate_limit(collector: Collector) -> bool:
    if collector.status == "quarantined":
        return False
    if not _apply_rate_limit_key(collector.id):
        with get_session() as session:
            db_collector = session.query(Collector).filter(Collector.id == collector.id).one()
            db_collector.status = "quarantined"
        return False
    return True


def _update_clock_skew(
    collector: Collector, collector_time_utc: str | None, server_time: datetime
) -> None:
    if not collector_time_utc:
        return
    try:
        collector_time = datetime.fromisoformat(collector_time_utc)
    except ValueError:
        return
    if collector_time.tzinfo is None:
        collector_time = collector_time.replace(tzinfo=timezone.utc)
    else:
        collector_time = collector_time.astimezone(timezone.utc)
    skew = int((collector_time - server_time).total_seconds())
    collector.clock_skew_seconds = skew


def _format_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


@router.post("/enroll")
async def enroll(request: Request) -> JSONResponse:
    payload = await request.json()
    token = payload.get("token")
    csr = payload.get("csr")
    if not token or not csr:
        log_warning(logger, "collector.enroll_failed", reason="missing_token_or_csr")
        return JSONResponse({"error": "token and csr are required"}, status_code=400)

    client_key = request.client.host if request.client else "unknown"
    if not _apply_rate_limit_key(client_key):
        return JSONResponse({"error": "rate_limited"}, status_code=429)

    token_hash = _hash_token(token)
    now = datetime.now(timezone.utc)
    with get_session() as session:
        record = (
            session.query(CollectorEnrollmentToken)
            .filter(CollectorEnrollmentToken.token_hash == token_hash)
            .one_or_none()
        )
        if not record or record.used_at or record.expires_at <= now:
            log_warning(logger, "collector.enroll_failed", reason="invalid_or_expired_token")
            return JSONResponse({"error": "invalid or expired token"}, status_code=400)

        collector = Collector(
            tenant_id=record.tenant_id,
            site_id=record.site_id,
            uuid=str(uuid4()),
            name=payload.get("name") or "collector",
            status="active",
            capabilities=payload.get("capabilities"),
            labels=payload.get("labels"),
        )
        session.add(collector)
        session.flush()
        record.used_at = now

        try:
            cert_pem, cert_serial, cert_fingerprint, valid_from, valid_to, ca_pem = (
                ca.issue_certificate(csr)
            )
        except Exception as exc:
            log_warning(logger, "collector.enroll_failed", reason="ca_issue", error=str(exc))
            return JSONResponse({"error": "certificate issuance failed"}, status_code=500)
        collector.cert_serial = cert_serial
        collector.cert_fingerprint = cert_fingerprint
        collector.cert_valid_from = valid_from
        collector.cert_valid_to = valid_to
        session.add(
            CollectorCertificate(
                collector_id=collector.id,
                serial=cert_serial,
                fingerprint=cert_fingerprint,
                valid_from=valid_from,
                valid_to=valid_to,
            )
        )
    log_info(
        logger,
        "collector.enrolled",
        collector_id=collector.uuid,
        tenant_id=collector.tenant_id,
        site_id=collector.site_id,
    )

    return JSONResponse(
        {
            "collector_id": collector.uuid,
            "cert_pem": cert_pem,
            "ca_bundle": ca_pem,
        }
    )


@router.post("/renew")
async def renew(request: Request) -> JSONResponse:
    payload = await request.json()
    csr = payload.get("csr")
    if not csr:
        log_warning(logger, "collector.renew_failed", reason="missing_csr")
        return JSONResponse({"error": "csr is required"}, status_code=400)

    identity = _get_mtls_identity(request)
    if not identity["serial"] and not identity["fingerprint"]:
        log_warning(logger, "collector.renew_failed", reason="missing_mtls_identity")
        return JSONResponse({"error": "mTLS identity required"}, status_code=401)

    now = datetime.now(timezone.utc)
    with get_session() as session:
        query = session.query(Collector)
        if identity["serial"]:
            query = query.filter(Collector.cert_serial == identity["serial"])
        elif identity["fingerprint"]:
            query = query.filter(Collector.cert_fingerprint == identity["fingerprint"])
        collector = query.one_or_none()
        if not collector:
            log_warning(logger, "collector.renew_failed", reason="collector_not_found")
            return JSONResponse({"error": "collector not found"}, status_code=404)
        if not _apply_rate_limit(collector):
            return JSONResponse({"error": "rate_limited"}, status_code=429)

        try:
            cert_pem, cert_serial, cert_fingerprint, valid_from, valid_to, ca_pem = (
                ca.issue_certificate(csr)
            )
        except Exception as exc:
            log_warning(logger, "collector.renew_failed", reason="ca_issue", error=str(exc))
            return JSONResponse({"error": "certificate issuance failed"}, status_code=500)
        collector.cert_serial = cert_serial
        collector.cert_fingerprint = cert_fingerprint
        collector.cert_valid_from = valid_from
        collector.cert_valid_to = valid_to
        session.add(
            CollectorCertificate(
                collector_id=collector.id,
                serial=cert_serial,
                fingerprint=cert_fingerprint,
                valid_from=valid_from,
                valid_to=valid_to,
            )
        )
    log_info(
        logger,
        "collector.renewed",
        collector_id=collector.uuid,
        tenant_id=collector.tenant_id,
        site_id=collector.site_id,
    )

    return JSONResponse(
        {
            "cert_pem": cert_pem,
            "ca_bundle": ca_pem,
        }
    )


@router.get("/jobs/poll")
def poll_jobs(request: Request) -> JSONResponse:
    collector = _resolve_collector(request)
    if not collector:
        log_warning(logger, "collector.poll_failed", reason="missing_mtls_identity")
        return JSONResponse({"error": "mTLS identity required"}, status_code=401)
    if not _apply_rate_limit(collector):
        return JSONResponse({"error": "rate_limited"}, status_code=429)
    now = datetime.now(timezone.utc)
    with get_session() as session:
        db_collector = session.query(Collector).filter(Collector.id == collector.id).one()
        db_collector.last_seen_utc = now
        schedule_type_id = parse_job_id(job_id)
        if schedule_type_id is not None:
            entry = (
                session.query(ScanScheduleType)
                .filter(ScanScheduleType.id == schedule_type_id)
                .one_or_none()
            )
            if entry and entry.actual_start_at_utc is None:
                entry.actual_start_at_utc = now
                schedule = (
                    session.query(ScanSchedule)
                    .filter(ScanSchedule.id == entry.schedule_id)
                    .one_or_none()
                )
                if schedule and schedule.actual_start_at_utc is None:
                    schedule.actual_start_at_utc = now
        site = None
        if db_collector.site_id:
            site = session.query(Site).filter(Site.id == db_collector.site_id).one_or_none()
        jobs = select_jobs_for_collector(
            session=session,
            collector=db_collector,
            now=now,
            max_jobs=settings.scheduler_max_jobs_per_poll,
        )
    log_info(
        logger,
        "collector.poll",
        collector_id=collector.uuid,
        tenant_id=collector.tenant_id,
        site_id=collector.site_id,
    )
    return JSONResponse(
        {
            "jobs": [
                {
                    "job_id": entry.job_id,
                    "scan_type": entry.scan_type,
                    "targets": entry.targets,
                    "params": entry.params,
                    "expires_at": _format_utc(entry.expires_at) if entry.expires_at else None,
                }
                for entry in jobs
            ],
            "server_time_utc": _format_utc(now),
            "site": (
                {"id": site.id, "name": site.name, "timezone": site.timezone}
                if site
                else None
            ),
        }
    )


@router.post("/jobs/ack")
async def acknowledge_job(request: Request) -> JSONResponse:
    collector = _resolve_collector(request)
    if not collector:
        log_warning(logger, "collector.ack_failed", reason="missing_mtls_identity")
        return JSONResponse({"error": "mTLS identity required"}, status_code=401)
    if not _apply_rate_limit(collector):
        return JSONResponse({"error": "rate_limited"}, status_code=429)
    payload: dict[str, Any] = await request.json()
    job_id = payload.get("job_id")
    if not job_id:
        log_warning(logger, "collector.ack_failed", reason="missing_job_id")
        return JSONResponse({"error": "job_id is required"}, status_code=400)
    now = datetime.now(timezone.utc)
    with get_session() as session:
        db_collector = session.query(Collector).filter(Collector.id == collector.id).one()
        db_collector.last_seen_utc = now
    log_info(
        logger,
        "collector.job_acknowledged",
        collector_id=collector.uuid,
        job_id=job_id,
    )
    await job_status_hub.broadcast(
        job_id,
        {
            "job_id": job_id,
            "status": "acknowledged",
            "collector_id": collector.uuid,
            "server_time_utc": _format_utc(now),
        },
    )
    return JSONResponse({"status": "acknowledged", "server_time_utc": _format_utc(now)})


@router.post("/jobs/result")
async def submit_result(request: Request) -> JSONResponse:
    collector = _resolve_collector(request)
    if not collector:
        log_warning(logger, "collector.result_failed", reason="missing_mtls_identity")
        return JSONResponse({"error": "mTLS identity required"}, status_code=401)
    if not _apply_rate_limit(collector):
        return JSONResponse({"error": "rate_limited"}, status_code=429)
    payload: dict[str, Any] = await request.json()
    job_id = payload.get("job_id")
    if not job_id:
        log_warning(logger, "collector.result_failed", reason="missing_job_id")
        return JSONResponse({"error": "job_id is required"}, status_code=400)
    now = datetime.now(timezone.utc)
    collector_time = payload.get("collector_time_utc")
    with get_session() as session:
        db_collector = session.query(Collector).filter(Collector.id == collector.id).one()
        db_collector.last_seen_utc = now
        _update_clock_skew(db_collector, collector_time, now)
        schedule_type_id = parse_job_id(job_id)
        if schedule_type_id is not None:
            entry = (
                session.query(ScanScheduleType)
                .filter(ScanScheduleType.id == schedule_type_id)
                .one_or_none()
            )
            if entry and entry.finished_at_utc is None:
                entry.finished_at_utc = now
                schedule = (
                    session.query(ScanSchedule)
                    .filter(ScanSchedule.id == entry.schedule_id)
                    .one_or_none()
                )
                if schedule and schedule.finished_at_utc is None:
                    pending = (
                        session.query(ScanScheduleType)
                        .filter(ScanScheduleType.schedule_id == schedule.id)
                        .filter(ScanScheduleType.finished_at_utc.is_(None))
                        .count()
                    )
                    if pending == 0:
                        schedule.finished_at_utc = now
    log_info(
        logger,
        "collector.result_accepted",
        collector_id=collector.uuid,
        job_id=job_id,
    )
    await job_status_hub.broadcast(
        job_id,
        {
            "job_id": job_id,
            "status": "completed",
            "collector_id": collector.uuid,
            "result_count": len(payload.get("results") or []),
            "server_time_utc": _format_utc(now),
        },
    )
    return JSONResponse({"status": "accepted", "server_time_utc": _format_utc(now)})


@router.post("/jobs/status")
async def submit_job_status(request: Request) -> JSONResponse:
    collector = _resolve_collector(request)
    if not collector:
        log_warning(logger, "collector.status_failed", reason="missing_mtls_identity")
        return JSONResponse({"error": "mTLS identity required"}, status_code=401)
    if not _apply_rate_limit(collector):
        return JSONResponse({"error": "rate_limited"}, status_code=429)
    payload: dict[str, Any] = await request.json()
    job_id = payload.get("job_id")
    status = payload.get("status")
    if not job_id or not status:
        return JSONResponse({"error": "job_id and status are required"}, status_code=400)
    now = datetime.now(timezone.utc)
    await job_status_hub.broadcast(
        job_id,
        {
            "job_id": job_id,
            "status": status,
            "collector_id": collector.uuid,
            "detail": payload.get("detail"),
            "progress": payload.get("progress"),
            "server_time_utc": _format_utc(now),
        },
    )
    return JSONResponse({"status": "accepted", "server_time_utc": _format_utc(now)})


@router.post("/credentials/resolve")
async def resolve_collector_credentials(request: Request) -> JSONResponse:
    collector = _resolve_collector(request)
    if not collector:
        log_warning(logger, "collector.credentials_failed", reason="missing_mtls_identity")
        return JSONResponse({"error": "mTLS identity required"}, status_code=401)
    if not _apply_rate_limit(collector):
        return JSONResponse({"error": "rate_limited"}, status_code=429)
    payload: dict[str, Any] = await request.json()
    protocol = payload.get("protocol")
    targets = payload.get("targets") or []
    if not protocol or not isinstance(targets, list):
        return JSONResponse({"error": "protocol and targets are required"}, status_code=400)
    credentials = resolve_credentials(collector.tenant_id, protocol, targets)
    return JSONResponse({"credentials": credentials})


@router.post("/schedules/{schedule_id}/types/{type_id}/status")
async def update_schedule_type_status(
    schedule_id: int, type_id: int, request: Request
) -> JSONResponse:
    collector = _resolve_collector(request)
    if not collector:
        log_warning(logger, "collector.schedule_type_update_failed", reason="missing_mtls_identity")
        return JSONResponse({"error": "mTLS identity required"}, status_code=401)
    if not _apply_rate_limit(collector):
        return JSONResponse({"error": "rate_limited"}, status_code=429)
    payload = await request.json()
    actual_start_at = payload.get("actual_start_at_utc") or payload.get("actual_start_at")
    finished_at = payload.get("finished_at_utc") or payload.get("finished_at")
    collector_time = payload.get("collector_time_utc")

    def parse_dt(value: str | None) -> datetime | None:
        if not value:
            return None
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None

    actual_dt = parse_dt(actual_start_at)
    finished_dt = parse_dt(finished_at)
    if actual_start_at and actual_dt is None:
        log_warning(logger, "collector.schedule_type_update_failed", reason="invalid_actual_start")
        return JSONResponse({"error": "Invalid actual_start_at_utc"}, status_code=400)
    if finished_at and finished_dt is None:
        log_warning(logger, "collector.schedule_type_update_failed", reason="invalid_finished_at")
        return JSONResponse({"error": "Invalid finished_at_utc"}, status_code=400)

    now = datetime.now(timezone.utc)
    with get_session() as session:
        db_collector = session.query(Collector).filter(Collector.id == collector.id).one()
        db_collector.last_seen_utc = now
        _update_clock_skew(db_collector, collector_time, now)
        entry = (
            session.query(ScanScheduleType)
            .filter(ScanScheduleType.id == type_id)
            .one_or_none()
        )
        if not entry:
            return JSONResponse({"error": "Scan type entry not found"}, status_code=404)
        schedule = (
            session.query(ScanSchedule)
            .filter(ScanSchedule.id == entry.schedule_id)
            .one_or_none()
        )
        site = None
        if schedule and schedule.site_id:
            site = session.query(Site).filter(Site.id == schedule.site_id).one_or_none()
        if actual_dt:
            entry.actual_start_at_utc = actual_dt
        if finished_dt:
            entry.finished_at_utc = finished_dt
    log_info(
        logger,
        "collector.schedule_type_updated",
        collector_id=collector.uuid,
        schedule_id=schedule_id,
        type_id=type_id,
    )

    return JSONResponse(
        {
            "status": "updated",
            "type_id": type_id,
            "server_time_utc": _format_utc(now),
            "site": (
                {"id": site.id, "name": site.name, "timezone": site.timezone}
                if site
                else None
            ),
        }
    )


@router.post("/schedules/{schedule_id}/status")
async def update_schedule_status(schedule_id: int, request: Request) -> JSONResponse:
    collector = _resolve_collector(request)
    if not collector:
        log_warning(logger, "collector.schedule_update_failed", reason="missing_mtls_identity")
        return JSONResponse({"error": "mTLS identity required"}, status_code=401)
    if not _apply_rate_limit(collector):
        return JSONResponse({"error": "rate_limited"}, status_code=429)
    payload = await request.json()
    actual_start_at = payload.get("actual_start_at_utc") or payload.get("actual_start_at")
    finished_at = payload.get("finished_at_utc") or payload.get("finished_at")
    collector_time = payload.get("collector_time_utc")

    def parse_dt(value: str | None) -> datetime | None:
        if not value:
            return None
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None

    actual_dt = parse_dt(actual_start_at)
    finished_dt = parse_dt(finished_at)
    if actual_start_at and actual_dt is None:
        log_warning(logger, "collector.schedule_update_failed", reason="invalid_actual_start")
        return JSONResponse({"error": "Invalid actual_start_at_utc"}, status_code=400)
    if finished_at and finished_dt is None:
        log_warning(logger, "collector.schedule_update_failed", reason="invalid_finished_at")
        return JSONResponse({"error": "Invalid finished_at_utc"}, status_code=400)

    now = datetime.now(timezone.utc)
    with get_session() as session:
        db_collector = session.query(Collector).filter(Collector.id == collector.id).one()
        db_collector.last_seen_utc = now
        _update_clock_skew(db_collector, collector_time, now)
        schedule = (
            session.query(ScanSchedule)
            .filter(ScanSchedule.id == schedule_id)
            .one_or_none()
        )
        if not schedule:
            return JSONResponse({"error": "Schedule not found"}, status_code=404)
        site = None
        if schedule.site_id:
            site = session.query(Site).filter(Site.id == schedule.site_id).one_or_none()
        if actual_dt:
            schedule.actual_start_at_utc = actual_dt
        if finished_dt:
            schedule.finished_at_utc = finished_dt
    log_info(
        logger,
        "collector.schedule_updated",
        collector_id=collector.uuid,
        schedule_id=schedule_id,
    )

    return JSONResponse(
        {
            "status": "updated",
            "schedule_id": schedule_id,
            "server_time_utc": _format_utc(now),
            "site": (
                {"id": site.id, "name": site.name, "timezone": site.timezone}
                if site
                else None
            ),
        }
    )
