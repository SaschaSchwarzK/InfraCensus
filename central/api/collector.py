from __future__ import annotations

import asyncio
import hashlib
import logging
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from central.api.job_status import job_status_hub
from central.core.audit import log_security_event
from central.core.ca import CertificateAuthority
from central.core.config import settings
from central.core.credentials import resolve_credentials
from central.core.logging import log_info, log_warning, set_log_context
from central.core.metrics import (
    job_completed_counter,
    job_duration_histogram,
    job_failed_counter,
)
from central.core.parsing import (
    format_utc,
    parse_iso8601,
    parse_labels,
    parse_optional_str_list,
)
from central.core.rate_limit import CollectorRateLimiter
from central.core.scheduling import JobSpec, parse_job_id, select_jobs_for_collector
from central.db.models import (
    Collector,
    CollectorCertificate,
    CollectorEnrollmentToken,
    ScanSchedule,
    ScanScheduleType,
    Site,
)
from central.db.session import get_session

router = APIRouter(prefix="/collectors", tags=["collectors"])
logger = logging.getLogger(__name__)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _get_rate_limiter(request: Request) -> CollectorRateLimiter:
    return request.app.state.rate_limiter


def _get_ca(request: Request) -> CertificateAuthority:
    return request.app.state.ca


def _get_mtls_identity(request: Request) -> dict[str, str]:
    # Expect the reverse proxy to inject verified client cert details.
    serial = request.headers.get("x-client-cert-serial", "")
    fingerprint = request.headers.get("x-client-cert-fingerprint", "")
    return {"serial": serial, "fingerprint": fingerprint}


def _validate_timestamp(request: Request) -> None:
    client_timestamp = request.headers.get("x-timestamp")
    if not client_timestamp:
        raise HTTPException(status_code=400, detail="Missing x-timestamp header")
    client_time = parse_iso8601(client_timestamp)
    if client_time is None:
        raise HTTPException(status_code=400, detail="Invalid timestamp format")
    server_time = datetime.now(UTC)
    skew = abs((server_time - client_time).total_seconds())
    if skew > settings.collector_clock_skew_max_seconds:
        raise HTTPException(
            status_code=403, detail=f"Clock skew too large: {int(skew)}s"
        )


async def _resolve_collector(request: Request) -> Collector | None:
    identity = _get_mtls_identity(request)
    if not identity["serial"] and not identity["fingerprint"]:
        return None

    def _load() -> Collector | None:
        with get_session() as session:
            query = session.query(Collector)
            if identity["serial"]:
                query = query.filter(Collector.cert_serial == identity["serial"])
            elif identity["fingerprint"]:
                query = query.filter(
                    Collector.cert_fingerprint == identity["fingerprint"]
                )
            return query.one_or_none()

    return await asyncio.to_thread(_load)


async def _apply_rate_limit_key(
    rate_limiter: CollectorRateLimiter, key: object
) -> bool:
    if not await rate_limiter.allow(key):
        log_warning(logger, "collector.rate_limited", rate_limit_key=str(key))
        return False
    return True


async def _apply_rate_limit(
    collector: Collector, rate_limiter: CollectorRateLimiter
) -> bool:
    if collector.status == "quarantined":
        return False
    if not await _apply_rate_limit_key(rate_limiter, collector.id):
        return False
    return True


def _update_clock_skew(
    collector: Collector, collector_time_utc: str | None, server_time: datetime
) -> None:
    collector_time = _parse_collector_time(collector_time_utc)
    if collector_time is None:
        return
    skew = int((collector_time - server_time).total_seconds())
    collector.clock_skew_seconds = skew


def _parse_collector_time(collector_time_utc: str | None) -> datetime | None:
    return parse_iso8601(collector_time_utc)


def _enforce_clock_skew(
    collector_time_utc: str | None, server_time: datetime
) -> tuple[bool, int | None]:
    collector_time = _parse_collector_time(collector_time_utc)
    if collector_time is None:
        return False, None
    skew = int((collector_time - server_time).total_seconds())
    if abs(skew) > settings.collector_clock_skew_max_seconds:
        return False, skew
    return True, skew


def _format_utc(value: datetime) -> str:
    return format_utc(value)


@router.post("/enroll")
async def enroll(request: Request) -> JSONResponse:
    payload = await request.json()
    token = payload.get("token")
    csr = payload.get("csr")
    if not token or not csr:
        log_warning(logger, "collector.enroll_failed", reason="missing_token_or_csr")
        log_security_event(
            action="collector.enroll",
            outcome="denied",
            details={
                "reason": "missing_token_or_csr",
                "ip": request.client.host if request.client else None,
                "user_agent": request.headers.get("user-agent"),
            },
        )
        return JSONResponse({"error": "token and csr are required"}, status_code=400)

    client_key = request.client.host if request.client else "unknown"
    rate_limiter = _get_rate_limiter(request)
    if not await _apply_rate_limit_key(rate_limiter, client_key):
        log_security_event(
            action="collector.enroll",
            outcome="denied",
            details={
                "reason": "rate_limited",
                "ip": request.client.host if request.client else None,
            },
        )
        return JSONResponse({"error": "rate_limited"}, status_code=429)

    ca = _get_ca(request)
    token_hash = _hash_token(token)
    now = datetime.now(UTC)

    def _enroll_db() -> tuple[str, str, str, int, int | None]:
        with get_session() as session:
            record = (
                session.query(CollectorEnrollmentToken)
                .filter(CollectorEnrollmentToken.token_hash == token_hash)
                .one_or_none()
            )
            if not record or record.used_at or record.expires_at <= now:
                raise RuntimeError("invalid_or_expired_token")
            collector = Collector(
                tenant_id=record.tenant_id,
                site_id=record.site_id,
                uuid=str(uuid4()),
                name=payload.get("name") or "collector",
                status="active",
                capabilities=parse_optional_str_list(payload.get("capabilities")),
                labels=parse_labels(payload.get("labels")),
            )
            session.add(collector)
            session.flush()
            record.used_at = now
            cert_pem, cert_serial, cert_fingerprint, valid_from, valid_to, ca_pem = (
                ca.issue_certificate(csr)
            )
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
            return collector.uuid, cert_pem, ca_pem, record.tenant_id, record.site_id

    try:
        collector_uuid, cert_pem, ca_pem, tenant_id, site_id = await asyncio.to_thread(
            _enroll_db
        )
    except RuntimeError:
        log_warning(
            logger, "collector.enroll_failed", reason="invalid_or_expired_token"
        )
        log_security_event(
            action="collector.enroll",
            outcome="denied",
            details={
                "reason": "invalid_or_expired_token",
                "ip": request.client.host if request.client else None,
            },
        )
        return JSONResponse({"error": "invalid or expired token"}, status_code=400)
    except (TypeError, ValueError) as exc:
        log_warning(
            logger, "collector.enroll_failed", reason="ca_issue", error=str(exc)
        )
        log_security_event(
            action="collector.enroll",
            outcome="error",
            details={
                "reason": "certificate_issue",
                "ip": request.client.host if request.client else None,
            },
        )
        return JSONResponse({"error": "certificate issuance failed"}, status_code=400)
    set_log_context(tenant_id=str(tenant_id))
    log_info(
        logger,
        "collector.enrolled",
        collector_id=collector_uuid,
        tenant_id=tenant_id,
        site_id=site_id,
    )

    return JSONResponse(
        {
            "collector_id": collector_uuid,
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
        log_security_event(
            action="collector.renew",
            outcome="denied",
            details={"reason": "missing_csr"},
        )
        return JSONResponse({"error": "csr is required"}, status_code=400)

    identity = _get_mtls_identity(request)
    if not identity["serial"] and not identity["fingerprint"]:
        log_warning(logger, "collector.renew_failed", reason="missing_mtls_identity")
        log_security_event(
            action="collector.renew",
            outcome="denied",
            details={"reason": "missing_mtls_identity"},
        )
        return JSONResponse({"error": "mTLS identity required"}, status_code=401)

    def _load_collector() -> Collector | None:
        with get_session() as session:
            query = session.query(Collector)
            if identity["serial"]:
                query = query.filter(Collector.cert_serial == identity["serial"])
            elif identity["fingerprint"]:
                query = query.filter(
                    Collector.cert_fingerprint == identity["fingerprint"]
                )
            return query.one_or_none()

    collector = await asyncio.to_thread(_load_collector)
    if not collector:
        log_warning(logger, "collector.renew_failed", reason="collector_not_found")
        log_security_event(
            action="collector.renew",
            outcome="denied",
            details={"reason": "collector_not_found"},
        )
        return JSONResponse({"error": "collector not found"}, status_code=404)
    set_log_context(tenant_id=str(collector.tenant_id), collector_id=collector.uuid)
    rate_limiter = _get_rate_limiter(request)
    if not await _apply_rate_limit(collector, rate_limiter):
        log_security_event(
            action="collector.renew",
            outcome="denied",
            actor_user_id=None,
            details={
                "reason": "rate_limited",
                "collector_id": collector.uuid,
                "tenant_id": collector.tenant_id,
            },
        )
        return JSONResponse({"error": "rate_limited"}, status_code=429)

    ca = _get_ca(request)

    def _renew_db() -> tuple[str, str]:
        with get_session() as session:
            db_collector = (
                session.query(Collector).filter(Collector.id == collector.id).one()
            )
            cert_pem, cert_serial, cert_fingerprint, valid_from, valid_to, ca_pem = (
                ca.issue_certificate(csr)
            )
            db_collector.cert_serial = cert_serial
            db_collector.cert_fingerprint = cert_fingerprint
            db_collector.cert_valid_from = valid_from
            db_collector.cert_valid_to = valid_to
            session.add(
                CollectorCertificate(
                    collector_id=db_collector.id,
                    serial=cert_serial,
                    fingerprint=cert_fingerprint,
                    valid_from=valid_from,
                    valid_to=valid_to,
                )
            )
            return cert_pem, ca_pem

    try:
        cert_pem, ca_pem = await asyncio.to_thread(_renew_db)
    except (TypeError, ValueError) as exc:
        log_warning(logger, "collector.renew_failed", reason="ca_issue", error=str(exc))
        log_security_event(
            action="collector.renew",
            outcome="error",
            details={"reason": "certificate_issue", "collector_id": collector.uuid},
        )
        return JSONResponse({"error": "certificate issuance failed"}, status_code=400)
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
async def poll_jobs(request: Request) -> JSONResponse:
    collector = await _resolve_collector(request)
    if not collector:
        log_warning(logger, "collector.poll_failed", reason="missing_mtls_identity")
        log_security_event(
            action="collector.poll",
            outcome="denied",
            details={"reason": "missing_mtls_identity"},
        )
        return JSONResponse({"error": "mTLS identity required"}, status_code=401)
    _validate_timestamp(request)
    set_log_context(tenant_id=str(collector.tenant_id), collector_id=collector.uuid)
    rate_limiter = _get_rate_limiter(request)
    if not await _apply_rate_limit(collector, rate_limiter):
        log_security_event(
            action="collector.poll",
            outcome="denied",
            details={"reason": "rate_limited", "collector_id": collector.uuid},
        )
        return JSONResponse({"error": "rate_limited"}, status_code=429)
    now = datetime.now(UTC)

    def _poll_db() -> tuple[list[JobSpec], Site | None]:
        with get_session() as session:
            db_collector = (
                session.query(Collector).filter(Collector.id == collector.id).one()
            )
            db_collector.last_seen_utc = now
            site = None
            if db_collector.site_id:
                site = (
                    session.query(Site)
                    .filter(Site.id == db_collector.site_id)
                    .one_or_none()
                )
            jobs = select_jobs_for_collector(
                session=session,
                collector=db_collector,
                now=now,
                max_jobs=settings.scheduler_max_jobs_per_poll,
            )
            for job in jobs:
                if not job.job_id:
                    continue
                schedule_type_id = parse_job_id(job.job_id)
                if schedule_type_id is None:
                    continue
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
            return jobs, site

    jobs, site = await asyncio.to_thread(_poll_db)
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
                    "expires_at": _format_utc(entry.expires_at)
                    if entry.expires_at
                    else None,
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
    collector = await _resolve_collector(request)
    if not collector:
        log_warning(logger, "collector.ack_failed", reason="missing_mtls_identity")
        log_security_event(
            action="collector.job_ack",
            outcome="denied",
            details={"reason": "missing_mtls_identity"},
        )
        return JSONResponse({"error": "mTLS identity required"}, status_code=401)
    _validate_timestamp(request)
    set_log_context(tenant_id=str(collector.tenant_id), collector_id=collector.uuid)
    rate_limiter = _get_rate_limiter(request)
    if not await _apply_rate_limit(collector, rate_limiter):
        log_security_event(
            action="collector.job_ack",
            outcome="denied",
            details={"reason": "rate_limited", "collector_id": collector.uuid},
        )
        return JSONResponse({"error": "rate_limited"}, status_code=429)
    payload: dict[str, Any] = await request.json()
    job_id = payload.get("job_id")
    if not job_id:
        log_warning(logger, "collector.ack_failed", reason="missing_job_id")
        log_security_event(
            action="collector.job_ack",
            outcome="denied",
            details={"reason": "missing_job_id", "collector_id": collector.uuid},
        )
        return JSONResponse({"error": "job_id is required"}, status_code=400)
    now = datetime.now(UTC)
    collector_time = payload.get("collector_time_utc")
    set_log_context(job_id=str(job_id))
    ok, skew = _enforce_clock_skew(collector_time, now)
    if not ok:
        log_warning(
            logger,
            "collector.ack_failed",
            reason="clock_skew_invalid" if collector_time else "missing_collector_time",
            skew_seconds=skew,
        )
        log_security_event(
            action="collector.job_ack",
            outcome="denied",
            details={
                "reason": "clock_skew_invalid"
                if collector_time
                else "missing_collector_time",
                "collector_id": collector.uuid,
                "skew_seconds": skew,
            },
        )
        return JSONResponse({"error": "clock_skew_invalid"}, status_code=400)

    def _ack_db() -> None:
        with get_session() as session:
            db_collector = (
                session.query(Collector).filter(Collector.id == collector.id).one()
            )
            db_collector.last_seen_utc = now
            _update_clock_skew(db_collector, collector_time, now)

    await asyncio.to_thread(_ack_db)
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
    collector = await _resolve_collector(request)
    if not collector:
        log_warning(logger, "collector.result_failed", reason="missing_mtls_identity")
        log_security_event(
            action="collector.job_result",
            outcome="denied",
            details={"reason": "missing_mtls_identity"},
        )
        return JSONResponse({"error": "mTLS identity required"}, status_code=401)
    _validate_timestamp(request)
    set_log_context(tenant_id=str(collector.tenant_id), collector_id=collector.uuid)
    rate_limiter = _get_rate_limiter(request)
    if not await _apply_rate_limit(collector, rate_limiter):
        log_security_event(
            action="collector.job_result",
            outcome="denied",
            details={"reason": "rate_limited", "collector_id": collector.uuid},
        )
        return JSONResponse({"error": "rate_limited"}, status_code=429)
    payload: dict[str, Any] = await request.json()
    job_id = payload.get("job_id")
    if not job_id:
        log_warning(logger, "collector.result_failed", reason="missing_job_id")
        log_security_event(
            action="collector.job_result",
            outcome="denied",
            details={"reason": "missing_job_id", "collector_id": collector.uuid},
        )
        return JSONResponse({"error": "job_id is required"}, status_code=400)
    now = datetime.now(UTC)
    collector_time = payload.get("collector_time_utc")
    set_log_context(job_id=str(job_id))
    ok, skew = _enforce_clock_skew(collector_time, now)
    if not ok:
        log_warning(
            logger,
            "collector.result_failed",
            reason="clock_skew_invalid" if collector_time else "missing_collector_time",
            skew_seconds=skew,
        )
        log_security_event(
            action="collector.job_result",
            outcome="denied",
            details={
                "reason": "clock_skew_invalid"
                if collector_time
                else "missing_collector_time",
                "collector_id": collector.uuid,
                "skew_seconds": skew,
            },
        )
        return JSONResponse({"error": "clock_skew_invalid"}, status_code=400)

    def _result_db() -> tuple[str | None, int]:
        with get_session() as session:
            db_collector = (
                session.query(Collector).filter(Collector.id == collector.id).one()
            )
            db_collector.last_seen_utc = now
            _update_clock_skew(db_collector, collector_time, now)
            schedule_type_id = parse_job_id(job_id)
            scan_type = None
            if schedule_type_id is not None:
                entry = (
                    session.query(ScanScheduleType)
                    .filter(ScanScheduleType.id == schedule_type_id)
                    .one_or_none()
                )
                if entry:
                    scan_type = entry.scan_type
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
            return scan_type, collector.tenant_id

    scan_type, tenant_id = await asyncio.to_thread(_result_db)
    if scan_type:
        job_completed_counter.labels(
            scan_type=scan_type, tenant_id=str(tenant_id)
        ).inc()
        durations = [
            entry.get("duration_ms")
            for entry in (payload.get("results") or [])
            if isinstance(entry, dict)
        ]
        duration_ms = sum(item for item in durations if isinstance(item, int | float))
        if duration_ms > 0:
            job_duration_histogram.labels(
                scan_type=scan_type, status="completed"
            ).observe(duration_ms / 1000.0)
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
    collector = await _resolve_collector(request)
    if not collector:
        log_warning(logger, "collector.status_failed", reason="missing_mtls_identity")
        log_security_event(
            action="collector.job_status",
            outcome="denied",
            details={"reason": "missing_mtls_identity"},
        )
        return JSONResponse({"error": "mTLS identity required"}, status_code=401)
    _validate_timestamp(request)
    set_log_context(tenant_id=str(collector.tenant_id), collector_id=collector.uuid)
    rate_limiter = _get_rate_limiter(request)
    if not await _apply_rate_limit(collector, rate_limiter):
        log_security_event(
            action="collector.job_status",
            outcome="denied",
            details={"reason": "rate_limited", "collector_id": collector.uuid},
        )
        return JSONResponse({"error": "rate_limited"}, status_code=429)
    payload: dict[str, Any] = await request.json()
    job_id = payload.get("job_id")
    status = payload.get("status")
    if not job_id or not status:
        log_security_event(
            action="collector.job_status",
            outcome="denied",
            details={
                "reason": "missing_job_id_or_status",
                "collector_id": collector.uuid,
            },
        )
        return JSONResponse(
            {"error": "job_id and status are required"}, status_code=400
        )
    set_log_context(job_id=str(job_id))
    now = datetime.now(UTC)
    collector_time = payload.get("collector_time_utc")
    ok, skew = _enforce_clock_skew(collector_time, now)
    if not ok:
        log_warning(
            logger,
            "collector.status_failed",
            reason="clock_skew_invalid" if collector_time else "missing_collector_time",
            skew_seconds=skew,
        )
        log_security_event(
            action="collector.job_status",
            outcome="denied",
            details={
                "reason": "clock_skew_invalid"
                if collector_time
                else "missing_collector_time",
                "collector_id": collector.uuid,
                "skew_seconds": skew,
            },
        )
        return JSONResponse({"error": "clock_skew_invalid"}, status_code=400)
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
    if status == "failed":

        def _load_scan_type() -> tuple[str | None, int]:
            with get_session() as session:
                schedule_type_id = parse_job_id(job_id)
                if schedule_type_id is None:
                    return None, collector.tenant_id
                entry = (
                    session.query(ScanScheduleType)
                    .filter(ScanScheduleType.id == schedule_type_id)
                    .one_or_none()
                )
                return (entry.scan_type if entry else None), collector.tenant_id

        scan_type, tenant_id = await asyncio.to_thread(_load_scan_type)
        if scan_type:
            job_failed_counter.labels(
                scan_type=scan_type, tenant_id=str(tenant_id)
            ).inc()
    return JSONResponse({"status": "accepted", "server_time_utc": _format_utc(now)})


@router.post("/credentials/resolve")
async def resolve_collector_credentials(request: Request) -> JSONResponse:
    collector = await _resolve_collector(request)
    if not collector:
        log_warning(
            logger, "collector.credentials_failed", reason="missing_mtls_identity"
        )
        log_security_event(
            action="collector.credentials",
            outcome="denied",
            details={"reason": "missing_mtls_identity"},
        )
        return JSONResponse({"error": "mTLS identity required"}, status_code=401)
    _validate_timestamp(request)
    set_log_context(tenant_id=str(collector.tenant_id), collector_id=collector.uuid)
    rate_limiter = _get_rate_limiter(request)
    if not await _apply_rate_limit(collector, rate_limiter):
        log_security_event(
            action="collector.credentials",
            outcome="denied",
            details={"reason": "rate_limited", "collector_id": collector.uuid},
        )
        return JSONResponse({"error": "rate_limited"}, status_code=429)
    if settings.require_vault and (not settings.vault_addr or not settings.vault_token):
        log_warning(
            logger, "collector.credentials_failed", reason="vault_not_configured"
        )
        log_security_event(
            action="collector.credentials",
            outcome="error",
            details={"reason": "vault_not_configured", "collector_id": collector.uuid},
        )
        return JSONResponse({"error": "vault_not_configured"}, status_code=503)
    payload: dict[str, Any] = await request.json()
    protocol = payload.get("protocol")
    targets = payload.get("targets") or []
    if not protocol or not isinstance(targets, list):
        log_security_event(
            action="collector.credentials",
            outcome="denied",
            details={"reason": "invalid_payload", "collector_id": collector.uuid},
        )
        return JSONResponse(
            {"error": "protocol and targets are required"}, status_code=400
        )
    try:
        credentials = await resolve_credentials(collector.tenant_id, protocol, targets)
    except ValueError:
        log_security_event(
            action="collector.credentials",
            outcome="denied",
            details={"reason": "invalid_protocol", "collector_id": collector.uuid},
        )
        return JSONResponse({"error": "invalid protocol"}, status_code=400)
    return JSONResponse({"credentials": credentials})


@router.post("/schedules/{schedule_id}/types/{type_id}/status")
async def update_schedule_type_status(
    schedule_id: int, type_id: int, request: Request
) -> JSONResponse:
    collector = await _resolve_collector(request)
    if not collector:
        log_warning(
            logger,
            "collector.schedule_type_update_failed",
            reason="missing_mtls_identity",
        )
        return JSONResponse({"error": "mTLS identity required"}, status_code=401)
    _validate_timestamp(request)
    set_log_context(tenant_id=str(collector.tenant_id), collector_id=collector.uuid)
    rate_limiter = _get_rate_limiter(request)
    if not await _apply_rate_limit(collector, rate_limiter):
        return JSONResponse({"error": "rate_limited"}, status_code=429)
    payload = await request.json()
    actual_start_at = payload.get("actual_start_at_utc") or payload.get(
        "actual_start_at"
    )
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
        log_warning(
            logger,
            "collector.schedule_type_update_failed",
            reason="invalid_actual_start",
        )
        return JSONResponse({"error": "Invalid actual_start_at_utc"}, status_code=400)
    if finished_at and finished_dt is None:
        log_warning(
            logger,
            "collector.schedule_type_update_failed",
            reason="invalid_finished_at",
        )
        return JSONResponse({"error": "Invalid finished_at_utc"}, status_code=400)

    now = datetime.now(UTC)
    ok, skew = _enforce_clock_skew(collector_time, now)
    if not ok:
        log_warning(
            logger,
            "collector.schedule_type_update_failed",
            reason="clock_skew_invalid" if collector_time else "missing_collector_time",
            skew_seconds=skew,
        )
        return JSONResponse({"error": "clock_skew_invalid"}, status_code=400)

    def _update_db() -> tuple[Site | None, bool]:
        with get_session() as session:
            db_collector = (
                session.query(Collector).filter(Collector.id == collector.id).one()
            )
            db_collector.last_seen_utc = now
            _update_clock_skew(db_collector, collector_time, now)
            entry = (
                session.query(ScanScheduleType)
                .filter(ScanScheduleType.id == type_id)
                .one_or_none()
            )
            if not entry:
                return None, False
            schedule = (
                session.query(ScanSchedule)
                .filter(ScanSchedule.id == entry.schedule_id)
                .one_or_none()
            )
            site = None
            if schedule and schedule.site_id:
                site = (
                    session.query(Site)
                    .filter(Site.id == schedule.site_id)
                    .one_or_none()
                )
            if actual_dt:
                entry.actual_start_at_utc = actual_dt
            if finished_dt:
                entry.finished_at_utc = finished_dt
            return site, True

    site, ok_entry = await asyncio.to_thread(_update_db)
    if not ok_entry:
        return JSONResponse({"error": "Scan type entry not found"}, status_code=404)
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
    collector = await _resolve_collector(request)
    if not collector:
        log_warning(
            logger, "collector.schedule_update_failed", reason="missing_mtls_identity"
        )
        return JSONResponse({"error": "mTLS identity required"}, status_code=401)
    _validate_timestamp(request)
    set_log_context(tenant_id=str(collector.tenant_id), collector_id=collector.uuid)
    rate_limiter = _get_rate_limiter(request)
    if not await _apply_rate_limit(collector, rate_limiter):
        return JSONResponse({"error": "rate_limited"}, status_code=429)
    payload = await request.json()
    actual_start_at = payload.get("actual_start_at_utc") or payload.get(
        "actual_start_at"
    )
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
        log_warning(
            logger, "collector.schedule_update_failed", reason="invalid_actual_start"
        )
        return JSONResponse({"error": "Invalid actual_start_at_utc"}, status_code=400)
    if finished_at and finished_dt is None:
        log_warning(
            logger, "collector.schedule_update_failed", reason="invalid_finished_at"
        )
        return JSONResponse({"error": "Invalid finished_at_utc"}, status_code=400)

    now = datetime.now(UTC)
    ok, skew = _enforce_clock_skew(collector_time, now)
    if not ok:
        log_warning(
            logger,
            "collector.schedule_update_failed",
            reason="clock_skew_invalid" if collector_time else "missing_collector_time",
            skew_seconds=skew,
        )
        return JSONResponse({"error": "clock_skew_invalid"}, status_code=400)

    def _update_db() -> tuple[Site | None, bool]:
        with get_session() as session:
            db_collector = (
                session.query(Collector).filter(Collector.id == collector.id).one()
            )
            db_collector.last_seen_utc = now
            _update_clock_skew(db_collector, collector_time, now)
            schedule = (
                session.query(ScanSchedule)
                .filter(ScanSchedule.id == schedule_id)
                .one_or_none()
            )
            if not schedule:
                return None, False
            site = None
            if schedule.site_id:
                site = (
                    session.query(Site)
                    .filter(Site.id == schedule.site_id)
                    .one_or_none()
                )
            if actual_dt:
                schedule.actual_start_at_utc = actual_dt
            if finished_dt:
                schedule.finished_at_utc = finished_dt
            return site, True

    site, ok_schedule = await asyncio.to_thread(_update_db)
    if not ok_schedule:
        return JSONResponse({"error": "Schedule not found"}, status_code=404)
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
