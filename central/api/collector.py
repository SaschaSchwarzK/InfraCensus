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

router = APIRouter(prefix="/collectors", tags=["collectors"])
logger = logging.getLogger(__name__)


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

        # Placeholder certificate issuance; integrate with CA.
        cert_pem = "-----BEGIN CERTIFICATE-----\nPENDING\n-----END CERTIFICATE-----"
        cert_serial = f"pending-{collector.id}"
        cert_fingerprint = "pending"
        collector.cert_serial = cert_serial
        collector.cert_fingerprint = cert_fingerprint
        collector.cert_valid_from = now
        collector.cert_valid_to = now
        session.add(
            CollectorCertificate(
                collector_id=collector.id,
                serial=cert_serial,
                fingerprint=cert_fingerprint,
                valid_from=now,
                valid_to=now,
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
            "ca_bundle": "-----BEGIN CERTIFICATE-----\nPENDING\n-----END CERTIFICATE-----",
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

        cert_pem = "-----BEGIN CERTIFICATE-----\nRENEWED\n-----END CERTIFICATE-----"
        cert_serial = f"renew-{collector.id}-{int(now.timestamp())}"
        collector.cert_serial = cert_serial
        collector.cert_fingerprint = "renewed"
        collector.cert_valid_from = now
        collector.cert_valid_to = now
        session.add(
            CollectorCertificate(
                collector_id=collector.id,
                serial=cert_serial,
                fingerprint="renewed",
                valid_from=now,
                valid_to=now,
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
            "ca_bundle": "-----BEGIN CERTIFICATE-----\nRENEWED\n-----END CERTIFICATE-----",
        }
    )


@router.get("/jobs/poll")
def poll_jobs(request: Request) -> JSONResponse:
    collector = _resolve_collector(request)
    if not collector:
        log_warning(logger, "collector.poll_failed", reason="missing_mtls_identity")
        return JSONResponse({"error": "mTLS identity required"}, status_code=401)
    now = datetime.now(timezone.utc)
    with get_session() as session:
        db_collector = session.query(Collector).filter(Collector.id == collector.id).one()
        db_collector.last_seen_utc = now
        site = None
        if db_collector.site_id:
            site = session.query(Site).filter(Site.id == db_collector.site_id).one_or_none()
    log_info(
        logger,
        "collector.poll",
        collector_id=collector.uuid,
        tenant_id=collector.tenant_id,
        site_id=collector.site_id,
    )
    return JSONResponse(
        {
            "jobs": [],
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
    return JSONResponse({"status": "acknowledged", "server_time_utc": _format_utc(now)})


@router.post("/jobs/result")
async def submit_result(request: Request) -> JSONResponse:
    collector = _resolve_collector(request)
    if not collector:
        log_warning(logger, "collector.result_failed", reason="missing_mtls_identity")
        return JSONResponse({"error": "mTLS identity required"}, status_code=401)
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
    log_info(
        logger,
        "collector.result_accepted",
        collector_id=collector.uuid,
        job_id=job_id,
    )
    return JSONResponse({"status": "accepted", "server_time_utc": _format_utc(now)})


@router.post("/schedules/{schedule_id}/types/{type_id}/status")
async def update_schedule_type_status(
    schedule_id: int, type_id: int, request: Request
) -> JSONResponse:
    collector = _resolve_collector(request)
    if not collector:
        log_warning(logger, "collector.schedule_type_update_failed", reason="missing_mtls_identity")
        return JSONResponse({"error": "mTLS identity required"}, status_code=401)
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
