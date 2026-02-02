import asyncio
import logging
import time
import uuid
from contextlib import AbstractContextManager

from fastapi import APIRouter, FastAPI, HTTPException, Request
from fastapi.responses import Response
from opentelemetry import propagate
from opentelemetry.trace import Span
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from starlette.middleware.sessions import SessionMiddleware

from central.api.collector import router as collector_router
from central.api.jobs import router as jobs_router
from central.api.metrics import build_metrics
from central.core.ca import CASettings, CertificateAuthority
from central.core.config import (
    Settings,
    register_settings_listener,
    settings,
    start_config_polling,
)
from central.core.logging import (
    configure_logging,
    log_error,
    log_info,
    set_log_context,
    set_trace_id,
)
from central.core.rate_limit import CollectorRateLimiter
from central.core.tracing import configure_tracing, get_tracer
from central.db.session import get_session
from central.web.app import router as web_router

app = FastAPI(
    title="InfraCensus Central API",
    version="0.1.0",
    description="Central API for InfraCensus (collectors, scheduling, and web UI).",
    openapi_url="/openapi.json",
    docs_url="/docs",
    redoc_url="/redoc",
)
configure_logging()
configure_tracing("infracensus-central")
app.add_middleware(SessionMiddleware, secret_key=settings.session_secret)
app.include_router(web_router)

api_v1 = APIRouter(prefix="/api/v1")
api_v1.include_router(collector_router)
api_v1.include_router(jobs_router)
app.include_router(api_v1)
logger = logging.getLogger(__name__)

app.state.rate_limiter = CollectorRateLimiter(settings.collector_rate_limit_per_hour)
app.state.ca = CertificateAuthority(
    CASettings(
        key_path=settings.ca_key_path,
        cert_path=settings.ca_cert_path,
        ca_valid_days=settings.ca_cert_valid_days,
        cert_valid_days=settings.collector_cert_valid_days,
    )
)


def _sanitize_rate_limit(value: object) -> int:
    if not isinstance(value, (int, float)) or value < 0 or value > 10000:
        return 100
    return int(value)


def _apply_settings(new_settings: Settings) -> None:
    for middleware in app.user_middleware:
        if middleware.cls is SessionMiddleware:
            options = getattr(middleware, "options", None)
            if isinstance(options, dict):
                options["secret_key"] = new_settings.session_secret
    app.middleware_stack = None
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        rate_limit = _sanitize_rate_limit(new_settings.collector_rate_limit_per_hour)
        asyncio.run(app.state.rate_limiter.update_limit(rate_limit))
    else:
        rate_limit = _sanitize_rate_limit(new_settings.collector_rate_limit_per_hour)
        loop.create_task(app.state.rate_limiter.update_limit(rate_limit))
    app.state.ca = CertificateAuthority(
        CASettings(
            key_path=new_settings.ca_key_path,
            cert_path=new_settings.ca_cert_path,
            ca_valid_days=new_settings.ca_cert_valid_days,
            cert_valid_days=new_settings.collector_cert_valid_days,
        )
    )


register_settings_listener(_apply_settings)


@app.on_event("startup")
async def _start_config_watcher() -> None:
    await start_config_polling()


def _setup_request_context(request: Request) -> tuple[str, str | None, str, str]:
    request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
    incoming_trace_id = request.headers.get("x-trace-id")
    path = request.url.path
    method = request.method
    return request_id, incoming_trace_id, path, method


def _setup_tracing(
    request: Request, method: str, path: str
) -> tuple[str | None, AbstractContextManager[Span]]:
    tracer = get_tracer(__name__)
    ctx = propagate.extract(request.headers)
    span_cm = tracer.start_as_current_span("http.request", context=ctx)
    return None, span_cm


def _get_session_user_id(request: Request) -> str | None:
    session = request.scope.get("session")
    if isinstance(session, dict):
        user_id = session.get("user_id")
        return str(user_id) if user_id is not None else None
    return None


def _handle_request_error(
    span,
    logger,
    request_id: str,
    method: str,
    path: str,
    start: float,
    request: Request,
    exc: Exception,
) -> None:
    user_id = _get_session_user_id(request)
    duration_ms = int((time.time() - start) * 1000)
    span.set_attribute("http.status_code", 500)
    span.record_exception(exc)
    log_error(
        logger,
        "http.request",
        request_id=request_id,
        method=method,
        path=path,
        status_code=500,
        duration_ms=duration_ms,
        client_ip=request.client.host if request.client else None,
        user_id=user_id,
        error=str(exc),
    )


def _add_security_headers(response: Response, request: Request) -> None:
    if not settings.security_headers_enabled:
        return
    response.headers.setdefault("x-content-type-options", "nosniff")
    response.headers.setdefault("x-frame-options", settings.security_frame_options)
    response.headers.setdefault("referrer-policy", settings.security_referrer_policy)
    response.headers.setdefault("content-security-policy", settings.security_csp)
    response.headers.setdefault(
        "permissions-policy", "geolocation=(), microphone=(), camera=()"
    )
    if request.url.scheme == "https" and settings.security_hsts_seconds > 0:
        hsts_value = f"max-age={settings.security_hsts_seconds}"
        if settings.security_hsts_include_subdomains:
            hsts_value += "; includeSubDomains"
        if settings.security_hsts_preload:
            hsts_value += "; preload"
        response.headers.setdefault("strict-transport-security", hsts_value)


@app.middleware("http")
async def log_requests(request: Request, call_next) -> Response:
    request_id, incoming_trace_id, path, method = _setup_request_context(request)
    start = time.time()
    trace_id, span_cm = _setup_tracing(request, method, path)

    with span_cm as span:
        span.set_attribute("http.method", method)
        span.set_attribute("http.route", path)
        span.set_attribute("http.scheme", request.url.scheme)
        span.set_attribute("http.target", request.url.path)
        span.set_attribute("http.host", request.url.hostname or "")
        trace_context = span.get_span_context()
        trace_id = f"{trace_context.trace_id:032x}" if trace_context.trace_id else None
        set_trace_id(trace_id or incoming_trace_id or request_id)
        user_id = _get_session_user_id(request)
        if user_id is not None:
            set_log_context(user_id=str(user_id))

        try:
            response = await call_next(request)
        except HTTPException:
            raise
        except Exception as exc:
            _handle_request_error(
                span, logger, request_id, method, path, start, request, exc
            )
            raise

        duration_ms = int((time.time() - start) * 1000)
        span.set_attribute("http.status_code", response.status_code)
        log_info(
            logger,
            "http.request",
            request_id=request_id,
            method=method,
            path=path,
            status_code=response.status_code,
            duration_ms=duration_ms,
            client_ip=request.client.host if request.client else None,
            user_id=_get_session_user_id(request),
        )

        response.headers["x-request-id"] = request_id
        response.headers["x-trace-id"] = trace_id or incoming_trace_id or request_id
        _add_security_headers(response, request)
        return response


@app.get("/health")
async def health_check() -> dict:
    return {"status": "ok"}


@app.get("/ready")
async def readiness_check() -> Response:
    try:
        with get_session() as session:
            session.execute(text("SELECT 1"))
    except (SQLAlchemyError, OSError, RuntimeError) as exc:
        return Response(content=str(exc), status_code=503)
    return Response(content="ok", status_code=200)


@app.get("/metrics")
async def metrics() -> Response:
    body = build_metrics()
    return Response(
        content=body,
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )
