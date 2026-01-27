from fastapi import FastAPI, Request
from fastapi.responses import Response
from starlette.middleware.sessions import SessionMiddleware
import time
import uuid
import logging

from central.api.collector import router as collector_router
from central.api.jobs import router as jobs_router
from central.web.app import router as web_router
from central.core.config import settings
from central.core.logging import configure_logging, log_info, log_error, set_trace_id
from central.core.tracing import configure_tracing, get_tracer
from central.api.metrics import build_metrics

app = FastAPI(title="InfraCensus Central API")
configure_logging()
configure_tracing("infracensus-central")
app.add_middleware(SessionMiddleware, secret_key=settings.session_secret)
app.include_router(web_router)
app.include_router(collector_router)
app.include_router(jobs_router)
logger = logging.getLogger(__name__)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
    trace_id = request.headers.get("x-trace-id") or request_id
    set_trace_id(trace_id)
    start = time.time()
    tracer = get_tracer(__name__)
    path = request.url.path
    method = request.method
    with tracer.start_as_current_span("http.request") as span:
        span.set_attribute("http.method", method)
        span.set_attribute("http.route", path)
        span.set_attribute("http.scheme", request.url.scheme)
        span.set_attribute("http.target", request.url.path)
        span.set_attribute("http.host", request.url.hostname or "")
    try:
        response = await call_next(request)
    except Exception as exc:
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
            user_id=request.session.get("user_id") if hasattr(request, "session") else None,
            error=str(exc),
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
        user_id=request.session.get("user_id") if hasattr(request, "session") else None,
    )
    response.headers["x-request-id"] = request_id
    response.headers["x-trace-id"] = trace_id
    return response


@app.get("/health")
async def health_check() -> dict:
    return {"status": "ok"}


@app.get("/metrics")
async def metrics() -> Response:
    body = build_metrics()
    return Response(
        content=body,
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )
