from __future__ import annotations

import asyncio
import time
from asyncio import Lock
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin

import httpx
from opentelemetry import propagate

from collector.core.tracing import get_tracer


@dataclass(frozen=True)
class ApiResponse:
    status_code: int
    payload: dict[str, Any]


class ApiClient:
    def __init__(
        self,
        base_url: str,
        cert: tuple[str, str] | None,
        verify: bool | str,
        timeout: int,
        max_retries: int = 3,
        backoff_seconds: float = 0.5,
        circuit_breaker_threshold: int = 5,
        circuit_breaker_cooldown: int = 30,
    ) -> None:
        self._base_url = base_url.rstrip("/") + "/"
        self._client = httpx.AsyncClient(
            timeout=timeout,
            verify=verify,
            cert=cert,
        )
        self._max_retries = max_retries
        self._backoff_seconds = backoff_seconds
        self._failure_count = 0
        self._circuit_open_until: float | None = None
        self._cb_threshold = circuit_breaker_threshold
        self._cb_cooldown = circuit_breaker_cooldown
        self._request_metrics: dict[tuple[str, int], dict[str, float]] = {}
        self._metrics_lock = Lock()

    async def __aenter__(self) -> ApiClient:
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()

    async def close(self) -> None:
        await self._client.aclose()

    async def enroll(self, payload: dict[str, Any]) -> ApiResponse:
        return await self._post_json("collectors/enroll", payload)

    async def renew(self, payload: dict[str, Any]) -> ApiResponse:
        return await self._post_json("collectors/renew", payload)

    async def poll_jobs(self) -> ApiResponse:
        return await self._get_json("collectors/jobs/poll")

    async def acknowledge_job(self, payload: dict[str, Any]) -> ApiResponse:
        return await self._post_json("collectors/jobs/ack", payload)

    async def submit_job_status(self, payload: dict[str, Any]) -> ApiResponse:
        return await self._post_json("collectors/jobs/status", payload)

    async def resolve_credentials(self, payload: dict[str, Any]) -> ApiResponse:
        return await self._post_json("collectors/credentials/resolve", payload)

    async def submit_results(self, payload: dict[str, Any]) -> ApiResponse:
        return await self._post_json("collectors/jobs/result", payload)

    async def _get_json(self, path: str) -> ApiResponse:
        return await self._request_json("GET", path, None)

    async def _post_json(self, path: str, payload: dict[str, Any]) -> ApiResponse:
        return await self._request_json("POST", path, payload)

    async def _request_json(
        self, method: str, path: str, payload: dict[str, Any] | None
    ) -> ApiResponse:
        url = urljoin(self._base_url, path)
        if self._circuit_open_until and time.monotonic() < self._circuit_open_until:
            await self._record_request(path, 0, 0.0)
            return ApiResponse(
                status_code=0,
                payload={"error": "circuit_open"},
            )
        tracer = get_tracer(__name__)
        for attempt in range(self._max_retries + 1):
            try:
                start = time.perf_counter()
                headers: dict[str, str] = {}
                with tracer.start_as_current_span("http.client") as span:
                    span.set_attribute("http.method", method)
                    span.set_attribute("http.url", url)
                    propagate.inject(headers)
                    if method == "GET":
                        response = await self._client.get(url, headers=headers)
                    else:
                        response = await self._client.post(
                            url, json=payload, headers=headers
                        )
                duration = time.perf_counter() - start
                try:
                    parsed = response.json()
                except ValueError:
                    parsed = {
                        "error": "invalid_json",
                        "text": response.text[:2000],
                    }
                await self._record_request(path, response.status_code, duration)
                if 200 <= response.status_code < 300:
                    self._reset_circuit()
                elif response.status_code >= 500:
                    self._register_failure()
                return ApiResponse(status_code=response.status_code, payload=parsed)
            except httpx.RequestError as exc:
                self._register_failure()
                if attempt >= self._max_retries:
                    await self._record_request(path, 0, 0.0)
                    return ApiResponse(
                        status_code=0,
                        payload={"error": "request_failed", "detail": str(exc)},
                    )
                await asyncio.sleep(self._backoff_seconds * (2**attempt))
        return ApiResponse(status_code=0, payload={"error": "request_failed"})

    def _register_failure(self) -> None:
        self._failure_count += 1
        if self._failure_count >= self._cb_threshold:
            self._circuit_open_until = time.monotonic() + self._cb_cooldown

    def _reset_circuit(self) -> None:
        self._failure_count = 0
        self._circuit_open_until = None

    async def _record_request(
        self, endpoint: str, status_code: int, duration: float
    ) -> None:
        key = (endpoint, status_code)
        async with self._metrics_lock:
            entry = self._request_metrics.get(key)
            if not entry:
                entry = {"count": 0, "duration_sum": 0.0}
                self._request_metrics[key] = entry
            entry["count"] += 1
            entry["duration_sum"] += duration

    async def metrics_snapshot(self) -> dict[tuple[str, int], dict[str, float]]:
        async with self._metrics_lock:
            return dict(self._request_metrics)

    def circuit_open(self) -> bool:
        return bool(
            self._circuit_open_until and time.monotonic() < self._circuit_open_until
        )
