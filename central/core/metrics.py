from __future__ import annotations

from typing import Any

PromCounter: Any = None
PromHistogram: Any = None
try:
    from prometheus_client import Counter as PromCounter
    from prometheus_client import Histogram as PromHistogram
except (ImportError, ModuleNotFoundError):  # pragma: no cover - optional dependency
    PromCounter = None
    PromHistogram = None


def _noop_counter(*args: Any, **kwargs: Any) -> Any:
    class _Counter:
        def labels(self, **_kwargs: Any) -> _Counter:
            return self

        def inc(self, *_args: Any, **_kwargs: Any) -> None:
            return None

    return _Counter()


def _noop_histogram(*args: Any, **kwargs: Any) -> Any:
    class _Histogram:
        def labels(self, **_kwargs: Any) -> _Histogram:
            return self

        def observe(self, *_args: Any, **_kwargs: Any) -> None:
            return None

    return _Histogram()


job_assigned_counter = (
    PromCounter(
        "infracensus_jobs_assigned_total",
        "Total jobs assigned to collectors",
        ["scan_type", "tenant_id"],
    )
    if PromCounter is not None
    else _noop_counter()
)

job_completed_counter = (
    PromCounter(
        "infracensus_jobs_completed_total",
        "Total jobs completed by collectors",
        ["scan_type", "tenant_id"],
    )
    if PromCounter is not None
    else _noop_counter()
)

job_failed_counter = (
    PromCounter(
        "infracensus_jobs_failed_total",
        "Total jobs failed by collectors",
        ["scan_type", "tenant_id"],
    )
    if PromCounter is not None
    else _noop_counter()
)

job_duration_histogram = (
    PromHistogram(
        "infracensus_job_duration_seconds",
        "Job execution duration",
        ["scan_type", "status"],
    )
    if PromHistogram is not None
    else _noop_histogram()
)
