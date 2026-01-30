from __future__ import annotations

import os

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.trace import Tracer


def configure_tracing(service_name: str) -> None:
    if os.getenv("OTEL_TRACES_EXPORTER", "").lower() in {"none", ""}:
        return
    resource = Resource.create(
        {
            "service.name": service_name,
            "deployment.environment": os.getenv("ENVIRONMENT", "dev"),
            "service.version": os.getenv("SERVICE_VERSION", "unknown"),
        }
    )
    provider = TracerProvider(resource=resource)
    endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
    exporter = OTLPSpanExporter(endpoint=endpoint) if endpoint else OTLPSpanExporter()
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)


def get_tracer(name: str) -> Tracer:
    return trace.get_tracer(name)
