from __future__ import annotations

import pytest

import central.core.tracing as central_tracing
import collector.core.tracing as collector_tracing


class DummyProvider:
    def __init__(self, resource=None):
        self.resource = resource
        self.processors = []

    def add_span_processor(self, processor):
        self.processors.append(processor)


class DummyProcessor:
    def __init__(self, exporter):
        self.exporter = exporter


class DummyExporter:
    def __init__(self, endpoint=None):
        self.endpoint = endpoint


def _patch_tracing(monkeypatch, module):
    provider_holder = {}

    def _set_provider(provider):
        provider_holder["provider"] = provider

    monkeypatch.setattr(module, "TracerProvider", DummyProvider)
    monkeypatch.setattr(module, "BatchSpanProcessor", DummyProcessor)
    monkeypatch.setattr(module, "OTLPSpanExporter", DummyExporter)
    monkeypatch.setattr(module.trace, "set_tracer_provider", _set_provider)
    return provider_holder


@pytest.mark.parametrize("module", [central_tracing, collector_tracing])
def test_configure_tracing_disabled(monkeypatch, module):
    holder = _patch_tracing(monkeypatch, module)
    monkeypatch.setenv("OTEL_TRACES_EXPORTER", "none")
    module.configure_tracing("svc")
    assert "provider" not in holder


@pytest.mark.parametrize("module", [central_tracing, collector_tracing])
def test_configure_tracing_enables_provider(monkeypatch, module):
    holder = _patch_tracing(monkeypatch, module)
    monkeypatch.setenv("OTEL_TRACES_EXPORTER", "otlp")
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("SERVICE_VERSION", "1.2.3")
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318")

    module.configure_tracing("infracensus-test")

    provider = holder.get("provider")
    assert provider is not None
    assert provider.processors
    processor = provider.processors[0]
    assert isinstance(processor, DummyProcessor)
    assert isinstance(processor.exporter, DummyExporter)
    assert processor.exporter.endpoint == "http://localhost:4318"
