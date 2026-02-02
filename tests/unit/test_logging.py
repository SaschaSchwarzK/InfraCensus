from __future__ import annotations

import importlib
import json
import logging


def test_sample_rate_cache(monkeypatch) -> None:
    monkeypatch.setenv("LOG_SAMPLE_DEFAULT", "1.0")
    monkeypatch.setenv("LOG_SAMPLE_RATES", "event_a=0.25, event_b=0.5")
    import central.core.logging as logging_module

    importlib.reload(logging_module)

    assert logging_module._sample_rate_for_event("event_a") == 0.25
    assert logging_module._sample_rate_for_event("event_b") == 0.5
    assert logging_module._sample_rate_for_event("missing") == 1.0


def test_log_event_includes_context(monkeypatch, caplog) -> None:
    monkeypatch.setenv("LOG_SAMPLE_DEFAULT", "1.0")
    monkeypatch.setenv("LOG_SAMPLE_RATES", "")
    import central.core.logging as logging_module

    importlib.reload(logging_module)

    logger = logging.getLogger("test.logger")
    logging_module.set_log_context(tenant_id="t1", user_id="u1")
    logging_module.set_trace_id("trace-123")

    with caplog.at_level(logging.INFO):
        logging_module.log_info(logger, "event.test", message="hello", extra_field=1)

    assert caplog.records
    payload = json.loads(caplog.records[-1].message)
    assert payload["event"] == "event.test"
    assert payload["tenant_id"] == "t1"
    assert payload["user_id"] == "u1"
    assert payload["trace_id"] == "trace-123"
    assert payload["message"] == "hello"
    assert payload["extra_field"] == 1
