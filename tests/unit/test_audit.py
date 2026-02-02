from __future__ import annotations

import pytest

from central.core import audit


class DummySession:
    def __init__(self) -> None:
        self.added: list[object] = []

    def add(self, obj) -> None:
        self.added.append(obj)


def test_log_audit_requires_session() -> None:
    with pytest.raises(ValueError, match="requires an active session"):
        audit.log_audit(
            actor_user_id=1,
            action="test",
            entity_type="tenant",
            entity_id=2,
            details={},
            session=None,
        )


def test_log_audit_adds_row_with_session() -> None:
    session = DummySession()
    audit.log_audit(
        actor_user_id=1,
        action="test",
        entity_type="tenant",
        entity_id=2,
        details={"k": "v"},
        session=session,  # type: ignore[arg-type]
    )
    assert len(session.added) == 1


def test_should_sample_security_event_respects_env(monkeypatch) -> None:
    monkeypatch.setenv("SECURITY_AUDIT_SAMPLE_RATE", "0")
    assert audit.should_sample_security_event() is False
    monkeypatch.setenv("SECURITY_AUDIT_SAMPLE_RATE", "1")
    assert audit.should_sample_security_event() is True
