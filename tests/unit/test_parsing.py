from __future__ import annotations

from datetime import UTC, datetime

from central.core import parsing


def test_parse_iso8601_handles_z_suffix() -> None:
    parsed = parsing.parse_iso8601("2024-01-02T03:04:05Z")
    assert parsed == datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC)


def test_parse_iso8601_returns_none_for_invalid() -> None:
    assert parsing.parse_iso8601("not-a-date") is None


def test_format_utc_normalizes_timezone() -> None:
    value = datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC)
    assert parsing.format_utc(value).endswith("Z")


def test_parse_int_list_accepts_list_and_csv() -> None:
    assert parsing.parse_int_list(["1", "2", "bad", ""]) == [1, 2]
    assert parsing.parse_int_list("3, 4, nope") == [3, 4]


def test_parse_str_list_accepts_json_string() -> None:
    assert parsing.parse_str_list('["a", "b", " "]') == ["a", "b"]
    assert parsing.parse_str_list("a, b") == ["a", "b"]


def test_parse_labels_accepts_string_and_dict() -> None:
    assert parsing.parse_labels("k=v, x=y") == {"k": "v", "x": "y"}
    assert parsing.parse_labels({"a": 1}) == {"a": "1"}
