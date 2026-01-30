from __future__ import annotations

from datetime import UTC, datetime


def parse_iso8601(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def format_utc(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def parse_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def parse_int_list(value: str | list[int] | list[str] | None) -> list[int]:
    if value is None:
        return []
    if isinstance(value, list):
        values: list[int] = []
        for item in value:
            if isinstance(item, int):
                values.append(item)
                continue
            if isinstance(item, str):
                text = item.strip()
                if not text:
                    continue
                try:
                    values.append(int(text))
                except ValueError:
                    continue
        return values
    values: list[int] = []
    for item in parse_csv(value):
        try:
            values.append(int(item))
        except ValueError:
            continue
    return values


def parse_str_list(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return []


def parse_optional_str_list(value: object) -> list[str] | None:
    parsed = parse_str_list(value)
    return parsed or None


def parse_labels(value: object) -> dict[str, str] | None:
    if value is None:
        return None
    if isinstance(value, dict):
        parsed = {str(key): str(val) for key, val in value.items()}
        return parsed or None
    if isinstance(value, str):
        labels: dict[str, str] = {}
        for entry in value.split(","):
            if not entry.strip():
                continue
            key, _, raw_value = entry.partition("=")
            if not key.strip():
                continue
            labels[key.strip()] = raw_value.strip()
        return labels or None
    return None
