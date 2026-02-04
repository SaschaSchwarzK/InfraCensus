"""Shared scanner helpers."""

from __future__ import annotations

import re

HOSTNAME_REGEX = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
)


def is_valid_hostname(value: str) -> bool:
    """Return True when value is a syntactically valid hostname."""
    if not value or len(value) > 253:
        return False
    return HOSTNAME_REGEX.fullmatch(value) is not None
