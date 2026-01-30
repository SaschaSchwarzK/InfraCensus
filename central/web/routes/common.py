from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterable, Sequence
from datetime import datetime
from typing import Any
from urllib.parse import quote_plus
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.exc import SQLAlchemyError

from central.core.parsing import format_utc, parse_labels, parse_optional_str_list

templates = Jinja2Templates(directory="central/web/templates")

_ALLOWED_CREDENTIAL_PROTOCOLS = {"snmp", "ssh", "http"}
type WebResponse = HTMLResponse | JSONResponse | RedirectResponse


def _safe_query(fetch: Callable[[], Iterable[Any]]) -> tuple[list[Any], str | None]:
    try:
        return list(fetch()), None
    except SQLAlchemyError as exc:  # pragma: no cover - guard for missing migrations
        return [], str(exc)


def _wants_json(request: Request) -> bool:
    return "application/json" in request.headers.get("accept", "")


def _format_dt(value: Any) -> str | None:
    if not value:
        return None
    return format_utc(value)


def _parse_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _is_valid_timezone(value: str) -> bool:
    banned = {
        "CET",
        "CEST",
        "EST",
        "EDT",
        "PST",
        "PDT",
        "CST",
        "CDT",
        "MST",
        "MDT",
        "GMT",
        "UTC",
    }
    if value.upper() in banned:
        return False
    try:
        ZoneInfo(value)
    except ZoneInfoNotFoundError:
        return False
    return True


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _parse_labels_value(value: object) -> dict[str, str] | None:
    return parse_labels(value)


def _parse_capabilities_value(value: object) -> list[str] | None:
    return parse_optional_str_list(value)


def _parse_scopes_value(value: object) -> list[str] | None:
    return parse_optional_str_list(value)


def _pagination_params(request: Request) -> tuple[int, int]:
    try:
        limit = int(request.query_params.get("limit", "50"))
    except ValueError:
        limit = 50
    try:
        offset = int(request.query_params.get("offset", "0"))
    except ValueError:
        offset = 0
    limit = max(1, min(limit, 1000))
    offset = max(0, offset)
    return limit, offset


def _paginate_query(query, request: Request) -> tuple[Any, int, int]:
    limit, offset = _pagination_params(request)
    return query.limit(limit).offset(offset), limit, offset


def _paginate_list(items: Sequence[Any], request: Request) -> list[Any]:
    limit, offset = _pagination_params(request)
    return list(items[offset : offset + limit])


def _redirect_with_message(url: str, message: str) -> RedirectResponse:
    return RedirectResponse(url=f"{url}?message={quote_plus(message)}", status_code=302)


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None
