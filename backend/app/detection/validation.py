"""Validation and normalisation of raw login records.

Turns untrusted input (such as dictionaries loaded from JSON) into clean
LoginEvent objects. Invalid required fields are rejected; missing or
invalid coordinates simply result in no location.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Any, Mapping

from app.detection.geo import is_valid_coordinate
from app.detection.models import Location, LoginEvent, LoginStatus


class ValidationError(ValueError):
    """Raised when a raw login record cannot be turned into a LoginEvent."""


def _require_text(raw: Mapping[str, Any], field: str) -> str:
    """Return a required, non-empty text field (ints are accepted as text)."""
    value = raw.get(field)
    if isinstance(value, bool):
        raise ValidationError(f"'{field}' must be text, not a boolean")
    if isinstance(value, int):
        value = str(value)
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"'{field}' is missing or empty")
    return value.strip()


def parse_timestamp(value: Any) -> datetime:
    """Convert a timestamp to a timezone-aware UTC datetime.

    Accepts an ISO 8601 string or a datetime. Timestamps without timezone
    information are rejected, because assuming they are UTC would be a guess.
    """
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.strip())
        except ValueError:
            raise ValidationError(f"'timestamp' is not valid ISO 8601: {value!r}")
    else:
        raise ValidationError("'timestamp' is missing or not a string")

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValidationError(
            "'timestamp' has no timezone; refusing to assume it is UTC"
        )
    return parsed.astimezone(timezone.utc)


def _parse_status(value: Any) -> LoginStatus:
    """Convert text such as 'success' or 'FAILURE' to a LoginStatus."""
    if isinstance(value, str):
        try:
            return LoginStatus(value.strip().upper())
        except ValueError:
            pass
    raise ValidationError(f"'status' must be SUCCESS or FAILURE, got {value!r}")


def _parse_ip(value: Any) -> str:
    """Return a normalised IPv4/IPv6 address, or raise ValidationError."""
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("'ip_address' is missing or empty")
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        raise ValidationError(f"'ip_address' is not a valid IP: {value!r}")


def _parse_location(raw: Mapping[str, Any]) -> Location | None:
    """Return a Location, or None if coordinates are missing or invalid."""
    latitude = raw.get("latitude")
    longitude = raw.get("longitude")
    if is_valid_coordinate(latitude, longitude):
        return Location(float(latitude), float(longitude))
    return None


def parse_login_event(raw: Mapping[str, Any]) -> LoginEvent:
    """Validate one raw record and return a clean LoginEvent.

    Raises:
        ValidationError: If a required field is missing or invalid.
    """
    if not isinstance(raw, Mapping):
        raise ValidationError("record must be an object with named fields")

    return LoginEvent(
        event_id=_require_text(raw, "event_id"),
        user_id=_require_text(raw, "user_id"),
        timestamp=parse_timestamp(raw.get("timestamp")),
        ip_address=_parse_ip(raw.get("ip_address")),
        status=_parse_status(raw.get("status")),
        location=_parse_location(raw),
    )


def parse_login_events(
    records: list[Mapping[str, Any]],
) -> tuple[list[LoginEvent], list[str]]:
    """Validate many records without stopping at the first bad one.

    Returns:
        A tuple of (valid events, error messages). Each error message
        names the position of the rejected record.
    """
    events: list[LoginEvent] = []
    errors: list[str] = []
    for position, raw in enumerate(records, start=1):
        try:
            events.append(parse_login_event(raw))
        except ValidationError as exc:
            errors.append(f"record {position}: {exc}")
    return events, errors