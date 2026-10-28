"""Data models for the impossible travel detection engine.

This module only defines data shapes. It contains no detection logic and
has no dependency on FastAPI, databases, or any third-party package.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum


class LoginStatus(str, Enum):
    """Whether an authentication attempt succeeded."""

    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"


class DetectionStatus(str, Enum):
    """Outcome of comparing two consecutive logins.

    SUSPICIOUS means "potentially impossible travel". It is a signal for
    review, not proof of malicious activity.
    """

    NORMAL = "NORMAL"
    SUSPICIOUS = "SUSPICIOUS"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"


@dataclass(frozen=True)
class Location:
    """A geographic point in decimal degrees."""

    latitude: float
    longitude: float


@dataclass(frozen=True)
class LoginEvent:
    """A single, validated login event.

    Attributes:
        event_id: Unique identifier of the event.
        user_id: Identifier of the account that logged in.
        timestamp: Timezone-aware datetime, always in UTC.
        ip_address: Source IP address as text.
        status: Whether the login succeeded or failed.
        location: Approximate location, or None if unavailable.
    """

    event_id: str
    user_id: str
    timestamp: datetime
    ip_address: str
    status: LoginStatus
    location: Location | None = None


@dataclass(frozen=True)
class DetectionResult:
    """Explainable result of comparing two consecutive logins of one user.

    Fields that cannot be calculated (for example distance when a location
    is missing) are None rather than a made-up value.
    """

    user_id: str
    previous_event_id: str
    current_event_id: str
    previous_location: Location | None
    current_location: Location | None
    distance_km: float | None
    elapsed: timedelta | None
    implied_speed_kmh: float | None
    status: DetectionStatus
    reason: str