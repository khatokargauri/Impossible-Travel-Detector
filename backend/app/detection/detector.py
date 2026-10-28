"""Core impossible travel detection logic.

Groups login events by user, sorts them chronologically, and compares
consecutive logins. A SUSPICIOUS result means "potentially impossible
travel" and is a signal for review, not proof of malicious activity.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from app.detection.config import DetectionConfig
from app.detection.geo import haversine_km
from app.detection.models import (
    DetectionResult,
    DetectionStatus,
    Location,
    LoginEvent,
    LoginStatus,
)


def _describe(location: Location | None) -> str:
    """Format a location for use in a human-readable reason."""
    if location is None:
        return "unknown location"
    return f"({location.latitude:.4f}, {location.longitude:.4f})"


def compare_events(
    previous: LoginEvent,
    current: LoginEvent,
    config: DetectionConfig,
) -> DetectionResult:
    """Compare two consecutive logins of the same user.

    The caller must pass events in chronological order.
    """
    elapsed = current.timestamp - previous.timestamp

    def result(
        status: DetectionStatus,
        reason: str,
        distance_km: float | None = None,
        speed_kmh: float | None = None,
    ) -> DetectionResult:
        return DetectionResult(
            user_id=current.user_id,
            previous_event_id=previous.event_id,
            current_event_id=current.event_id,
            previous_location=previous.location,
            current_location=current.location,
            distance_km=distance_km,
            elapsed=elapsed,
            implied_speed_kmh=speed_kmh,
            status=status,
            reason=reason,
        )

    # Rule 1: without both locations we cannot judge anything.
    if previous.location is None or current.location is None:
        return result(
            DetectionStatus.INSUFFICIENT_DATA,
            "Location is missing for at least one of the two logins, "
            "so distance and speed cannot be calculated.",
        )

    try:
        distance_km = haversine_km(previous.location, current.location)
    except ValueError:
        return result(
            DetectionStatus.INSUFFICIENT_DATA,
            "A location has invalid coordinates, so distance cannot be "
            "calculated.",
        )

    # Rule 2: time going backwards means the ordering cannot be trusted.
    if elapsed < timedelta(0):
        return result(
            DetectionStatus.INSUFFICIENT_DATA,
            "The time difference is negative, so the events cannot be "
            "compared reliably.",
            distance_km,
        )

    # Rule 3: tiny distances are inside IP geolocation error.
    if distance_km < config.min_distance_km:
        return result(
            DetectionStatus.NORMAL,
            f"Distance of {distance_km:.1f} km is below the "
            f"{config.min_distance_km:.1f} km minimum, which is within "
            "normal IP geolocation error.",
            distance_km,
        )

    # Rule 4: same timestamp but far apart. Speed would be infinite.
    if elapsed == timedelta(0):
        return result(
            DetectionStatus.SUSPICIOUS,
            f"Two logins with the same timestamp are {distance_km:.1f} km "
            "apart. Implied speed cannot be calculated (zero elapsed "
            "time). This may also be a logging or clock artefact.",
            distance_km,
        )

    hours = elapsed.total_seconds() / 3600.0

    # Rule 5: a long gap leaves ample time to travel (optional setting).
    if config.max_gap_hours is not None and hours > config.max_gap_hours:
        return result(
            DetectionStatus.NORMAL,
            f"The gap of {hours:.2f} hours exceeds the configured maximum "
            f"of {config.max_gap_hours:.2f} hours, so implied speed is "
            "not meaningful.",
            distance_km,
        )

    # Rule 6: the speed check itself.
    speed_kmh = distance_km / hours
    if speed_kmh > config.speed_threshold_kmh:
        return result(
            DetectionStatus.SUSPICIOUS,
            f"Potentially impossible travel: {distance_km:.1f} km in "
            f"{hours:.2f} hours implies {speed_kmh:.0f} km/h, above the "
            f"{config.speed_threshold_kmh:.0f} km/h threshold. Review "
            "manually; VPNs, proxies and geolocation errors can cause "
            "false positives.",
            distance_km,
            speed_kmh,
        )

    return result(
        DetectionStatus.NORMAL,
        f"{distance_km:.1f} km in {hours:.2f} hours implies "
        f"{speed_kmh:.0f} km/h, within the {config.speed_threshold_kmh:.0f} "
        "km/h threshold.",
        distance_km,
        speed_kmh,
    )


def detect_impossible_travel(
    events: list[LoginEvent],
    config: DetectionConfig | None = None,
) -> list[DetectionResult]:
    """Run detection over many events and return one result per comparison.

    Events are grouped by user, so different users are never compared.
    """
    config = config or DetectionConfig()

    by_user: dict[str, list[LoginEvent]] = defaultdict(list)
    for event in events:
        if config.only_successful_logins and event.status != LoginStatus.SUCCESS:
            continue
        by_user[event.user_id].append(event)

    results: list[DetectionResult] = []
    for user_id in sorted(by_user):
        ordered = sorted(by_user[user_id], key=lambda e: (e.timestamp, e.event_id))
        for previous, current in zip(ordered, ordered[1:]):
            results.append(compare_events(previous, current, config))
    return results