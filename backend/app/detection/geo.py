"""Geographic distance calculations.

Pure maths only: no dependency on FastAPI, databases, or third-party
packages.
"""

from __future__ import annotations

import math

from app.detection.models import Location

# Mean Earth radius in kilometres (IUGG value).
EARTH_RADIUS_KM = 6371.0088


def is_valid_coordinate(latitude: object, longitude: object) -> bool:
    """Return True if the values form a usable latitude/longitude pair.

    Rejects non-numbers, booleans, NaN, infinity, and values outside the
    valid ranges (latitude -90..90, longitude -180..180).
    """
    for value in (latitude, longitude):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return False
        if not math.isfinite(value):
            return False
    return -90.0 <= latitude <= 90.0 and -180.0 <= longitude <= 180.0


def haversine_km(first: Location, second: Location) -> float:
    """Return the great-circle distance between two locations in kilometres.

    The result is approximate because the Earth is treated as a perfect
    sphere. Identical locations return exactly 0.0.

    Raises:
        ValueError: If either location has invalid coordinates.
    """
    for point in (first, second):
        if not is_valid_coordinate(point.latitude, point.longitude):
            raise ValueError(
                f"Invalid coordinates: ({point.latitude}, {point.longitude})"
            )

    if first == second:
        return 0.0

    lat1 = math.radians(first.latitude)
    lat2 = math.radians(second.latitude)
    delta_lat = lat2 - lat1
    delta_lon = math.radians(second.longitude - first.longitude)

    a = (
        math.sin(delta_lat / 2) ** 2
        + math.cos(lat1) * math.cos(lat2) * math.sin(delta_lon / 2) ** 2
    )
    # Clamp to 1.0 so tiny floating-point errors can't break asin().
    a = min(1.0, a)

    return 2 * EARTH_RADIUS_KM * math.asin(math.sqrt(a))