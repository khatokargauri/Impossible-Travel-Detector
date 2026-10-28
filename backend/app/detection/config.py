"""Configuration for the impossible travel detector.

Settings live here so detection rules can be tuned without editing the
detection logic.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

# A commercial jet cruises at roughly 800-900 km/h, so a sustained speed
# above this between two logins is hard to explain by real travel.
DEFAULT_SPEED_THRESHOLD_KMH = 900.0

# IP geolocation is often off by tens of kilometres, so very short hops
# are treated as noise rather than travel.
DEFAULT_MIN_DISTANCE_KM = 50.0


@dataclass(frozen=True)
class DetectionConfig:
    """Tunable settings for the detector.

    Attributes:
        speed_threshold_kmh: Implied speeds above this are SUSPICIOUS.
        min_distance_km: Distances below this are always NORMAL, because
            IP geolocation error makes tiny jumps unreliable.
        max_gap_hours: If set, login pairs further apart than this are
            treated as NORMAL (the user had ample time to travel).
        only_successful_logins: If True, failed logins are ignored.
    """

    speed_threshold_kmh: float = DEFAULT_SPEED_THRESHOLD_KMH
    min_distance_km: float = DEFAULT_MIN_DISTANCE_KM
    max_gap_hours: float | None = None
    only_successful_logins: bool = True

    def __post_init__(self) -> None:
        """Reject nonsensical settings as soon as the config is created."""
        if not math.isfinite(self.speed_threshold_kmh) or self.speed_threshold_kmh <= 0:
            raise ValueError("speed_threshold_kmh must be a positive number")
        if not math.isfinite(self.min_distance_km) or self.min_distance_km < 0:
            raise ValueError("min_distance_km must be zero or greater")
        if self.max_gap_hours is not None and (
            not math.isfinite(self.max_gap_hours) or self.max_gap_hours <= 0
        ):
            raise ValueError("max_gap_hours must be a positive number or None")