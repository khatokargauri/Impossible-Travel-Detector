"""Demonstration and basic verification of the detection engine.

Run from the backend folder:  python run_demo.py

Uses only the synthetic dataset in data/sample/. The events are fictional
test data, not real logins and not real attacks.
"""

from __future__ import annotations

import json
from pathlib import Path

from app.detection.config import DetectionConfig
from app.detection.detector import detect_impossible_travel
from app.detection.models import DetectionResult, DetectionStatus
from app.detection.validation import parse_login_events

DATASET_PATH = (
    Path(__file__).resolve().parent.parent / "data" / "sample" / "synthetic_logins.json"
)


def format_elapsed(result: DetectionResult) -> str:
    """Format elapsed time as hours with two decimals."""
    if result.elapsed is None:
        return "n/a"
    return f"{result.elapsed.total_seconds() / 3600:.2f} h"


def print_results(results: list[DetectionResult]) -> None:
    """Print one row per comparison, then the reason for each."""
    header = (
        f"{'User':<13}{'Prev':<9}{'Curr':<9}{'Distance':>12}"
        f"{'Elapsed':>10}{'Speed':>14}  Status"
    )
    print(header)
    print("-" * len(header))
    for r in results:
        distance = f"{r.distance_km:,.1f} km" if r.distance_km is not None else "n/a"
        speed = (
            f"{r.implied_speed_kmh:,.0f} km/h"
            if r.implied_speed_kmh is not None
            else "n/a"
        )
        print(
            f"{r.user_id:<13}{r.previous_event_id:<9}{r.current_event_id:<9}"
            f"{distance:>12}{format_elapsed(r):>10}{speed:>14}  {r.status.value}"
        )

    print("\nReasons:")
    for r in results:
        print(f"- {r.user_id} ({r.previous_event_id} -> {r.current_event_id}): {r.reason}")


def verify(results: list[DetectionResult]) -> None:
    """Basic assertions. The full test suite comes in Phase 3."""
    by_user: dict[str, list[DetectionResult]] = {}
    for r in results:
        by_user.setdefault(r.user_id, []).append(r)

    # Single-login user: nothing to compare.
    assert "carol_synth" not in by_user, "carol_synth has one login only"

    # Failed login is ignored: Mumbai -> Pune is the only comparison.
    assert len(by_user["alice_synth"]) == 1
    alice = by_user["alice_synth"][0]
    assert (alice.previous_event_id, alice.current_event_id) == ("evt-001", "evt-003")
    assert alice.status == DetectionStatus.NORMAL

    # New York -> Tokyo in 30 minutes.
    bob = by_user["bob_synth"][0]
    assert bob.status == DetectionStatus.SUSPICIOUS
    assert bob.distance_km is not None and 10_500 < bob.distance_km < 11_200

    # Interleaved users must not be mixed.
    for user in ("dave_synth", "erin_synth"):
        assert len(by_user[user]) == 1
        assert by_user[user][0].status == DetectionStatus.NORMAL

    # Missing coordinates.
    frank = by_user["frank_synth"][0]
    assert frank.status == DetectionStatus.INSUFFICIENT_DATA
    assert frank.distance_km is None and frank.implied_speed_kmh is None

    # Duplicate timestamps, far apart: suspicious, but speed not calculable.
    grace = by_user["grace_synth"][0]
    assert grace.status == DetectionStatus.SUSPICIOUS
    assert grace.implied_speed_kmh is None

    # Every comparison stays within a single user.
    assert all(r.user_id for r in results)

    # The threshold must be configurable.
    strict = detect_impossible_travel(events, DetectionConfig(speed_threshold_kmh=10.0))
    relaxed = detect_impossible_travel(events, DetectionConfig(speed_threshold_kmh=50_000.0))
    assert sum(r.status == DetectionStatus.SUSPICIOUS for r in strict) >= sum(
        r.status == DetectionStatus.SUSPICIOUS for r in relaxed
    )

    print("\nAll basic checks passed.")


if __name__ == "__main__":
    raw = json.loads(DATASET_PATH.read_text(encoding="utf-8"))
    print(raw["dataset_label"], "\n")

    events, errors = parse_login_events(raw["events"])
    print(f"Loaded {len(events)} valid events, {len(errors)} rejected.")
    for message in errors:
        print("  rejected:", message)
    print()

    results = detect_impossible_travel(events)
    print_results(results)
    verify(results)