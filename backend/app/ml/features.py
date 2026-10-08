"""Turn raw events into numeric features the model can learn from."""

from collections import defaultdict

from app.models import Event, EventType
from app.services.detectors import SENSITIVE_PATHS

FEATURE_NAMES = [
    "total_events",
    "failed_logins",
    "successful_logins",
    "access_events",
    "failure_ratio",
    "distinct_paths",
    "sensitive_hits",
    "max_failure_streak",
]


def group_by_ip(events: list[Event]) -> dict[str, list[Event]]:
    grouped: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        grouped[event.ip].append(event)
    return dict(grouped)


def feature_vector(events: list[Event]) -> list[float]:
    """Summarize ALL events from ONE source IP as a list of numbers (order = FEATURE_NAMES)."""
    failed = successes = accesses = sensitive = streak = max_streak = 0
    paths: set[str] = set()

    for event in events:
        if event.event_type == EventType.FAILED_LOGIN:
            failed += 1
            streak += 1
            max_streak = max(max_streak, streak)
            continue
        streak = 0  # anything other than a failure ends the streak
        if event.event_type == EventType.SUCCESS_LOGIN:
            successes += 1
        elif event.event_type == EventType.ACCESS:
            accesses += 1
            if event.path:
                paths.add(event.path)
                if event.path in SENSITIVE_PATHS:
                    sensitive += 1

    attempts = failed + successes
    failure_ratio = failed / attempts if attempts else 0.0

    return [
        float(len(events)),
        float(failed),
        float(successes),
        float(accesses),
        failure_ratio,
        float(len(paths)),
        float(sensitive),
        float(max_streak),
    ]