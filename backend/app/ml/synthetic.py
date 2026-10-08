"""Synthetic labelled sessions for training and evaluating the anomaly detector.

Labels come from how each session was GENERATED (ground truth), never from our rules.
Timestamps are drawn from a SEPARATE random generator, so adding them does not change which
sessions are produced.
"""

import random
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta

from app.models import Event, EventType
from app.services.detectors import SENSITIVE_PATHS

Step = tuple[EventType, str | None]

NORMAL_PATHS = ["/dashboard", "/home", "/profile", "/reports", "/settings", "/search"]
ADMIN_PATHS = ["/admin", "/config"]
SENSITIVE_LIST = sorted(SENSITIVE_PATHS)  # sorted so results are reproducible
PROBE_PATHS = SENSITIVE_LIST + [f"/scan/{n}" for n in range(60)]

FAIL: Step = (EventType.FAILED_LOGIN, None)
SUCCESS: Step = (EventType.SUCCESS_LOGIN, None)

NORMAL_KINDS = ["typical_user", "heavy_user", "forgetful_user", "admin_user"]
NORMAL_WEIGHTS = [0.70, 0.12, 0.08, 0.10]
ATTACK_KINDS = [
    "brute_force",
    "brute_no_success",
    "scanner",
    "sensitive_probe",
    "post_login_abuse",
    "bulk_access",
]

BASE_TIME = datetime(2026, 10, 5, 8, 0, 0)
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"

# Seconds between consecutive events, per session type:
# (range around login attempts, range between other events).
TIMING: dict[str, tuple[tuple[int, int], tuple[int, int]]] = {
    "typical_user": ((10, 60), (2, 30)),
    "heavy_user": ((10, 60), (2, 30)),
    "forgetful_user": ((20, 150), (2, 30)),  # a person retyping a password: slow
    "admin_user": ((10, 60), (2, 30)),
    "brute_force": ((1, 3), (1, 5)),  # a script: fast
    "brute_no_success": ((1, 3), (1, 3)),
    "scanner": ((0, 2), (0, 2)),
    "sensitive_probe": ((0, 2), (1, 10)),
    "post_login_abuse": ((1, 5), (1, 20)),
    "bulk_access": ((1, 5), (0, 2)),
}


@dataclass
class LabeledSession:
    ip: str
    kind: str
    label: int  # 0 = normal, 1 = attack
    events: list[Event]


def _visits(rng: random.Random, count: int, paths: list[str]) -> list[Step]:
    return [(EventType.ACCESS, rng.choice(paths)) for _ in range(count)]


def _typical_user(rng: random.Random) -> list[Step]:
    return [FAIL] * rng.randint(0, 2) + [SUCCESS] + _visits(rng, rng.randint(3, 12), NORMAL_PATHS)


def _heavy_user(rng: random.Random) -> list[Step]:
    return [FAIL] * rng.randint(0, 1) + [SUCCESS] + _visits(rng, rng.randint(15, 30), NORMAL_PATHS)


def _forgetful_user(rng: random.Random) -> list[Step]:
    # Mistypes the password 3-4 times, then gets in. Normal, but looks suspicious to a naive rule.
    return [FAIL] * rng.randint(3, 4) + [SUCCESS] + _visits(rng, rng.randint(2, 8), NORMAL_PATHS)


def _admin_user(rng: random.Random) -> list[Step]:
    return (
        [SUCCESS]
        + _visits(rng, rng.randint(2, 8), NORMAL_PATHS)
        + _visits(rng, rng.randint(1, 2), ADMIN_PATHS)
    )


def _brute_force(rng: random.Random) -> list[Step]:
    return [FAIL] * rng.randint(6, 40) + [SUCCESS] + _visits(rng, rng.randint(1, 3), SENSITIVE_LIST)


def _brute_no_success(rng: random.Random) -> list[Step]:
    return [FAIL] * rng.randint(8, 40)


def _scanner(rng: random.Random) -> list[Step]:
    return _visits(rng, rng.randint(10, 40), PROBE_PATHS)


def _sensitive_probe(rng: random.Random) -> list[Step]:
    return _visits(rng, rng.randint(1, 3), SENSITIVE_LIST)


def _post_login_abuse(rng: random.Random) -> list[Step]:
    # Valid login, then straight to many sensitive pages (stolen credentials).
    return [SUCCESS] + _visits(rng, rng.randint(4, 8), SENSITIVE_LIST)


def _bulk_access(rng: random.Random) -> list[Step]:
    # Valid login, then an unusually huge number of requests (data harvesting).
    return [SUCCESS] + _visits(rng, rng.randint(60, 100), NORMAL_PATHS)


_BUILDERS: dict[str, Callable[[random.Random], list[Step]]] = {
    "typical_user": _typical_user,
    "heavy_user": _heavy_user,
    "forgetful_user": _forgetful_user,
    "admin_user": _admin_user,
    "brute_force": _brute_force,
    "brute_no_success": _brute_no_success,
    "scanner": _scanner,
    "sensitive_probe": _sensitive_probe,
    "post_login_abuse": _post_login_abuse,
    "bulk_access": _bulk_access,
}


def _timestamps(kind: str, steps: list[Step], rng: random.Random) -> list[str]:
    """One timestamp per step. Login attempts and other events use different speeds per kind."""
    login_gap, other_gap = TIMING[kind]
    current = BASE_TIME + timedelta(seconds=rng.randint(0, 8 * 3600))
    stamps = [current.strftime(TIME_FORMAT)]
    for previous, step in zip(steps, steps[1:]):
        around_login_attempt = EventType.FAILED_LOGIN in (previous[0], step[0])
        low, high = login_gap if around_login_attempt else other_gap
        current += timedelta(seconds=rng.randint(low, high))
        stamps.append(current.strftime(TIME_FORMAT))
    return stamps


def generate_dataset(n_normal: int = 800, n_attack: int = 200, seed: int = 42) -> list[LabeledSession]:
    """One session per unique IP. The same seed always gives the same data."""
    rng = random.Random(seed)
    time_rng = random.Random(seed + 1)  # separate, so timestamps don't change the sessions
    sessions: list[LabeledSession] = []
    next_line = 1

    for label, count in ((0, n_normal), (1, n_attack)):
        for _ in range(count):
            if label == 0:
                kind = rng.choices(NORMAL_KINDS, weights=NORMAL_WEIGHTS)[0]
            else:
                kind = rng.choice(ATTACK_KINDS)
            ip = f"10.0.{len(sessions) // 256}.{len(sessions) % 256}"
            steps = _BUILDERS[kind](rng)
            stamps = _timestamps(kind, steps, time_rng)
            events = [
                Event(next_line + i, stamps[i], ip, event_type, path)
                for i, (event_type, path) in enumerate(steps)
            ]
            next_line += len(events)
            sessions.append(LabeledSession(ip, kind, label, events))

    rng.shuffle(sessions)
    return sessions