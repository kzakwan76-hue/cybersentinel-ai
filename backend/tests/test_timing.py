from app.ml.synthetic import generate_dataset
from app.models import EventType, Severity
from app.services.detectors import detect, parse_timestamp
from app.services.parser import parse_logs

FAST = (
    "2026-10-05 09:00:00 1.1.1.1 - FAILED LOGIN\n"
    "2026-10-05 09:00:02 1.1.1.1 - FAILED LOGIN\n"
    "2026-10-05 09:00:04 1.1.1.1 - FAILED LOGIN\n"
    "2026-10-05 09:00:06 1.1.1.1 - SUCCESSFUL LOGIN\n"
)
SLOW = (  # same events, but two minutes apart: a person retyping a password
    "2026-10-05 09:00:00 1.1.1.1 - FAILED LOGIN\n"
    "2026-10-05 09:02:00 1.1.1.1 - FAILED LOGIN\n"
    "2026-10-05 09:04:00 1.1.1.1 - FAILED LOGIN\n"
    "2026-10-05 09:06:00 1.1.1.1 - SUCCESSFUL LOGIN\n"
)
SLOW_MANY = (
    "2026-10-05 09:00:00 1.1.1.1 - FAILED LOGIN\n"
    "2026-10-05 09:02:00 1.1.1.1 - FAILED LOGIN\n"
    "2026-10-05 09:04:00 1.1.1.1 - FAILED LOGIN\n"
    "2026-10-05 09:06:00 1.1.1.1 - FAILED LOGIN\n"
    "2026-10-05 09:08:00 1.1.1.1 - FAILED LOGIN\n"
    "2026-10-05 09:10:00 1.1.1.1 - SUCCESSFUL LOGIN\n"
)
NO_TIMESTAMPS = "1.1.1.1 - FAILED LOGIN\n" * 3 + "1.1.1.1 - SUCCESSFUL LOGIN\n"


def analyze(text: str, use_timing: bool = True):
    return detect(parse_logs(text).events, use_timing=use_timing)


def failure_gaps(session) -> list[float]:
    times = [
        parse_timestamp(event.timestamp)
        for event in session.events
        if event.event_type == EventType.FAILED_LOGIN
    ]
    return [(later - earlier).total_seconds() for earlier, later in zip(times, times[1:])]


def test_fast_failures_then_success_is_brute_force():
    findings = analyze(FAST)
    assert len(findings) == 1
    assert findings[0].title == "Possible Brute-Force Attack"
    assert findings[0].severity == Severity.HIGH


def test_slow_failures_then_success_is_not_brute_force():
    assert analyze(SLOW) == []


def test_count_only_mode_still_flags_slow_failures():
    assert len(analyze(SLOW, use_timing=False)) == 1


def test_many_slow_failures_are_still_flagged():
    findings = analyze(SLOW_MANY)
    assert [finding.title for finding in findings] == ["Possible Brute-Force Attack"]


def test_logs_without_timestamps_fall_back_to_counting():
    assert len(analyze(NO_TIMESTAMPS)) == 1


def test_reason_mentions_timing_when_available():
    assert "4 seconds" in analyze(FAST)[0].reason


def test_forgetful_users_fail_slowly():
    sessions = [s for s in generate_dataset(n_normal=400, n_attack=0, seed=3) if s.kind == "forgetful_user"]
    assert sessions
    assert all(gap >= 20 for session in sessions for gap in failure_gaps(session))


def test_brute_force_attackers_fail_quickly():
    sessions = [s for s in generate_dataset(n_normal=0, n_attack=200, seed=3) if s.kind == "brute_force"]
    assert sessions
    assert all(gap <= 3 for session in sessions for gap in failure_gaps(session))


def test_dataset_is_reproducible():
    assert generate_dataset(n_normal=50, n_attack=20, seed=5) == generate_dataset(n_normal=50, n_attack=20, seed=5)