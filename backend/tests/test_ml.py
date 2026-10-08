import numpy as np
import pytest

from app.ml.anomaly import AnomalyDetector
from app.ml.features import FEATURE_NAMES, feature_vector
from app.ml.synthetic import generate_dataset
from app.models import Event, EventType
from app.services.analysis import analyze_events
from app.services.detectors import detect
from app.services.parser import parse_logs


@pytest.fixture(scope="module")
def trained() -> AnomalyDetector:
    normal = generate_dataset(n_normal=600, n_attack=0, seed=7)
    return AnomalyDetector().fit(np.array([feature_vector(s.events) for s in normal]))


def bulk_events(ip: str = "10.9.9.9") -> list[Event]:
    """One valid login, then 80 page requests: rules see nothing wrong."""
    events = [Event(1, None, ip, EventType.SUCCESS_LOGIN, None)]
    events += [Event(i + 2, None, ip, EventType.ACCESS, "/reports") for i in range(80)]
    return events


def test_feature_vector_counts_correctly():
    events = parse_logs(
        "1.1.1.1 - FAILED LOGIN\n1.1.1.1 - FAILED LOGIN\n1.1.1.1 - FAILED LOGIN\n"
        "1.1.1.1 - SUCCESSFUL LOGIN\n1.1.1.1 - ACCESS /admin\n1.1.1.1 - ACCESS /dashboard\n"
    ).events
    features = dict(zip(FEATURE_NAMES, feature_vector(events)))
    assert features["total_events"] == 6
    assert features["failed_logins"] == 3
    assert features["successful_logins"] == 1
    assert features["access_events"] == 2
    assert features["failure_ratio"] == pytest.approx(0.75)
    assert features["distinct_paths"] == 2
    assert features["sensitive_hits"] == 1
    assert features["max_failure_streak"] == 3


def test_model_rarely_flags_unseen_normal_behavior(trained):
    unseen = generate_dataset(n_normal=300, n_attack=0, seed=8)
    flags = trained.predict(np.array([feature_vector(s.events) for s in unseen]))
    assert flags.mean() < 0.2


def test_model_flags_bulk_access_attacks(trained):
    attacks = [s for s in generate_dataset(n_normal=0, n_attack=120, seed=9) if s.kind == "bulk_access"]
    flags = trained.predict(np.array([feature_vector(s.events) for s in attacks]))
    assert flags.mean() >= 0.5


def test_ml_adds_finding_for_behavior_rules_miss(trained):
    events = bulk_events()
    assert detect(events) == []
    findings = analyze_events(events, model=trained)
    assert [finding.title for finding in findings] == ["Anomalous Behavior (ML)"]
    assert "access_events" in findings[0].reason or "total_events" in findings[0].reason


def test_rule_flagged_ip_gets_no_duplicate_ml_finding(trained):
    text = (
        "1.1.1.1 - FAILED LOGIN\n1.1.1.1 - FAILED LOGIN\n1.1.1.1 - FAILED LOGIN\n"
        "1.1.1.1 - SUCCESSFUL LOGIN\n1.1.1.1 - ACCESS /admin\n"
    )
    findings = analyze_events(parse_logs(text).events, model=trained)
    assert [finding.title for finding in findings] == ["Brute-Force Compromise with Admin Activity"]


def test_without_a_model_only_rules_run():
    events = parse_logs("203.0.113.50 - ACCESS /.env\n").events
    assert analyze_events(events) == detect(events)