"""One repeatable experiment: generate data, split, train, and score every detection method."""

from dataclasses import dataclass

import numpy as np
from sklearn.model_selection import train_test_split

from app.ml.anomaly import AnomalyDetector
from app.ml.evaluate import Metrics, evaluate
from app.ml.features import feature_vector
from app.ml.synthetic import generate_dataset
from app.services.detectors import detect

METHODS = [
    "Rules (count only)",
    "Rules (with timing)",
    "Forest only",
    "ML (full)",
    "Rules(count) + ML",
    "Rules(timing) + ML",
]


@dataclass(frozen=True)
class ExperimentResult:
    seed: int
    metrics: dict[str, Metrics]
    flag_rate_by_kind: dict[str, dict[str, float]]  # session type -> method -> share flagged
    kind_is_attack: dict[str, bool]


def run_experiment(seed: int, n_normal: int = 800, n_attack: int = 200) -> ExperimentResult:
    """Everything random (data, split, model) is driven by `seed`, so a seed always repeats exactly."""
    sessions = generate_dataset(n_normal=n_normal, n_attack=n_attack, seed=seed)
    train, test = train_test_split(
        sessions, test_size=0.3, stratify=[s.label for s in sessions], random_state=seed
    )

    # Learn the baseline from NORMAL training sessions only.
    normal_matrix = np.array([feature_vector(s.events) for s in train if s.label == 0])
    detector = AnomalyDetector(random_state=seed).fit(normal_matrix)

    y_true = [s.label for s in test]
    test_matrix = np.array([feature_vector(s.events) for s in test])
    forest = detector.predict(test_matrix, use_range_guard=False).tolist()
    ml = detector.predict(test_matrix).tolist()

    test_events = [event for session in test for event in session.events]
    count_ips = {finding.ip for finding in detect(test_events, use_timing=False)}
    timing_ips = {finding.ip for finding in detect(test_events)}
    count_flags = [int(s.ip in count_ips) for s in test]
    timing_flags = [int(s.ip in timing_ips) for s in test]

    flags = {
        "Rules (count only)": count_flags,
        "Rules (with timing)": timing_flags,
        "Forest only": forest,
        "ML (full)": ml,
        "Rules(count) + ML": [int(r or m) for r, m in zip(count_flags, ml)],
        "Rules(timing) + ML": [int(r or m) for r, m in zip(timing_flags, ml)],
    }
    metrics = {name: evaluate(y_true, predicted) for name, predicted in flags.items()}

    flag_rate_by_kind: dict[str, dict[str, float]] = {}
    kind_is_attack: dict[str, bool] = {}
    for kind in sorted({s.kind for s in test}):
        indexes = [i for i, s in enumerate(test) if s.kind == kind]
        flag_rate_by_kind[kind] = {
            name: sum(predicted[i] for i in indexes) / len(indexes) for name, predicted in flags.items()
        }
        kind_is_attack[kind] = bool(test[indexes[0]].label)

    return ExperimentResult(seed, metrics, flag_rate_by_kind, kind_is_attack)