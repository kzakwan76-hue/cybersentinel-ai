"""Train and evaluate the anomaly detector on synthetic data.

Run from the project root:  python backend\\train_anomaly.py
"""

import numpy as np
from sklearn.model_selection import train_test_split

from app.ml import DEFAULT_MODEL_PATH
from app.ml.anomaly import AnomalyDetector
from app.ml.evaluate import Metrics, evaluate
from app.ml.features import feature_vector
from app.ml.synthetic import LabeledSession, generate_dataset
from app.services.detectors import detect

RANDOM_SEED = 42


def print_metrics(name: str, metrics: Metrics) -> None:
    print(
        f"{name:<22} precision={metrics.precision:.2f}  recall={metrics.recall:.2f}  "
        f"F1={metrics.f1:.2f}"
    )
    print(f"{'':<22} confusion matrix:  TN={metrics.true_negatives:<4} FP={metrics.false_positives:<4}")
    print(f"{'':<22}                    FN={metrics.false_negatives:<4} TP={metrics.true_positives:<4}\n")


def print_by_kind(test: list[LabeledSession], predictions: dict[str, list[int]]) -> None:
    print("How many sessions of each type were FLAGGED (attacks: higher is better, normal: lower is better)")
    header = f"{'session type':<20}{'attack?':<9}{'total':>6}" + "".join(f"{n:>11}" for n in predictions)
    print(header)
    print("-" * len(header))
    for kind in sorted({s.kind for s in test}, key=lambda k: (next(s.label for s in test if s.kind == k), k)):
        indexes = [i for i, s in enumerate(test) if s.kind == kind]
        is_attack = "yes" if test[indexes[0]].label else "no"
        cells = "".join(f"{sum(p[i] for i in indexes):>11}" for p in predictions.values())
        print(f"{kind:<20}{is_attack:<9}{len(indexes):>6}{cells}")


def main() -> None:
    sessions = generate_dataset(seed=RANDOM_SEED)
    train, test = train_test_split(
        sessions, test_size=0.3, stratify=[s.label for s in sessions], random_state=RANDOM_SEED
    )

    # Learn the baseline from NORMAL training sessions only.
    normal_matrix = np.array([feature_vector(s.events) for s in train if s.label == 0])
    detector = AnomalyDetector().fit(normal_matrix)
    detector.save(DEFAULT_MODEL_PATH)

    y_true = [s.label for s in test]
    test_matrix = np.array([feature_vector(s.events) for s in test])
    forest_flags = detector.predict(test_matrix, use_range_guard=False).tolist()
    ml_flags = detector.predict(test_matrix).tolist()

    test_events = [event for session in test for event in session.events]
    count_ips = {finding.ip for finding in detect(test_events, use_timing=False)}
    timing_ips = {finding.ip for finding in detect(test_events)}
    count_flags = [int(s.ip in count_ips) for s in test]
    timing_flags = [int(s.ip in timing_ips) for s in test]
    combined_count = [int(r or m) for r, m in zip(count_flags, ml_flags)]
    combined_timing = [int(r or m) for r, m in zip(timing_flags, ml_flags)]

    print(f"Trained on {len(normal_matrix)} normal sessions. Tested on {len(test)} unseen sessions "
          f"({sum(y_true)} attacks, {len(y_true) - sum(y_true)} normal).\n")
    print_metrics("Rules (count only)", evaluate(y_true, count_flags))
    print_metrics("Rules (with timing)", evaluate(y_true, timing_flags))
    print_metrics("Forest only", evaluate(y_true, forest_flags))
    print_metrics("ML (full)", evaluate(y_true, ml_flags))
    print_metrics("Rules(count) + ML", evaluate(y_true, combined_count))
    print_metrics("Rules(timing) + ML", evaluate(y_true, combined_timing))
    print_by_kind(
        test,
        {
            "rules": count_flags,
            "rules+time": timing_flags,
            "forest": forest_flags,
            "ML": ml_flags,
            "both": combined_timing,
        },
    )
    print(f"\nModel saved to {DEFAULT_MODEL_PATH}")


if __name__ == "__main__":
    main()