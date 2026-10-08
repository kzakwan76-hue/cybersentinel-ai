"""Hybrid anomaly detector: Isolation Forest plus a range guard, with simple explanations."""

from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from app.ml.features import FEATURE_NAMES

# A value must be this much further out than the most extreme normal example to trip the guard.
RANGE_MARGIN = 1.25


@dataclass(frozen=True)
class Deviation:
    feature: str
    value: float
    typical: float  # average of this feature in the normal training data
    z_score: float  # how many standard deviations away


class AnomalyDetector:
    def __init__(
        self, contamination: float = 0.02, n_estimators: int = 200, random_state: int = 42
    ) -> None:
        # contamination = share of NORMAL training data we accept flagging (about 2% false alarms).
        self._model = IsolationForest(
            n_estimators=n_estimators, contamination=contamination, random_state=random_state
        )
        self._mean: np.ndarray | None = None
        self._std: np.ndarray | None = None
        self._z_limits: np.ndarray | None = None

    def fit(self, matrix: np.ndarray) -> "AnomalyDetector":
        """Learn the normal baseline. Each row = one IP's feature vector."""
        self._model.fit(matrix)
        self._mean = matrix.mean(axis=0)
        std = matrix.std(axis=0)
        self._std = np.where(std < 1e-9, 1.0, std)  # avoid dividing by zero
        # Per-feature limit: how far from average the most extreme NORMAL example was, plus a margin.
        z_train = np.abs((matrix - self._mean) / self._std)
        self._z_limits = np.maximum(z_train.max(axis=0) * RANGE_MARGIN, 1.0)
        return self

    def predict(self, matrix: np.ndarray, use_range_guard: bool = True) -> np.ndarray:
        """Return 1 for anomalous rows and 0 for normal rows."""
        self._check_fitted()
        matrix = np.asarray(matrix, dtype=float)
        flagged = self._model.predict(matrix) == -1
        if use_range_guard:
            z_scores = np.abs((matrix - self._mean) / self._std)
            flagged = flagged | (z_scores > self._z_limits).any(axis=1)
        return flagged.astype(int)

    def explain(self, vector: list[float] | np.ndarray, top_n: int = 3) -> list[Deviation]:
        """The features that differ most from normal: the model's 'why?'."""
        self._check_fitted()
        values = np.asarray(vector, dtype=float)
        z_scores = (values - self._mean) / self._std
        order = np.argsort(-np.abs(z_scores))[:top_n]
        return [
            Deviation(FEATURE_NAMES[i], float(values[i]), float(self._mean[i]), float(z_scores[i]))
            for i in order
        ]

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)

    @staticmethod
    def load(path: Path) -> "AnomalyDetector":
        # Only load model files you created yourself: joblib files can run code when loaded.
        detector = joblib.load(path)
        if not isinstance(detector, AnomalyDetector):
            raise ValueError("Model file does not contain an AnomalyDetector.")
        return detector

    def _check_fitted(self) -> None:
        if self._mean is None or self._std is None or self._z_limits is None:
            raise RuntimeError("Call fit() before using the detector.")