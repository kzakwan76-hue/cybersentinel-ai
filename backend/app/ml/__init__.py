"""Machine-learning layer: features, anomaly detector, synthetic data, evaluation."""

from pathlib import Path

# backend/models/anomaly.joblib
DEFAULT_MODEL_PATH = Path(__file__).resolve().parents[2] / "models" / "anomaly.joblib"