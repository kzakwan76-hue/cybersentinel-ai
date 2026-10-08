"""Runs before any test: temporary database, throwaway secret key, and no ML model."""

import os
import tempfile
from pathlib import Path

os.environ["DATABASE_URL"] = "sqlite:///" + (Path(tempfile.mkdtemp()) / "test.db").as_posix()
os.environ["SECRET_KEY"] = "test-only-secret-key-do-not-use-anywhere-else-0123456789"
os.environ["MODEL_PATH"] = str(Path(tempfile.mkdtemp()) / "no-model.joblib")  # file doesn't exist