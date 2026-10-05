"""Runs before any test: use a temporary database and a throwaway secret key."""

import os
import tempfile
from pathlib import Path

os.environ["DATABASE_URL"] = "sqlite:///" + (Path(tempfile.mkdtemp()) / "test.db").as_posix()
os.environ["SECRET_KEY"] = "test-only-secret-key-do-not-use-anywhere-else-0123456789"