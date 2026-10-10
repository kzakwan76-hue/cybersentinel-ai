"""Application settings, read from environment variables (and the .env file)."""

import os
from pathlib import Path

from dotenv import load_dotenv

from app.ml import DEFAULT_MODEL_PATH

load_dotenv()

DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./cybersentinel.db")
MAX_UPLOAD_BYTES: int = int(os.getenv("MAX_UPLOAD_BYTES", "2000000"))  # 2 MB
ACCESS_TOKEN_MINUTES: int = int(os.getenv("ACCESS_TOKEN_MINUTES", "60"))
MODEL_PATH: Path = Path(os.getenv("MODEL_PATH", str(DEFAULT_MODEL_PATH)))
ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")
LLM_MODEL: str = os.getenv("LLM_MODEL", "claude-haiku-4-5-20251001")
LLM_TIMEOUT_SECONDS: float = float(os.getenv("LLM_TIMEOUT_SECONDS", "30"))

SECRET_KEY: str = os.getenv("SECRET_KEY", "")
if not SECRET_KEY:
    raise RuntimeError(
        "SECRET_KEY is not set. Create a .env file (see .env.example) with a random value."
    )