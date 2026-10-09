"""Database engine and session handling (SQLAlchemy)."""

from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import DATABASE_URL

# SQLite needs this flag because FastAPI uses multiple threads.
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

url = DATABASE_URL
if url.startswith("postgres://"):
    url = url.replace("postgres://", "postgresql+psycopg://", 1)
elif url.startswith("postgresql://"):
    url = url.replace("postgresql://", "postgresql+psycopg://", 1)

engine = create_engine(url, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False)
pool_pre_ping=True


class Base(DeclarativeBase):
    """Parent class for all database tables."""


def get_db() -> Iterator[Session]:
    """Give each request its own database session, and always close it."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()