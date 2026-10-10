"""Login throttling: slow down password guessing against our OWN login endpoint.

Failed attempts are stored in the database, so limits survive restarts and work across several
server processes. Two limits apply inside a sliding time window:
  - per (email, IP) pair: stops one client hammering one account
  - per IP: stops one client trying many accounts (credential stuffing)
The email is whatever was typed, even if no such account exists, so the behavior never reveals
whether an account exists.
"""

import math
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app import orm
from app.config import LOGIN_MAX_FAILURES, LOGIN_MAX_FAILURES_PER_IP, LOGIN_WINDOW_MINUTES


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(moment: datetime) -> datetime:
    """SQLite hands back naive datetimes; they were stored as UTC."""
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def seconds_until_allowed(db: Session, email: str, ip: str) -> int:
    """0 if this attempt may proceed, otherwise how many seconds the client must wait."""
    window = timedelta(minutes=LOGIN_WINDOW_MINUTES)
    now = _now()
    cutoff = now - window
    rules = (
        ((orm.LoginFailure.email == email, orm.LoginFailure.ip == ip), LOGIN_MAX_FAILURES),
        ((orm.LoginFailure.ip == ip,), LOGIN_MAX_FAILURES_PER_IP),
    )

    longest_wait = 0
    for conditions, limit in rules:
        times = list(
            db.scalars(
                select(orm.LoginFailure.created_at)
                .where(*conditions, orm.LoginFailure.created_at > cutoff)
                .order_by(orm.LoginFailure.created_at)
            )
        )
        if len(times) >= limit:
            # The lock lifts when enough old failures expire to drop below the limit.
            unlock_at = _as_utc(times[len(times) - limit]) + window
            longest_wait = max(longest_wait, math.ceil((unlock_at - now).total_seconds()), 1)
    return longest_wait


def record_failure(db: Session, email: str, ip: str) -> None:
    now = _now()
    db.add(orm.LoginFailure(email=email, ip=ip, created_at=now))
    # Housekeeping: forget failures that are far too old to matter.
    stale = now - 2 * timedelta(minutes=LOGIN_WINDOW_MINUTES)
    db.execute(delete(orm.LoginFailure).where(orm.LoginFailure.created_at < stale))
    db.commit()


def clear_failures(db: Session, email: str, ip: str) -> None:
    """A successful login wipes this email-and-IP pair's failure count."""
    db.execute(delete(orm.LoginFailure).where(orm.LoginFailure.email == email, orm.LoginFailure.ip == ip))
    db.commit()