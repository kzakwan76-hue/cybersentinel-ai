from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete

from app import orm
from app.config import LOGIN_MAX_FAILURES, LOGIN_MAX_FAILURES_PER_IP, LOGIN_WINDOW_MINUTES
from app.database import SessionLocal
from app.main import app

client = TestClient(app)
PASSWORD = "correct-horse-battery"
WRONG = "definitely-wrong-password"


def register(email: str) -> None:
    client.post("/auth/register", json={"email": email, "password": PASSWORD})


def attempt(email: str, password: str):
    return client.post("/auth/login", data={"username": email, "password": password})


def wipe_failures() -> None:
    with SessionLocal() as db:
        db.execute(delete(orm.LoginFailure))
        db.commit()


@pytest.fixture(autouse=True)
def clean_failures():
    # All tests share one client IP, so every test starts and ends with a clean slate.
    wipe_failures()
    yield
    wipe_failures()


def test_repeated_failures_lock_out_even_the_right_password():
    register("lock@example.com")
    for _ in range(LOGIN_MAX_FAILURES):
        assert attempt("lock@example.com", WRONG).status_code == 401
    locked = attempt("lock@example.com", PASSWORD)
    assert locked.status_code == 429
    assert int(locked.headers["Retry-After"]) > 0


def test_unknown_emails_are_throttled_too_so_nothing_is_revealed():
    for _ in range(LOGIN_MAX_FAILURES):
        assert attempt("ghost@example.com", WRONG).status_code == 401
    assert attempt("ghost@example.com", WRONG).status_code == 429


def test_successful_login_clears_the_failure_count():
    register("clear@example.com")
    for _ in range(LOGIN_MAX_FAILURES - 2):
        assert attempt("clear@example.com", WRONG).status_code == 401
    assert attempt("clear@example.com", PASSWORD).status_code == 200
    for _ in range(LOGIN_MAX_FAILURES - 1):
        assert attempt("clear@example.com", WRONG).status_code == 401


def test_locking_one_account_does_not_block_another():
    register("victim@example.com")
    register("neighbour@example.com")
    for _ in range(LOGIN_MAX_FAILURES):
        attempt("victim@example.com", WRONG)
    assert attempt("victim@example.com", PASSWORD).status_code == 429
    assert attempt("neighbour@example.com", PASSWORD).status_code == 200


def test_per_ip_limit_stops_guessing_across_many_accounts():
    for number in range(LOGIN_MAX_FAILURES_PER_IP):
        assert attempt(f"stuffing{number}@example.com", WRONG).status_code == 401
    assert attempt("fresh@example.com", WRONG).status_code == 429


def test_old_failures_do_not_count():
    register("expired@example.com")
    old = datetime.now(timezone.utc) - timedelta(minutes=LOGIN_WINDOW_MINUTES + 5)
    with SessionLocal() as db:
        db.add_all(
            orm.LoginFailure(email="expired@example.com", ip="testclient", created_at=old)
            for _ in range(LOGIN_MAX_FAILURES)
        )
        db.commit()
    assert attempt("expired@example.com", PASSWORD).status_code == 200