from fastapi.testclient import TestClient
from sqlalchemy import select

from app import orm
from app.database import SessionLocal
from app.main import app

client = TestClient(app)
PASSWORD = "correct-horse-battery"


def register(email: str, password: str = PASSWORD):
    return client.post("/auth/register", json={"email": email, "password": password})


def login(email: str, password: str = PASSWORD):
    return client.post("/auth/login", data={"username": email, "password": password})


def test_register_returns_user_without_password():
    response = register("new@example.com")
    assert response.status_code == 201
    body = response.json()
    assert body["email"] == "new@example.com"
    assert "password" not in body and "password_hash" not in body


def test_duplicate_email_is_rejected():
    register("dupe@example.com")
    assert register("DUPE@example.com").status_code == 409


def test_short_password_is_rejected():
    assert register("short@example.com", "abc").status_code == 422


def test_invalid_email_is_rejected():
    assert register("not-an-email").status_code == 422


def test_wrong_password_is_rejected():
    register("wrongpw@example.com")
    assert login("wrongpw@example.com", "totally-wrong-password").status_code == 401


def test_unknown_email_is_rejected():
    assert login("nobody@example.com").status_code == 401


def test_me_returns_logged_in_user():
    register("me@example.com")
    token = login("me@example.com").json()["access_token"]
    response = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["email"] == "me@example.com"


def test_bad_token_is_rejected():
    response = client.get("/auth/me", headers={"Authorization": "Bearer not.a.real.token"})
    assert response.status_code == 401


def test_password_is_stored_as_a_hash():
    register("hashed@example.com")
    with SessionLocal() as db:
        user = db.scalar(select(orm.User).where(orm.User.email == "hashed@example.com"))
        assert user is not None
        assert PASSWORD not in user.password_hash
        assert user.password_hash.startswith("$argon2")