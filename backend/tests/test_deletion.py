from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, func, select

from app import orm
from app.config import LOGIN_MAX_FAILURES
from app.database import SessionLocal
from app.main import app

client = TestClient(app)
PASSWORD = "correct-horse-battery"
WRONG = "definitely-wrong-password"
SAMPLE_LOG = (Path(__file__).resolve().parents[2] / "data" / "synthetic" / "sample.log").read_bytes()


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


def register(email: str) -> dict[str, str]:
    client.post("/auth/register", json={"email": email, "password": PASSWORD})
    response = client.post("/auth/login", data={"username": email, "password": PASSWORD})
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def upload_sample(headers: dict[str, str]) -> int:
    response = client.post("/analyze", files={"file": ("s.log", SAMPLE_LOG, "text/plain")}, headers=headers)
    return response.json()["upload"]["id"]


def delete_account(headers: dict[str, str], password: str = PASSWORD):
    return client.post("/auth/delete-account", json={"password": password}, headers=headers)


def count(model, condition) -> int:
    with SessionLocal() as db:
        return db.scalar(select(func.count()).select_from(model).where(condition)) or 0


def test_user_can_delete_own_upload():
    headers = register("del-owner@example.com")
    keep_id = upload_sample(headers)
    gone_id = upload_sample(headers)
    assert client.delete(f"/uploads/{gone_id}", headers=headers).status_code == 204
    ids = [upload["id"] for upload in client.get("/uploads", headers=headers).json()]
    assert gone_id not in ids and keep_id in ids
    assert client.get(f"/uploads/{gone_id}/timeline", headers=headers).status_code == 404
    assert count(orm.FindingRecord, orm.FindingRecord.upload_id == gone_id) == 0
    assert count(orm.FindingRecord, orm.FindingRecord.upload_id == keep_id) > 0


def test_cannot_delete_someone_elses_upload():
    owner = register("del-owner@example.com")
    other = register("del-other@example.com")
    upload_id = upload_sample(owner)
    assert client.delete(f"/uploads/{upload_id}", headers=other).status_code == 404
    assert client.get(f"/uploads/{upload_id}/timeline", headers=owner).status_code == 200


def test_delete_requires_login_and_missing_upload_is_404():
    assert client.delete("/uploads/1").status_code == 401
    headers = register("del-owner@example.com")
    assert client.delete("/uploads/999999", headers=headers).status_code == 404


def test_wrong_password_does_not_delete_the_account():
    headers = register("del-wrongpw@example.com")
    assert delete_account(headers, WRONG).status_code == 403
    assert client.get("/auth/me", headers=headers).status_code == 200


def test_account_deletion_removes_the_account_and_all_its_data():
    keeper = register("del-keeper@example.com")
    keeper_upload = upload_sample(keeper)
    headers = register("del-leaver@example.com")
    upload_id = upload_sample(headers)

    assert delete_account(headers).status_code == 204

    assert client.get("/auth/me", headers=headers).status_code == 401  # the old token is dead
    login = client.post("/auth/login", data={"username": "del-leaver@example.com", "password": PASSWORD})
    assert login.status_code == 401
    assert count(orm.User, orm.User.email == "del-leaver@example.com") == 0
    assert count(orm.Upload, orm.Upload.id == upload_id) == 0
    assert count(orm.FindingRecord, orm.FindingRecord.upload_id == upload_id) == 0
    assert [upload["id"] for upload in client.get("/uploads", headers=keeper).json()] == [keeper_upload]


def test_account_deletion_is_throttled_like_login():
    headers = register("del-throttle@example.com")
    for _ in range(LOGIN_MAX_FAILURES):
        assert delete_account(headers, WRONG).status_code == 403
    locked = delete_account(headers)  # even the right password is refused while locked
    assert locked.status_code == 429
    assert int(locked.headers["Retry-After"]) > 0
    assert client.get("/auth/me", headers=headers).status_code == 200