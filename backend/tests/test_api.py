from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)
PASSWORD = "correct-horse-battery"
SAMPLE_LOG = (Path(__file__).resolve().parents[2] / "data" / "synthetic" / "sample.log").read_bytes()


def auth_headers(email: str) -> dict[str, str]:
    """Register (if new) and log in, returning the Authorization header."""
    client.post("/auth/register", json={"email": email, "password": PASSWORD})
    response = client.post("/auth/login", data={"username": email, "password": PASSWORD})
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


ANALYST = auth_headers("analyst@example.com")
OTHER_USER = auth_headers("other@example.com")  # never uploads anything


def upload(content: bytes, headers: dict[str, str] = ANALYST, name: str = "test.log"):
    return client.post("/analyze", files={"file": (name, content, "text/plain")}, headers=headers)


def test_health():
    assert client.get("/health").json() == {"status": "ok"}


def test_analyze_sample_log_finds_three_threats():
    response = upload(SAMPLE_LOG)
    assert response.status_code == 200
    body = response.json()
    severities = sorted(finding["severity"] for finding in body["findings"])
    assert severities == ["CRITICAL", "HIGH", "MEDIUM"]
    assert body["upload"]["events_parsed"] == 14


def test_findings_can_be_filtered_by_severity():
    upload(SAMPLE_LOG)
    response = client.get("/findings", params={"severity": "CRITICAL"}, headers=ANALYST)
    assert response.status_code == 200
    results = response.json()
    assert len(results) >= 1
    assert all(finding["severity"] == "CRITICAL" for finding in results)


def test_findings_can_be_searched_by_ip():
    upload(SAMPLE_LOG)
    results = client.get("/findings", params={"q": "203.0.113.50"}, headers=ANALYST).json()
    assert len(results) >= 1
    assert all(finding["ip"] == "203.0.113.50" for finding in results)


def test_invalid_severity_is_rejected():
    response = client.get("/findings", params={"severity": "BANANA"}, headers=ANALYST)
    assert response.status_code == 422


def test_garbage_file_is_rejected():
    assert upload(b"hello world\nnot a log").status_code == 422


def test_stats_reflect_saved_data():
    upload(SAMPLE_LOG)
    body = client.get("/stats", headers=ANALYST).json()
    assert body["total_uploads"] >= 1
    assert body["by_severity"]["CRITICAL"] >= 1


def test_endpoints_require_login():
    for path in ["/findings", "/uploads", "/stats"]:
        assert client.get(path).status_code == 401
    response = client.post("/analyze", files={"file": ("x.log", b"1.1.1.1 - FAILED LOGIN", "text/plain")})
    assert response.status_code == 401


def test_users_cannot_see_each_others_data():
    upload(SAMPLE_LOG)  # uploaded by ANALYST
    assert client.get("/findings", headers=OTHER_USER).json() == []
    assert client.get("/uploads", headers=OTHER_USER).json() == []
    assert client.get("/stats", headers=OTHER_USER).json()["total_uploads"] == 0


def test_dashboard_is_served():
    assert client.get("/dashboard/").status_code == 200