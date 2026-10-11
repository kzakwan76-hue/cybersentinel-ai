from pathlib import Path
from types import SimpleNamespace

from fastapi.testclient import TestClient

from app.main import app
from app.models import Event, EventType
from app.services.timeline import build_timeline, markers_for

client = TestClient(app)
PASSWORD = "correct-horse-battery"
SAMPLE_LOG = (Path(__file__).resolve().parents[2] / "data" / "synthetic" / "sample.log").read_bytes()


def event(stamp: str | None, kind: EventType = EventType.ACCESS) -> Event:
    return Event(1, stamp, "1.1.1.1", kind, "/x" if kind == EventType.ACCESS else None)


def test_no_timestamps_means_no_timeline():
    assert build_timeline([event(None)]) is None
    assert build_timeline([event("2026-10-05 09:00:00", EventType.OTHER)]) is None


def test_counts_land_in_the_right_buckets():
    timeline = build_timeline(
        [
            event("2026-10-05 09:00:00", EventType.FAILED_LOGIN),
            event("2026-10-05 09:00:03", EventType.FAILED_LOGIN),
            event("2026-10-05 09:00:30", EventType.SUCCESS_LOGIN),
            event("2026-10-05 09:01:00", EventType.ACCESS),
        ]
    )
    assert timeline["bucket_seconds"] == 5
    assert timeline["start"] == "2026-10-05 09:00:00"
    assert timeline["end"] == "2026-10-05 09:01:05"
    assert len(timeline["counts"]) == 13
    assert timeline["counts"][0] == [2, 0, 0]
    assert timeline["counts"][6] == [0, 1, 0]
    assert timeline["counts"][12] == [0, 0, 1]


def test_one_instant_gives_one_bucket():
    timeline = build_timeline(
        [event("2026-10-05 09:00:00", EventType.FAILED_LOGIN), event("2026-10-05 09:00:00")]
    )
    assert timeline["bucket_seconds"] == 1
    assert timeline["counts"] == [[1, 0, 1]]


def test_long_spans_are_capped():
    timeline = build_timeline([event("2026-01-01 00:00:00"), event("2026-12-31 00:00:00")])
    assert len(timeline["counts"]) <= 48
    assert sum(sum(bucket) for bucket in timeline["counts"]) == 2


def test_events_without_timestamps_are_left_out():
    timeline = build_timeline([event("2026-10-05 09:00:00"), event(None)])
    assert sum(sum(bucket) for bucket in timeline["counts"]) == 1


def test_absurd_timestamps_do_not_crash():
    result = build_timeline([event("2026-01-01 00:00:00"), event("9999-12-31 23:59:59")])
    assert result is None or len(result["counts"]) <= 48


def test_markers_point_at_the_right_bucket():
    timeline = build_timeline(
        [
            event("2026-10-05 09:00:00", EventType.FAILED_LOGIN),
            event("2026-10-05 09:00:30", EventType.SUCCESS_LOGIN),
            event("2026-10-05 09:01:00"),
        ]
    )

    def finding(stamp: str | None):
        return SimpleNamespace(log_timestamp=stamp, severity="HIGH", title="t", ip="1.1.1.1")

    markers = markers_for(
        timeline, [finding("2026-10-05 09:00:30"), finding(None), finding("2026-10-05 09:10:00")]
    )
    assert [marker["bucket"] for marker in markers] == [6]


def auth_headers(email: str) -> dict[str, str]:
    client.post("/auth/register", json={"email": email, "password": PASSWORD})
    response = client.post("/auth/login", data={"username": email, "password": PASSWORD})
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def upload(headers: dict[str, str], content: bytes) -> int:
    response = client.post("/analyze", files={"file": ("t.log", content, "text/plain")}, headers=headers)
    return response.json()["upload"]["id"]


def test_timeline_endpoint_for_the_sample_log():
    headers = auth_headers("timeline-owner@example.com")
    body = client.get(f"/uploads/{upload(headers, SAMPLE_LOG)}/timeline", headers=headers).json()
    assert body["available"] is True
    assert [sum(column) for column in zip(*body["counts"])] == [9, 2, 3]  # failed, success, access
    assert {marker["severity"] for marker in body["markers"]} == {"CRITICAL", "HIGH", "MEDIUM"}


def test_timeline_unavailable_without_timestamps():
    headers = auth_headers("timeline-owner@example.com")
    body = client.get(f"/uploads/{upload(headers, b'1.1.1.1 - FAILED LOGIN')}/timeline", headers=headers).json()
    assert body["available"] is False
    assert body["counts"] == []


def test_timeline_is_private_and_requires_login():
    owner = auth_headers("timeline-owner@example.com")
    other = auth_headers("timeline-other@example.com")
    upload_id = upload(owner, SAMPLE_LOG)
    assert client.get(f"/uploads/{upload_id}/timeline", headers=other).status_code == 404
    assert client.get(f"/uploads/{upload_id}/timeline").status_code == 401