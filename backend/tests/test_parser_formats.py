from app.models import EventType
from app.services.detectors import detect
from app.services.parser import parse_logs

SSH_LINES = "\n".join(
    [
        "Oct  5 09:00:01 web1 sshd[811]: Failed password for invalid user admin from 203.0.113.5 port 52114 ssh2",
        "Oct  5 09:00:03 web1 sshd[811]: Failed password for root from 203.0.113.5 port 52114 ssh2",
        "Oct  5 09:00:05 web1 sshd[811]: Failed password for root from 203.0.113.5 port 52114 ssh2",
        "Oct  5 09:00:07 web1 sshd[812]: Accepted password for root from 203.0.113.5 port 52120 ssh2",
    ]
)


def web_line(
    ip: str = "203.0.113.50",
    when: str = "05/Oct/2026:09:10:00 +0000",
    request: str = "GET /.env HTTP/1.1",
    status: int = 404,
) -> str:
    return f'{ip} - - [{when}] "{request}" {status} 153 "-" "curl/8.0"'


def test_simple_format_still_works():
    result = parse_logs("[2026-10-05 09:00:01] 192.168.1.24 - FAILED LOGIN\n192.168.1.24 - ACCESS /Admin\n")
    assert [e.event_type for e in result.events] == [EventType.FAILED_LOGIN, EventType.ACCESS]
    assert result.events[0].timestamp == "2026-10-05 09:00:01"
    assert result.events[1].path == "/admin"


def test_ssh_failed_and_accepted_logins_are_parsed():
    events = parse_logs(SSH_LINES, default_year=2026).events
    assert [e.event_type for e in events] == [EventType.FAILED_LOGIN] * 3 + [EventType.SUCCESS_LOGIN]
    assert events[0].ip == "203.0.113.5"
    assert events[0].timestamp == "2026-10-05 09:00:01"
    assert events[3].timestamp == "2026-10-05 09:00:07"


def test_ssh_brute_force_is_detected_end_to_end():
    findings = detect(parse_logs(SSH_LINES, default_year=2026).events)
    assert [f.title for f in findings] == ["Possible Brute-Force Attack"]


def test_other_sshd_lines_are_ignored_and_other_programs_skipped():
    text = "\n".join(
        [
            "Oct  5 09:00:01 web1 sshd[811]: Connection closed by 203.0.113.5 port 52114 [preauth]",
            "Oct  5 09:00:02 web1 CRON[900]: (root) CMD (run-parts /etc/cron.hourly)",
        ]
    )
    result = parse_logs(text, default_year=2026)
    assert result.events == []
    assert result.ignored_lines == 1
    assert result.skipped_lines == [2]


def test_iso_timestamps_in_syslog_are_supported():
    line = "2026-10-05T09:00:01.123456+00:00 web1 sshd[811]: Failed password for root from 203.0.113.5 port 22 ssh2"
    assert parse_logs(line).events[0].timestamp == "2026-10-05 09:00:01"


def test_impossible_syslog_date_keeps_event_without_timestamp():
    line = "Feb 30 09:00:01 web1 sshd[811]: Failed password for root from 203.0.113.5 port 22 ssh2"
    assert parse_logs(line, default_year=2026).events[0].timestamp is None


def test_ipv6_sources_are_skipped():
    line = "Oct  5 09:00:01 web1 sshd[811]: Failed password for root from 2001:db8::1 port 22 ssh2"
    result = parse_logs(line, default_year=2026)
    assert result.events == []
    assert result.skipped_lines == [1]


def test_web_timestamp_is_converted_to_utc():
    event = parse_logs(web_line(when="05/Oct/2026:11:10:00 +0200")).events[0]
    assert event.timestamp == "2026-10-05 09:10:00"


def test_web_path_is_normalized():
    text = "\n".join(
        [web_line(request="GET /Admin/?next=%2Fhome HTTP/1.1"), web_line(request="GET /%2E%65nv HTTP/1.1")]
    )
    assert [e.path for e in parse_logs(text).events] == ["/admin", "/.env"]


def test_static_assets_are_ignored_not_skipped():
    result = parse_logs(web_line(request="GET /static/App.CSS?v=2 HTTP/1.1", status=200))
    assert result.events == []
    assert result.skipped_lines == []
    assert result.ignored_lines == 1


def test_login_posts_become_login_events():
    text = "\n".join(
        [
            web_line(request="POST /login HTTP/1.1", status=401),
            web_line(request="POST /login HTTP/1.1", status=302),
            web_line(request="GET /login HTTP/1.1", status=200),
        ]
    )
    types = [e.event_type for e in parse_logs(text).events]
    assert types == [EventType.FAILED_LOGIN, EventType.SUCCESS_LOGIN, EventType.ACCESS]


def test_web_brute_force_is_detected_end_to_end():
    lines = [
        web_line(when=f"05/Oct/2026:{moment} +0000", request="POST /login HTTP/1.1", status=401)
        for moment in ("09:00:00", "09:00:02", "09:00:04")
    ]
    lines.append(web_line(when="05/Oct/2026:09:00:06 +0000", request="POST /login HTTP/1.1", status=200))
    findings = detect(parse_logs("\n".join(lines)).events)
    assert [f.title for f in findings] == ["Possible Brute-Force Attack"]


def test_web_sensitive_path_without_login_is_flagged():
    findings = detect(parse_logs(web_line(request="GET /.env HTTP/1.1")).events)
    assert [f.title for f in findings] == ["Sensitive Path Access Without Login"]


def test_formats_can_be_mixed_in_one_file():
    text = "\n".join(["1.1.1.1 - FAILED LOGIN", SSH_LINES.splitlines()[0], web_line(), "total garbage"])
    result = parse_logs(text, default_year=2026)
    assert len(result.events) == 3
    assert result.skipped_lines == [4]