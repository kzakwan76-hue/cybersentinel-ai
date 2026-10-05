from app.models import Severity
from app.services.detectors import detect
from app.services.parser import parse_logs


def analyze(text: str):
    return detect(parse_logs(text).events)


def test_brute_force_then_success_is_high():
    findings = analyze(
        "1.1.1.1 - FAILED LOGIN\n"
        "1.1.1.1 - FAILED LOGIN\n"
        "1.1.1.1 - FAILED LOGIN\n"
        "1.1.1.1 - SUCCESSFUL LOGIN\n"
    )
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].evidence_lines == [1, 2, 3, 4]


def test_admin_access_after_brute_force_escalates_to_critical():
    findings = analyze(
        "1.1.1.1 - FAILED LOGIN\n"
        "1.1.1.1 - FAILED LOGIN\n"
        "1.1.1.1 - FAILED LOGIN\n"
        "1.1.1.1 - SUCCESSFUL LOGIN\n"
        "1.1.1.1 - ACCESS /admin\n"
    )
    assert findings[0].severity == Severity.CRITICAL


def test_two_failures_is_not_a_threat():
    assert analyze("1.1.1.1 - FAILED LOGIN\n1.1.1.1 - FAILED LOGIN\n1.1.1.1 - SUCCESSFUL LOGIN\n") == []


def test_sensitive_path_without_login_is_high():
    findings = analyze("203.0.113.50 - ACCESS /.env\n")
    assert findings[0].severity == Severity.HIGH


def test_normal_user_is_not_flagged():
    assert analyze("10.0.0.7 - SUCCESSFUL LOGIN\n10.0.0.7 - ACCESS /dashboard\n") == []


def test_invalid_lines_are_skipped_not_fatal():
    result = parse_logs("999.1.1.1 - FAILED LOGIN\nhello world\n1.1.1.1 - FAILED LOGIN\n")
    assert result.skipped_lines == [1, 2]
    assert len(result.events) == 1