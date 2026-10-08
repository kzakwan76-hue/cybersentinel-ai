from datetime import datetime

from app import orm
from app.services.report import build_pdf


def make_upload(findings: list[orm.FindingRecord]) -> orm.Upload:
    upload = orm.Upload(
        id=1,
        user_id=1,
        filename="<b>evil</b> & co.log",
        created_at=datetime(2026, 10, 8, 12, 0),
        events_parsed=5,
        lines_skipped=0,
    )
    upload.findings = findings
    return upload


def test_report_handles_markup_characters_in_log_content():
    finding = orm.FindingRecord(
        id=1,
        upload_id=1,
        ip="1.1.1.1",
        severity="HIGH",
        title="Sensitive <Path> & Stuff",
        reason="Requested /<script>alert(1)</script> & more",
        recommendations=["Review <this>"],
        evidence_lines=[1, 2],
        log_timestamp=None,
    )
    assert build_pdf(make_upload([finding])).startswith(b"%PDF")


def test_report_works_with_no_findings():
    assert build_pdf(make_upload([])).startswith(b"%PDF")