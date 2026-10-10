"""Generate a PDF security analysis report for one upload."""

from datetime import datetime, timezone
from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app import orm

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEVERITY_HEX = {"CRITICAL": "#f85149", "HIGH": "#f0883e", "MEDIUM": "#d29922", "LOW": "#3fb950"}
MAX_EVIDENCE_LINES = 30
MARGIN = 18 * mm


def _severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else len(SEVERITY_ORDER)


def summary_text(upload: orm.Upload, findings: list[orm.FindingRecord], counts: dict[str, int]) -> str:
    """Plain-English summary built from the data (no LLM needed)."""
    if not findings:
        return f"No threats were detected in the {upload.events_parsed} events analyzed."
    breakdown = ", ".join(f"{counts[level]} {level.lower()}" for level in SEVERITY_ORDER if counts[level])
    top = findings[0]
    return (
        f"{len(findings)} potential threat(s) were detected across {upload.events_parsed} events "
        f"({breakdown}). The most severe finding is \"{top.title}\" from source {top.ip}."
    )


def _footer(canvas, doc) -> None:
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.grey)
    canvas.drawString(MARGIN, 10 * mm, "CyberSentinel AI - defensive & educational - synthetic data only")
    canvas.drawRightString(A4[0] - MARGIN, 10 * mm, f"Page {doc.page}")
    canvas.restoreState()


def _finding_block(finding: orm.FindingRecord, heading: ParagraphStyle, body: ParagraphStyle):
    # Everything that came from the log is untrusted, so escape() it before it reaches the PDF library.
    color = SEVERITY_HEX.get(finding.severity, "#8b97b8")
    recommendations = "<br/>".join(f"- {escape(text)}" for text in finding.recommendations)
    shown = finding.evidence_lines[:MAX_EVIDENCE_LINES]
    evidence = ", ".join(str(number) for number in shown) or "n/a"
    if len(finding.evidence_lines) > MAX_EVIDENCE_LINES:
        evidence += ", ..."
    return KeepTogether(
        [
            Paragraph(
                f'<font color="{color}"><b>[{escape(finding.severity)}]</b></font> {escape(finding.title)}',
                heading,
            ),
            Paragraph(f"<b>Source:</b> {escape(finding.ip)} | <b>Time:</b> {escape(finding.log_timestamp or 'n/a')}", body),
            Paragraph(f"<b>Why flagged:</b> {escape(finding.reason)}", body),
            Paragraph(f"<b>Evidence lines:</b> {evidence}", body),
            Paragraph(f"<b>Recommended actions:</b><br/>{recommendations}", body),
            Spacer(1, 5 * mm),
        ]
    )

def _ai_overview(upload: orm.Upload, body: ParagraphStyle, small: ParagraphStyle) -> list:
    text = getattr(upload, "ai_summary", None)
    if not text:
        return []
    return [
        Spacer(1, 2 * mm),
        Paragraph("AI-written overview (generated from the findings; verify before acting)", small),
        Paragraph(escape(text), body),
    ]


def build_pdf(upload: orm.Upload) -> bytes:
    """Build the report for one upload and return the PDF file as bytes."""
    findings = sorted(upload.findings, key=lambda f: (_severity_rank(f.severity), f.id))
    counts = {level: sum(1 for f in findings if f.severity == level) for level in SEVERITY_ORDER}

    styles = getSampleStyleSheet()
    body = ParagraphStyle("Body", parent=styles["BodyText"], fontSize=9.5, leading=13)
    heading = ParagraphStyle("FindingHeading", parent=styles["Heading3"], spaceBefore=4, spaceAfter=2)
    small = ParagraphStyle("Small", parent=body, fontSize=8.5, leading=11, textColor=colors.grey)

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    uploaded = upload.created_at.strftime("%Y-%m-%d %H:%M UTC")

    summary_table = Table(
        [["Severity", "Findings"]] + [[level, str(counts[level])] for level in SEVERITY_ORDER],
        colWidths=[40 * mm, 30 * mm],
        hAlign="LEFT",
    )
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1b2542")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.lightgrey),
            ]
            + [
                ("TEXTCOLOR", (0, i + 1), (0, i + 1), colors.HexColor(SEVERITY_HEX[level]))
                for i, level in enumerate(SEVERITY_ORDER)
            ]
        )
    )

    story: list = [
        Paragraph("CyberSentinel AI: Security Analysis Report", styles["Title"]),
        Paragraph(
            f"<b>File:</b> {escape(upload.filename)}<br/>"
            f"<b>Uploaded:</b> {uploaded}<br/>"
            f"<b>Report generated:</b> {generated}<br/>"
            f"<b>Events parsed:</b> {upload.events_parsed} | "
            f"<b>Unreadable lines skipped:</b> {upload.lines_skipped}",
            body,
        ),
        Spacer(1, 5 * mm),
        Paragraph("Summary", styles["Heading2"]),
        Paragraph(escape(summary_text(upload, findings, counts)), body),
        *_ai_overview(upload, body, small),
        Spacer(1, 3 * mm),
        summary_table,
        Spacer(1, 6 * mm),
        Paragraph("Findings", styles["Heading2"]),
    ]

    if findings:
        story.extend(_finding_block(finding, heading, body) for finding in findings)
    else:
        story.append(Paragraph("No threats detected.", body))

    story += [
        Spacer(1, 4 * mm),
        Paragraph("How to read this report", styles["Heading3"]),
        Paragraph(
            "Rule-based findings follow explicit, documented rules. Findings marked (ML) come from a "
            "statistical model that flags behavior unlike its training baseline; treat them as leads to "
            "investigate, not confirmed attacks. Severity is an estimate and should be verified by a person "
            "before any action is taken.",
            small,
        ),
    ]

    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=MARGIN,
        bottomMargin=MARGIN,
        title="CyberSentinel AI Security Analysis Report",
        author="CyberSentinel AI",
    )
    document.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buffer.getvalue()