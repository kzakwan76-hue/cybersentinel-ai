"""CyberSentinel AI: FastAPI application."""
from pathlib import Path

from fastapi.staticfiles import StaticFiles
import logging
from typing import Literal

from fastapi import Depends, FastAPI, File, HTTPException, Query, Response, UploadFile
from sqlalchemy import ColumnElement, func, or_, select
from sqlalchemy.orm import Session

from app import orm
from app.api import auth
from app.config import MAX_UPLOAD_BYTES
from app.database import Base, engine, get_db
from app.deps import get_current_user
from app.schemas import AnalysisOut, FindingOut, IpCount, StatsOut, UploadOut
from app.services.analysis import analyze_events
from app.services.parser import parse_logs
from app.services.report import build_pdf

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cybersentinel")

SEVERITY_LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]



app = FastAPI(title="CyberSentinel AI", version="0.4.0")
app.include_router(auth.router)


def owned_by(user: orm.User) -> ColumnElement[bool]:
    """SQL condition: only findings that belong to this user's uploads."""
    return orm.FindingRecord.upload_id.in_(
        select(orm.Upload.id).where(orm.Upload.user_id == user.id)
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/analyze", response_model=AnalysisOut)
async def analyze(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: orm.User = Depends(get_current_user),
):
    """Upload a log file, detect threats, and save the results."""
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File too large.")

    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File must be UTF-8 text.")

    parsed = parse_logs(text)
    if not parsed.events:
        raise HTTPException(status_code=422, detail="No valid log lines found.")

    findings = analyze_events(parsed.events)

    upload = orm.Upload(
        user_id=current_user.id,
        filename=(file.filename or "upload.log")[:255],
        events_parsed=len(parsed.events),
        lines_skipped=len(parsed.skipped_lines),
    )
    upload.findings = [
        orm.FindingRecord(
            ip=finding.ip,
            severity=finding.severity.name,
            title=finding.title,
            reason=finding.reason,
            recommendations=finding.recommendations,
            evidence_lines=finding.evidence_lines,
            log_timestamp=finding.timestamp,
        )
        for finding in findings
    ]
    db.add(upload)
    db.commit()
    db.refresh(upload)

    logger.info(
        "User %d analyzed %s: %d events, %d findings",
        current_user.id,
        upload.filename,
        len(parsed.events),
        len(findings),
    )
    return {"upload": upload, "findings": upload.findings}


@app.get("/findings", response_model=list[FindingOut])
def list_findings(
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = None,
    q: str | None = Query(default=None, max_length=100),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: orm.User = Depends(get_current_user),
):
    """List your saved threats, newest first. Filter by severity or search text."""
    statement = (
        select(orm.FindingRecord)
        .where(owned_by(current_user))
        .order_by(orm.FindingRecord.id.desc())
        .limit(limit)
    )
    if severity:
        statement = statement.where(orm.FindingRecord.severity == severity)
    if q:
        pattern = f"%{q}%"
        statement = statement.where(
            or_(
                orm.FindingRecord.ip.ilike(pattern),
                orm.FindingRecord.title.ilike(pattern),
                orm.FindingRecord.reason.ilike(pattern),
            )
        )
    return list(db.scalars(statement))


@app.get("/uploads", response_model=list[UploadOut])
def list_uploads(
    db: Session = Depends(get_db), current_user: orm.User = Depends(get_current_user)
):
    """Your upload history, newest first."""
    statement = (
        select(orm.Upload)
        .where(orm.Upload.user_id == current_user.id)
        .order_by(orm.Upload.id.desc())
        .limit(50)
    )
    return list(db.scalars(statement))


@app.get("/stats", response_model=StatsOut)
def stats(db: Session = Depends(get_db), current_user: orm.User = Depends(get_current_user)):
    """Security statistics for your data."""
    total_uploads = (
        db.scalar(select(func.count(orm.Upload.id)).where(orm.Upload.user_id == current_user.id))
        or 0
    )
    total_findings = (
        db.scalar(select(func.count(orm.FindingRecord.id)).where(owned_by(current_user))) or 0
    )

    by_severity = {level: 0 for level in SEVERITY_LEVELS}
    severity_rows = db.execute(
        select(orm.FindingRecord.severity, func.count())
        .where(owned_by(current_user))
        .group_by(orm.FindingRecord.severity)
    ).all()
    for severity, count in severity_rows:
        by_severity[severity] = count

    ip_rows = db.execute(
        select(orm.FindingRecord.ip, func.count())
        .where(owned_by(current_user))
        .group_by(orm.FindingRecord.ip)
        .order_by(func.count().desc())
        .limit(5)
    ).all()

    return StatsOut(
        total_uploads=total_uploads,
        total_findings=total_findings,
        by_severity=by_severity,
        top_ips=[IpCount(ip=ip, count=count) for ip, count in ip_rows],
    )
@app.get("/uploads/{upload_id}/report.pdf")
def download_report(
    upload_id: int,
    db: Session = Depends(get_db),
    current_user: orm.User = Depends(get_current_user),
):
    """Download a PDF report for one of YOUR uploads."""
    upload = db.scalar(
        select(orm.Upload).where(orm.Upload.id == upload_id, orm.Upload.user_id == current_user.id)
    )
    if upload is None:  # same answer for "missing" and "belongs to someone else"
        raise HTTPException(status_code=404, detail="Upload not found.")
    return Response(
        content=build_pdf(upload),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="cybersentinel-report-{upload.id}.pdf"'},
    )

FRONTEND_DIR = Path(__file__).resolve().parents[2] / "frontend"
if FRONTEND_DIR.is_dir():
    app.mount("/dashboard", StaticFiles(directory=FRONTEND_DIR, html=True), name="dashboard")