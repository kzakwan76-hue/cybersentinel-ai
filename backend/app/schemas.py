"""API request and response shapes."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str
    created_at: datetime


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    upload_id: int
    ip: str
    severity: str
    title: str
    reason: str
    recommendations: list[str]
    evidence_lines: list[int]
    log_timestamp: str | None


class UploadOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    filename: str
    created_at: datetime
    events_parsed: int
    lines_skipped: int


class AnalysisOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    upload: UploadOut
    findings: list[FindingOut]


class IpCount(BaseModel):
    ip: str
    count: int


class StatsOut(BaseModel):
    total_uploads: int
    total_findings: int
    by_severity: dict[str, int]
    top_ips: list[IpCount]