"""Core data structures shared by the parser, detectors, and (later) the API."""

from dataclasses import dataclass, field
from enum import Enum, IntEnum


class EventType(str, Enum):
    FAILED_LOGIN = "FAILED_LOGIN"
    SUCCESS_LOGIN = "SUCCESS_LOGIN"
    ACCESS = "ACCESS"
    OTHER = "OTHER"


class Severity(IntEnum):
    """IntEnum so severities can be compared and sorted: CRITICAL > HIGH."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass(frozen=True)
class Event:
    """One normalized log line."""

    line_number: int
    timestamp: str | None
    ip: str
    event_type: EventType
    path: str | None = None


@dataclass
class Finding:
    """One detected threat, with the reasoning behind it."""

    ip: str
    severity: Severity
    title: str
    reason: str
    recommendations: list[str]
    evidence_lines: list[int] = field(default_factory=list)
    timestamp: str | None = None