"""Parse raw log text into normalized Event objects."""

import ipaddress
import re
from dataclasses import dataclass, field

from app.models import Event, EventType

LINE_PATTERN = re.compile(
    r"^(?:\[?(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})\]?\s+)?"  # optional timestamp
    r"((?:\d{1,3}\.){3}\d{1,3})\s+-\s+"  # IP address
    r"(.+?)\s*$"  # event description
)


@dataclass
class ParseResult:
    events: list[Event] = field(default_factory=list)
    skipped_lines: list[int] = field(default_factory=list)


def _is_valid_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def parse_logs(text: str) -> ParseResult:
    """Parse log text. Lines that don't match are recorded, never fatal."""
    result = ParseResult()

    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue

        match = LINE_PATTERN.match(line)
        if match is None or not _is_valid_ipv4(match.group(2)):
            result.skipped_lines.append(line_number)
            continue

        timestamp, ip, description = match.groups()
        upper = description.upper()
        path: str | None = None

        if upper == "FAILED LOGIN":
            event_type = EventType.FAILED_LOGIN
        elif upper == "SUCCESSFUL LOGIN":
            event_type = EventType.SUCCESS_LOGIN
        elif upper.startswith("ACCESS "):
            event_type = EventType.ACCESS
            path = description[7:].strip().lower()
        else:
            event_type = EventType.OTHER

        result.events.append(Event(line_number, timestamp, ip, event_type, path))

    return result