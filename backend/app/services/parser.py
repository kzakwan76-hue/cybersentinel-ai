"""Parse raw log text into normalized Event objects.

Supported formats (detected line by line, so one file may mix them):
  1. Simple      [2026-10-05 09:00:01] 192.168.1.24 - FAILED LOGIN | SUCCESSFUL LOGIN | ACCESS /admin
  2. SSH syslog  Oct  5 09:00:01 host sshd[811]: Failed password for root from 203.0.113.5 port 22 ssh2
  3. Web access  203.0.113.5 - - [05/Oct/2026:09:10:00 +0000] "GET /admin HTTP/1.1" 401 153 "-" "curl"

Every timestamp is normalized to 'YYYY-MM-DD HH:MM:SS' (web logs are converted to UTC).
Only IPv4 sources are analysed. Lines that cannot be used are reported as skipped, never fatal.
"""

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote

from app.models import Event, EventType

MONTHS = {
    name: number
    for number, name in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1
    )
}
MAX_PATH_CHARS = 200
STATIC_EXTENSIONS = (
    ".css", ".js", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".woff", ".woff2", ".ttf",
)
LOGIN_PATHS = {"/login", "/signin", "/auth/login", "/api/login", "/api/auth/login", "/user/login"}
LOGIN_FAILURE_STATUSES = {401, 403}

SIMPLE_PATTERN = re.compile(
    r"^(?:\[?(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})\]?\s+)?"  # optional timestamp
    r"((?:\d{1,3}\.){3}\d{1,3})\s+-\s+"  # IP address
    r"(.+?)\s*$"  # event description
)
SSH_CLASSIC = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+"
    r"sshd(?:\[\d+\])?:\s+(?P<message>.*)$"
)
SSH_ISO = re.compile(
    r"^(?P<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?\s+\S+\s+"
    r"sshd(?:\[\d+\])?:\s+(?P<message>.*)$"
)
SSH_FAILED = re.compile(r"^Failed \S+ for .+? from (?P<ip>\S+) port \d+")
SSH_ACCEPTED = re.compile(r"^Accepted \S+ for .+? from (?P<ip>\S+) port \d+")
WEB_LINE = re.compile(
    r"^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<day>\d{2})/(?P<month>[A-Za-z]{3})/(?P<year>\d{4}):"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<offset>[+-]\d{4})\]"
    r'\s+"(?P<method>[A-Z]+)\s+(?P<target>\S+)[^"]*"\s+(?P<status>\d{3})\b'
)


class _Ignored:
    """Marker: a recognized line that carries no login or access information."""


IGNORED = _Ignored()
ParsedLine = Event | _Ignored | None


@dataclass
class ParseResult:
    events: list[Event] = field(default_factory=list)
    skipped_lines: list[int] = field(default_factory=list)  # lines we could not use
    ignored_lines: int = 0  # recognized but irrelevant (static assets, other sshd messages)


def _valid_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def _stamp(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%d %H:%M:%S")


def _normalize_path(target: str) -> str:
    """Strip query/fragment, decode percent-escapes once, lowercase, drop control characters."""
    path = unquote(target.split("?", 1)[0].split("#", 1)[0]).lower()
    path = "".join(character for character in path if character.isprintable())
    if len(path) > 1:
        path = path.rstrip("/") or "/"
    return path[:MAX_PATH_CHARS]


def _parse_simple(line: str, number: int) -> ParsedLine:
    match = SIMPLE_PATTERN.match(line)
    if match is None:
        return None
    timestamp, ip, description = match.groups()
    if not _valid_ipv4(ip):
        return None

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
    return Event(number, timestamp, ip, event_type, path)


def _ssh_timestamp(match: re.Match[str], year: int) -> str | None:
    """Classic syslog has no year, so the caller supplies one."""
    month = MONTHS.get(match["month"])
    if month is None:
        return None
    hour, minute, second = (int(part) for part in match["time"].split(":"))
    try:
        return _stamp(datetime(year, month, int(match["day"]), hour, minute, second))
    except ValueError:
        return None


def _parse_ssh(line: str, number: int, year: int) -> ParsedLine:
    classic = SSH_CLASSIC.match(line)
    if classic:
        timestamp, message = _ssh_timestamp(classic, year), classic["message"]
    else:
        iso = SSH_ISO.match(line)
        if iso is None:
            return None
        timestamp, message = iso["iso"].replace("T", " "), iso["message"]

    failed = SSH_FAILED.match(message)
    hit = failed or SSH_ACCEPTED.match(message)
    if hit is None:
        return IGNORED  # some other sshd message (disconnects, pam notices, ...)
    if not _valid_ipv4(hit["ip"]):
        return None  # IPv6 and hostnames are not supported
    event_type = EventType.FAILED_LOGIN if failed else EventType.SUCCESS_LOGIN
    return Event(number, timestamp, hit["ip"], event_type, None)


def _web_timestamp(match: re.Match[str]) -> str | None:
    """Convert '05/Oct/2026:11:10:00 +0200' to UTC 'YYYY-MM-DD HH:MM:SS'."""
    month = MONTHS.get(match["month"].capitalize())
    if month is None:
        return None
    offset = match["offset"]
    sign = -1 if offset[0] == "-" else 1
    try:
        zone = timezone(sign * timedelta(hours=int(offset[1:3]), minutes=int(offset[3:5])))
        hour, minute, second = (int(part) for part in match["time"].split(":"))
        moment = datetime(int(match["year"]), month, int(match["day"]), hour, minute, second, tzinfo=zone)
        return _stamp(moment.astimezone(timezone.utc))
    except (ValueError, OverflowError):
        return None


def _parse_web(line: str, number: int) -> ParsedLine:
    match = WEB_LINE.match(line)
    if match is None:
        return None
    ip = match["ip"]
    if not _valid_ipv4(ip):
        return None

    path = _normalize_path(match["target"])
    status = int(match["status"])
    timestamp = _web_timestamp(match)

    # Heuristic: a POST to a known login path tells us whether the login worked.
    if match["method"] == "POST" and path in LOGIN_PATHS:
        if status in LOGIN_FAILURE_STATUSES:
            return Event(number, timestamp, ip, EventType.FAILED_LOGIN, None)
        if 200 <= status < 400:
            return Event(number, timestamp, ip, EventType.SUCCESS_LOGIN, None)
    if path.endswith(STATIC_EXTENSIONS):
        return IGNORED  # pictures and scripts would make normal browsing look like scanning
    return Event(number, timestamp, ip, EventType.ACCESS, path)


def parse_logs(text: str, default_year: int | None = None) -> ParseResult:
    """Parse log text. Lines that don't match any format are recorded, never fatal.

    default_year is used for classic syslog lines, which carry no year (defaults to this year).
    """
    year = default_year or datetime.now().year
    result = ParseResult()

    for number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        # The most specific formats go first: a web log line would also match the simple pattern.
        parsed = _parse_web(line, number) or _parse_ssh(line, number, year) or _parse_simple(line, number)
        if parsed is None:
            result.skipped_lines.append(number)
        elif isinstance(parsed, Event):
            result.events.append(parsed)
        else:
            result.ignored_lines += 1

    return result