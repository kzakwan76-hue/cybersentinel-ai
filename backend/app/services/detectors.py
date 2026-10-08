"""Rule-based threat detection. Each rule produces a Finding with a reason."""

from collections import defaultdict
from datetime import datetime

from app.models import Event, EventType, Finding, Severity

SENSITIVE_PATHS = {"/admin", "/.env", "/wp-admin", "/etc/passwd", "/phpmyadmin", "/config"}
BRUTE_FORCE_THEN_SUCCESS = 3  # failures before a success
BRUTE_FORCE_NO_SUCCESS = 5  # failures with no success
HIGH_VOLUME_FAILURES = 10
PATH_ENUMERATION = 8  # distinct paths from one IP
BRUTE_FORCE_WINDOW_SECONDS = 60  # 3 failures inside this window = a rapid burst


def parse_timestamp(timestamp: str | None) -> datetime | None:
    """Turn '2026-10-05 09:00:01' into a datetime. Returns None if missing or malformed."""
    if timestamp is None:
        return None
    try:
        return datetime.fromisoformat(timestamp)
    except ValueError:
        return None


def _span_seconds(times: list[datetime | None]) -> float | None:
    """Seconds from the first to the last time, or None if any timestamp is missing."""
    known = [moment for moment in times if moment is not None]
    if not known or len(known) != len(times):
        return None
    return (known[-1] - known[0]).total_seconds()


def _is_brute_force(failed_times: list[datetime | None], use_timing: bool) -> bool:
    """Do these failures (followed by a success) look like a brute-force attack?"""
    count = len(failed_times)
    if count < BRUTE_FORCE_THEN_SUCCESS:
        return False
    if not use_timing or _span_seconds(failed_times) is None:
        return True  # no usable timestamps: judge by count alone
    if count >= BRUTE_FORCE_NO_SUCCESS:
        return True  # sheer volume is suspicious however slowly it happened
    # 3-4 failures: an attack only if 3 of them landed inside the window.
    known = [moment for moment in failed_times if moment is not None]
    return any(
        abs((known[i + 2] - known[i]).total_seconds()) <= BRUTE_FORCE_WINDOW_SECONDS
        for i in range(count - 2)
    )


def _analyze_ip(ip: str, events: list[Event], use_timing: bool) -> list[Finding]:
    """Walk one IP's events in order so sequences ('fails THEN success') are real."""
    findings: list[Finding] = []
    failed_lines: list[int] = []
    failed_times: list[datetime | None] = []
    logged_in = False
    brute_force: Finding | None = None
    paths: set[str | None] = set()

    for event in events:
        if event.event_type == EventType.FAILED_LOGIN:
            failed_lines.append(event.line_number)
            failed_times.append(parse_timestamp(event.timestamp))

        elif event.event_type == EventType.SUCCESS_LOGIN:
            if _is_brute_force(failed_times, use_timing):
                span = _span_seconds(failed_times) if use_timing else None
                if span is None:
                    reason = f"{len(failed_lines)} failed logins followed by a successful login."
                else:
                    reason = (
                        f"{len(failed_lines)} failed logins over {abs(span):.0f} seconds, "
                        "followed by a successful login."
                    )
                brute_force = Finding(
                    ip=ip,
                    severity=Severity.HIGH,
                    title="Possible Brute-Force Attack",
                    reason=reason,
                    recommendations=[
                        "Review account activity",
                        "Verify the login was authorized",
                        "Consider temporarily blocking the source",
                    ],
                    evidence_lines=[*failed_lines, event.line_number],
                    timestamp=event.timestamp,
                )
                findings.append(brute_force)
            logged_in = True
            failed_lines = []
            failed_times = []

        elif event.event_type == EventType.ACCESS:
            paths.add(event.path)
            if event.path in SENSITIVE_PATHS:
                if brute_force is not None:
                    brute_force.severity = Severity.CRITICAL
                    brute_force.title = "Brute-Force Compromise with Admin Activity"
                    brute_force.reason += f" The same source then accessed {event.path}."
                    brute_force.evidence_lines.append(event.line_number)
                elif not logged_in:
                    findings.append(
                        Finding(
                            ip=ip,
                            severity=Severity.HIGH,
                            title="Sensitive Path Access Without Login",
                            reason=(
                                f"Requested {event.path} with no prior successful "
                                "authentication from this source."
                            ),
                            recommendations=[
                                "Check the server's access controls",
                                "Review other requests from this IP",
                                "Consider blocking the source",
                            ],
                            evidence_lines=[event.line_number],
                            timestamp=event.timestamp,
                        )
                    )

    last_timestamp = events[-1].timestamp

    if len(failed_lines) >= BRUTE_FORCE_NO_SUCCESS:
        severity = Severity.HIGH if len(failed_lines) >= HIGH_VOLUME_FAILURES else Severity.MEDIUM
        findings.append(
            Finding(
                ip=ip,
                severity=severity,
                title="Brute-Force Attempt (no success)",
                reason=f"{len(failed_lines)} consecutive failed logins with no successful login.",
                recommendations=[
                    "Enable rate limiting or account lockout",
                    "Monitor this IP for further attempts",
                ],
                evidence_lines=list(failed_lines),
                timestamp=last_timestamp,
            )
        )

    if len(paths) >= PATH_ENUMERATION:
        findings.append(
            Finding(
                ip=ip,
                severity=Severity.MEDIUM,
                title="Possible Path Enumeration",
                reason=f"Requested {len(paths)} different paths, which can indicate scanning.",
                recommendations=["Review web server logs", "Consider rate limiting"],
                timestamp=last_timestamp,
            )
        )

    return findings


def detect(events: list[Event], use_timing: bool = True) -> list[Finding]:
    """Run all rules over the events. Returns findings, most severe first.

    use_timing=False gives the original count-only behavior (used to measure the improvement).
    """
    events_by_ip: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        events_by_ip[event.ip].append(event)

    findings: list[Finding] = []
    for ip, ip_events in events_by_ip.items():
        findings.extend(_analyze_ip(ip, ip_events, use_timing))

    return sorted(findings, key=lambda finding: finding.severity, reverse=True)