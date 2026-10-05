"""Rule-based threat detection. Each rule produces a Finding with a reason."""

from collections import defaultdict

from app.models import Event, EventType, Finding, Severity

SENSITIVE_PATHS = {"/admin", "/.env", "/wp-admin", "/etc/passwd", "/phpmyadmin", "/config"}
BRUTE_FORCE_THEN_SUCCESS = 3  # failures before a success
BRUTE_FORCE_NO_SUCCESS = 5  # failures with no success
HIGH_VOLUME_FAILURES = 10
PATH_ENUMERATION = 8  # distinct paths from one IP


def _analyze_ip(ip: str, events: list[Event]) -> list[Finding]:
    """Walk one IP's events in order so sequences ('fails THEN success') are real."""
    findings: list[Finding] = []
    failed_lines: list[int] = []
    logged_in = False
    brute_force: Finding | None = None
    paths: set[str | None] = set()

    for event in events:
        if event.event_type == EventType.FAILED_LOGIN:
            failed_lines.append(event.line_number)

        elif event.event_type == EventType.SUCCESS_LOGIN:
            if len(failed_lines) >= BRUTE_FORCE_THEN_SUCCESS:
                brute_force = Finding(
                    ip=ip,
                    severity=Severity.HIGH,
                    title="Possible Brute-Force Attack",
                    reason=f"{len(failed_lines)} failed logins followed by a successful login.",
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


def detect(events: list[Event]) -> list[Finding]:
    """Run all rules over the events. Returns findings, most severe first."""
    events_by_ip: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        events_by_ip[event.ip].append(event)

    findings: list[Finding] = []
    for ip, ip_events in events_by_ip.items():
        findings.extend(_analyze_ip(ip, ip_events))

    return sorted(findings, key=lambda finding: finding.severity, reverse=True)