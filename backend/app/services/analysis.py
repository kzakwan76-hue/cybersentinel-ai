"""Combine rule-based detection with the optional ML anomaly detector."""

import logging
from functools import lru_cache
from pathlib import Path

import numpy as np

from app.config import MODEL_PATH
from app.ml.anomaly import AnomalyDetector
from app.ml.features import feature_vector, group_by_ip
from app.models import Event, Finding, Severity
from app.services.detectors import detect

logger = logging.getLogger("cybersentinel.analysis")
MAX_EVIDENCE_LINES = 20


@lru_cache(maxsize=1)
def _load_model() -> AnomalyDetector | None:
    path = Path(MODEL_PATH)
    if not path.is_file():
        logger.info("No anomaly model at %s, running rules only.", path)
        return None
    try:
        return AnomalyDetector.load(path)
    except Exception:
        logger.exception("Could not load anomaly model, running rules only.")
        return None


def _ml_findings(
    events: list[Event], detector: AnomalyDetector, already_flagged: set[str]
) -> list[Finding]:
    candidates = {ip: evs for ip, evs in group_by_ip(events).items() if ip not in already_flagged}
    if not candidates:
        return []

    ips = list(candidates)
    matrix = np.array([feature_vector(candidates[ip]) for ip in ips])
    flags = detector.predict(matrix)

    findings: list[Finding] = []
    for ip, vector, flag in zip(ips, matrix, flags):
        if not flag:
            continue
        details = "; ".join(
            f"{d.feature} = {d.value:g} (typical: {d.typical:.1f})" for d in detector.explain(vector)
        )
        ip_events = candidates[ip]
        findings.append(
            Finding(
                ip=ip,
                severity=Severity.MEDIUM,
                title="Anomalous Behavior (ML)",
                reason=f"Activity differs from the learned normal baseline. Biggest differences: {details}.",
                recommendations=[
                    "Review this source's activity in the raw logs",
                    "Check whether this behavior is expected for this user or system",
                    "Treat as a lead to investigate, not a confirmed attack",
                ],
                evidence_lines=[e.line_number for e in ip_events[:MAX_EVIDENCE_LINES]],
                timestamp=ip_events[-1].timestamp,
            )
        )
    return findings


def analyze_events(events: list[Event], model: AnomalyDetector | None = None) -> list[Finding]:
    """Run the rules, then (if a model is available) add ML findings for anything they missed."""
    findings = detect(events)
    if model is None:
        model = _load_model()
    if model is not None:
        findings.extend(_ml_findings(events, model, {finding.ip for finding in findings}))
    return sorted(findings, key=lambda finding: finding.severity, reverse=True)