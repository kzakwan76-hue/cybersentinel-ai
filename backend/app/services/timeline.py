"""Activity timeline for an upload: failed logins, successful logins and page requests over time.

Only aggregated counts are stored (a few dozen small buckets), never the raw events.
"""

import math
from datetime import datetime, timedelta
from typing import Any

from app.models import Event, EventType
from app.services.detectors import parse_timestamp

MAX_BUCKETS = 48
BUCKET_LADDER_SECONDS = [1, 5, 10, 30, 60, 300, 600, 1800, 3600, 7200, 21600, 86400]
COLUMN = {EventType.FAILED_LOGIN: 0, EventType.SUCCESS_LOGIN: 1, EventType.ACCESS: 2}


def _bucket_size(span_seconds: float) -> int:
    """The smallest bucket size from the ladder that keeps the chart within MAX_BUCKETS."""
    for size in BUCKET_LADDER_SECONDS:
        if span_seconds // size + 1 <= MAX_BUCKETS:
            return size
    return math.ceil(span_seconds / (MAX_BUCKETS - 1))


def build_timeline(events: list[Event]) -> dict[str, Any] | None:
    """Count events per time bucket as [failed, success, access]. None if no usable timestamps."""
    stamped = []
    for event in events:
        moment = parse_timestamp(event.timestamp)
        if moment is not None and event.event_type in COLUMN:
            stamped.append((moment, COLUMN[event.event_type]))
    if not stamped:
        return None

    start = min(moment for moment, _ in stamped)
    span = (max(moment for moment, _ in stamped) - start).total_seconds()
    size = _bucket_size(span)
    count = int(span // size) + 1

    counts = [[0, 0, 0] for _ in range(count)]
    for moment, column in stamped:
        counts[int((moment - start).total_seconds() // size)][column] += 1

    try:
        end = start + timedelta(seconds=size * count)
    except OverflowError:  # absurd timestamps (year 9999) must never crash an upload
        return None
    return {
        "start": start.isoformat(sep=" "),
        "end": end.isoformat(sep=" "),
        "bucket_seconds": size,
        "counts": counts,
    }


def markers_for(timeline: dict[str, Any], findings: list[Any]) -> list[dict[str, Any]]:
    """One marker per finding whose timestamp falls inside the timeline."""
    start = datetime.fromisoformat(timeline["start"])
    size = timeline["bucket_seconds"]
    last_bucket = len(timeline["counts"]) - 1

    markers = []
    for finding in findings:
        moment = parse_timestamp(finding.log_timestamp)
        if moment is None:
            continue
        bucket = int((moment - start).total_seconds() // size)
        if 0 <= bucket <= last_bucket:
            markers.append(
                {"bucket": bucket, "severity": finding.severity, "title": finding.title, "ip": finding.ip}
            )
    return markers