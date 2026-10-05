from pathlib import Path

from app.services.detectors import detect
from app.services.parser import parse_logs

LOG_FILE = Path(__file__).resolve().parent.parent / "data" / "synthetic" / "sample.log"

result = parse_logs(LOG_FILE.read_text(encoding="utf-8"))
print(f"Parsed {len(result.events)} events, skipped {len(result.skipped_lines)} lines\n")

for finding in detect(result.events):
    print(f"[{finding.severity.name}] {finding.title}")
    print(f"  Source:   {finding.ip}")
    print(f"  Reason:   {finding.reason}")
    print(f"  Evidence: lines {finding.evidence_lines}\n")