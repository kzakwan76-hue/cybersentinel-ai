"""Writes data/synthetic/ml_demo.log: a log that rules alone mostly miss."""

from pathlib import Path

OUTPUT = Path(__file__).resolve().parent.parent / "data" / "synthetic" / "ml_demo.log"

lines = ["10.0.0.7 - SUCCESSFUL LOGIN", "10.0.0.7 - ACCESS /dashboard", "10.0.0.7 - ACCESS /reports"]
# Valid login, then a huge number of requests (data-harvesting pattern).
lines += ["172.16.0.5 - SUCCESSFUL LOGIN"] + ["172.16.0.5 - ACCESS /reports"] * 85
# Valid login, then many sensitive pages (stolen-credentials pattern).
lines += ["172.16.0.9 - SUCCESSFUL LOGIN"]
lines += [f"172.16.0.9 - ACCESS {path}" for path in ["/admin", "/config", "/.env", "/phpmyadmin", "/admin", "/config"]]
# A plain rule-detectable event for comparison.
lines += ["203.0.113.50 - ACCESS /.env"]

OUTPUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
print(f"Wrote {OUTPUT}")