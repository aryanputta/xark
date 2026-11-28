"""Independently reparse downloaded GitHub Actions benchmark receipts."""

import json
import re
import statistics
import sys
from pathlib import Path

from replay import p95, parse

EXPECTED = {
    "final-attempt1": {"source": "a97a69980835eaba47814d7a3f1831d33eb9d5a7",
                       "eligible": False, "controls": 8, "measurements": 0},
    "final-attempt2": {"source": "a97a69980835eaba47814d7a3f1831d33eb9d5a7",
                       "eligible": True, "controls": 8, "measurements": 16},
    "cleanup-ablation": {"source": "5cadc60e1aca6f5ed557da41c501d4f3f89e3549",
                         "eligible": True, "controls": 12, "measurements": 36},
}
ALLOWED_SUFFIXES = {".json", ".stdout", ".stderr", ".txt"}
SENSITIVE = re.compile(rb"(?i)(github_pat_|ghp_[A-Za-z0-9]{20}|AKIA[0-9A-Z]{16}|bearer [A-Za-z0-9._-]{20}|password\s*[:=]|secret\s*[:=])")


def verify(root, label):
    expected = EXPECTED[label]
    files = [path for path in root.rglob("*") if path.is_file()]
    if not files:
        raise ValueError(f"{label}: no transferred files")
    for path in files:
        if path.suffix not in ALLOWED_SUFFIXES:
            raise ValueError(f"{label}: unexpected file type {path}")
        if SENSITIVE.search(path.read_bytes()):
            raise ValueError(f"{label}: sensitive-looking content in {path}")
    reports = [(path, json.loads(path.read_text())) for path in root.rglob("report.json")]
    selected = [report for _, report in reports if not report.get("smoke", False)]
    if len(selected) != 1:
        raise ValueError(f"{label}: expected one non-smoke report")
    report = selected[0]
    if report["performance_eligible"] != expected["eligible"]:
        raise ValueError(f"{label}: eligibility changed")
    if len(report["controls"]) != expected["controls"] or len(report["measurements"]) != expected["measurements"]:
        raise ValueError(f"{label}: unexpected request block count")
    if label.startswith("final-"):
        if report["source_commits"]["prepared"] != expected["source"]:
            raise ValueError(f"{label}: source head changed")
    elif report["source_commits"]["guarded"] != expected["source"]:
        raise ValueError(f"{label}: guarded source head changed")
    checked = 0
    for path, report in reports:
        for row in report["controls"] + report["measurements"]:
            stdout = path.parent / (row["tag"] + ".stdout")
            if not stdout.is_file():
                raise ValueError(f"{label}: missing stdout for {row['tag']}")
            setup, samples = parse(stdout.read_text().splitlines(), len(row["services_ns"]), 2)
            if setup != row["setup_ns"] or samples != row["services_ns"]:
                raise ValueError(f"{label}: raw samples differ for {row['tag']}")
            if statistics.median(samples) != row["p50_ns"] or p95(samples) != row["p95_ns"]:
                raise ValueError(f"{label}: reported percentiles differ for {row['tag']}")
            checked += len(samples)
    print(json.dumps({"label": label, "files": len(files), "reports": len(reports),
                      "reparsed_raw_request_samples": checked,
                      "performance_eligible": expected["eligible"]}))


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: verify_transferred_receipts.py RECEIPT_ROOT")
    root = Path(sys.argv[1])
    for label in EXPECTED:
        verify(root / label, label)


if __name__ == "__main__":
    main()
