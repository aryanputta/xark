#!/usr/bin/env python3
"""Independently audit paired Gnark receipts and gate same-binary host drift."""

import argparse
import csv
import json
from pathlib import Path
import sys

from run import summarize


WORKLOADS = ("escrow", "withdrawal")
BACKENDS = ("xark", "gnark")


def audit(directory, pairs, samples, max_p50=0.02, max_p95=0.10):
    report = json.loads((directory / "report.json").read_text())
    if (
        report.get("status") != "verified"
        or report.get("competitors") != ["gnark"]
        or report.get("workloads") != list(WORKLOADS)
        or report.get("xark_build_provenance") != "self_consistent"
        or report.get("contention", {}).get("flagged_steps")
    ):
        raise ValueError("report lacks verified Gnark/Xark provenance or clean controls")
    if report["budget"]["pairs"] != pairs or report["budget"]["samples"] != samples:
        raise ValueError("report budget differs from frozen request")
    expected = {
        (workload, backend, pair)
        for workload in WORKLOADS
        for backend in BACKENDS
        for pair in range(1, pairs + 1)
    }
    groups = {key: {} for key in expected}
    with (directory / "samples.csv").open(newline="") as stream:
        for row in csv.DictReader(stream):
            key = (row["workload"], row["backend"], int(row["pair"]))
            if key not in expected or row["metric"] != "proof" or row["lane"] != "checked-resident-proof":
                raise ValueError("unexpected sample lane or group")
            index = int(row["sample"])
            value = int(row["duration_ns"])
            if index in groups[key] or not 1 <= index <= samples or value <= 0:
                raise ValueError("duplicate, missing, or invalid sample")
            groups[key][index] = value
    if any(set(values) != set(range(1, samples + 1)) for values in groups.values()):
        raise ValueError("incomplete sample group")
    summary = {
        (row["workload"], row["backend"]): row
        for row in report["summary"]
        if row["competitor"] == "gnark" and row["metric"] == "proof"
    }
    if set(summary) != {(w, b) for w in WORKLOADS for b in BACKENDS}:
        raise ValueError("missing aggregate summary")
    controls = []
    for workload in WORKLOADS:
        for backend in BACKENDS:
            blocks = [
                summarize(list(groups[(workload, backend, pair)].values()))
                for pair in range(1, pairs + 1)
            ]
            values = [
                value
                for pair in range(1, pairs + 1)
                for value in groups[(workload, backend, pair)].values()
            ]
            pooled = summarize(values)
            expected_summary = summary[(workload, backend)]
            for field in ("count", "p50_ns", "p95_ns", "p99_ns"):
                if pooled[field] != expected_summary[field]:
                    raise ValueError(f"{workload}/{backend} {field} disagrees with raw samples")
            medians = [block["p50_ns"] for block in blocks]
            tails = [block["p95_ns"] for block in blocks]
            p50_drift = (max(medians) - min(medians)) / min(medians)
            p95_drift = (max(tails) - min(tails)) / min(tails)
            controls.append(
                {
                    "workload": workload,
                    "backend": backend,
                    "p50_drift": p50_drift,
                    "p95_drift": p95_drift,
                    "p50_ns": pooled["p50_ns"],
                    "p95_ns": pooled["p95_ns"],
                }
            )
    return {
        "eligible": all(
            row["p50_drift"] <= max_p50 and row["p95_drift"] <= max_p95
            for row in controls
        ),
        "samples_audited": len(expected) * samples,
        "max_p50_drift": max_p50,
        "max_p95_drift": max_p95,
        "controls": controls,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--pairs", type=int, required=True)
    parser.add_argument("--samples", type=int, required=True)
    args = parser.parse_args()
    path = args.directory / "gate.json"
    try:
        result = audit(args.directory, args.pairs, args.samples)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        result = {"eligible": False, "error": str(exc)}
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, sort_keys=True))
    return 0 if result["eligible"] else 1


if __name__ == "__main__":
    sys.exit(main())
