#!/usr/bin/env python3
"""Audit four ABBA Xark-only receipts from portable and ADX/BMI2 builds."""

import argparse
import csv
import json
from pathlib import Path
import sys

from run import summarize


ORDER = ("portable-a", "tuned-a", "tuned-b", "portable-b")
WORKLOADS = ("escrow", "withdrawal")


def audit(root, samples=30, max_p50=0.02, max_p95=0.10):
    by_mode = {"portable": {w: [] for w in WORKLOADS}, "tuned": {w: [] for w in WORKLOADS}}
    binaries = {}
    sources = set()
    fixtures = {}
    hosts = set()
    for name in ORDER:
        directory = root / name
        report = json.loads((directory / "report.json").read_text())
        if (
            report.get("status") != "verified"
            or report.get("competitors") != ["xark"]
            or report.get("workloads") != list(WORKLOADS)
            or report.get("xark_build_provenance") != "self_consistent"
            or report.get("contention", {}).get("flagged_steps")
            or report.get("budget", {}).get("pairs") != 2
            or report.get("budget", {}).get("samples") != samples
            or report.get("budget", {}).get("threads") != 2
            or report.get("budget", {}).get("warmups") != 3
        ):
            raise ValueError(f"{name}: missing verified Xark-only receipt or host control")
        mode = name.split("-")[0]
        binary = report["artifacts"]["bench"]["sha256"]
        binaries.setdefault(mode, set()).add(binary)
        sources.add(report["sources"]["xark"]["commit"])
        hosts.add(json.dumps(report["hardware"], sort_keys=True))
        for key, artifact in report["artifacts"].items():
            if key.startswith(("escrow/", "withdrawal/")):
                fixtures.setdefault(key, set()).add(artifact["sha256"])
        groups = {(workload, pair): {} for workload in WORKLOADS for pair in (1, 2)}
        with (directory / "samples.csv").open(newline="") as stream:
            for row in csv.DictReader(stream):
                key = (row["workload"], int(row["pair"]))
                if key not in groups or row["backend"] != "xark" or row["arm"] != "xark" or row["lane"] != "checked-resident-proof" or row["metric"] != "proof":
                    raise ValueError(f"{name}: unexpected sample group")
                index = int(row["sample"])
                value = int(row["duration_ns"])
                if index in groups[key] or not 1 <= index <= samples or value <= 0:
                    raise ValueError(f"{name}: invalid sample index or time")
                groups[key][index] = value
        if any(set(group) != set(range(1, samples + 1)) for group in groups.values()):
            raise ValueError(f"{name}: incomplete samples")
        summaries = {
            row["workload"]: row for row in report["summary"]
            if row["competitor"] == "xark" and row["backend"] == "xark" and row["metric"] == "proof"
        }
        if set(summaries) != set(WORKLOADS):
            raise ValueError(f"{name}: missing aggregate summary")
        for workload in WORKLOADS:
            values = [v for pair in (1, 2) for v in groups[(workload, pair)].values()]
            computed = summarize(values)
            if any(computed[field] != summaries[workload][field] for field in ("count", "p50_ns", "p95_ns", "p99_ns")):
                raise ValueError(f"{name}/{workload}: aggregate disagrees with raw samples")
            for pair in (1, 2):
                by_mode[mode][workload].append(list(groups[(workload, pair)].values()))
    if len(hosts) != 1 or len(sources) != 1 or any(len(v) != 1 for v in binaries.values()) or binaries["portable"] == binaries["tuned"] or any(len(v) != 1 for v in fixtures.values()):
        raise ValueError("source, build, or fixture identity changed across ABBA")
    portable_manifest = json.loads((root / "portable-build-manifest.json").read_text())
    tuned_manifest = json.loads((root / "tuned-build-manifest.json").read_text())
    if (
        portable_manifest["source_commit"] not in sources
        or tuned_manifest["source_commit"] not in sources
        or portable_manifest["binary_sha256"] not in binaries["portable"]
        or tuned_manifest["binary_sha256"] not in binaries["tuned"]
        or portable_manifest.get("rustflags")
        or tuned_manifest.get("rustflags") != "-C target-feature=+adx,+bmi2"
    ):
        raise ValueError("portable/tuned build flags or manifests disagree")
    results = []
    for workload in WORKLOADS:
        block = {}
        for mode in ("portable", "tuned"):
            groups = by_mode[mode][workload]
            medians = [summarize(group)["p50_ns"] for group in groups]
            tails = [summarize(group)["p95_ns"] for group in groups]
            p50_drift = (max(medians) - min(medians)) / min(medians)
            p95_drift = (max(tails) - min(tails)) / min(tails)
            pooled = summarize([value for group in groups for value in group])
            block[mode] = {
                "p50_ns": pooled["p50_ns"],
                "p95_ns": pooled["p95_ns"],
                "p50_drift": p50_drift,
                "p95_drift": p95_drift,
                "eligible": p50_drift <= max_p50 and p95_drift <= max_p95,
            }
        results.append({
            "workload": workload,
            "portable": block["portable"],
            "tuned": block["tuned"],
        })
    eligible = all(row[mode]["eligible"] for row in results for mode in ("portable", "tuned"))
    if eligible:
        for row in results:
            row["tuned_p50_reduction"] = 1 - row["tuned"]["p50_ns"] / row["portable"]["p50_ns"]
    return {
        "eligible": eligible,
        "sample_count": len(ORDER) * len(WORKLOADS) * 2 * samples,
        "max_p50_drift": max_p50,
        "max_p95_drift": max_p95,
        "results": results,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--samples", type=int, default=30)
    args = parser.parse_args()
    try:
        result = audit(args.root, args.samples)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        result = {"eligible": False, "error": str(exc)}
    (args.root / "build-mode-gate.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, sort_keys=True))
    return 0 if result["eligible"] else 1


if __name__ == "__main__":
    sys.exit(main())
