"""Matched three-arm cleanup ablation for the public prepared CPU prover API."""

import argparse
import json
import statistics
import subprocess
import sys
from pathlib import Path

from replay import digest, drift, host, p95, run

COMMITS = {
    "before": "2b7190abbc6fc1696f23a23fb049d7917416ccc1",
    "cleanup": "98ef685895a9c594938ae6528e8e57bfaf637734",
    "guarded": "5cadc60e1aca6f5ed557da41c501d4f3f89e3549",
}
ORDERS = (
    ("before", "cleanup", "guarded"),
    ("cleanup", "guarded", "before"),
    ("guarded", "before", "cleanup"),
    ("guarded", "cleanup", "before"),
    ("cleanup", "before", "guarded"),
    ("before", "guarded", "cleanup"),
)
EXAMPLE = "crates/groth16/examples/bench_prepared_api.rs"


def source(path, expected, example_digest):
    def git(*args):
        return subprocess.check_output(["git", "-C", str(path), *args], text=True).strip()

    if git("rev-parse", "HEAD") != expected:
        raise ValueError(f"source {path} is not pinned commit {expected}")
    if digest(path / EXAMPLE) != example_digest:
        raise ValueError(f"source {path} has a different benchmark example")
    changed = set(git("status", "--porcelain", "--untracked-files=all").splitlines())
    if changed != {f"?? {EXAMPLE}"}:
        raise ValueError(f"source {path} has unexpected changes: {changed}")


def control_failures(rows):
    failures = []
    for circuit in ("escrow", "withdrawal"):
        for arm in COMMITS:
            pair = [row for row in rows if row["circuit"] == circuit and row["arm"] == arm]
            if len(pair) != 2:
                failures.append(f"{circuit}/{arm}: missing control pair")
            elif drift(pair[0]["p50_ns"], pair[1]["p50_ns"]) > .02 or drift(pair[0]["p95_ns"], pair[1]["p95_ns"]) > .10:
                failures.append(f"{circuit}/{arm}: p50 or p95 drift exceeded 2% / 10%")
    return failures


def summarize(rows):
    summary = {}
    for circuit in ("escrow", "withdrawal"):
        arms = {}
        for arm in COMMITS:
            selected = [row for row in rows if row["circuit"] == circuit and row["arm"] == arm]
            services = [ns for row in selected for ns in row["services_ns"]]
            arms[arm] = {"samples": len(services), "warm_p50_ns": statistics.median(services),
                         "warm_p95_ns": p95(services),
                         "preparation_ns_median": statistics.median(row["setup_ns"] for row in selected),
                         "peak_rss_bytes": max(row["peak_rss_bytes"] for row in selected)}
        deltas = {}
        for before, after in (("before", "cleanup"), ("cleanup", "guarded"), ("before", "guarded")):
            deltas[f"{before}_to_{after}"] = {
                "p50_delta_ns": arms[after]["warm_p50_ns"] - arms[before]["warm_p50_ns"],
                "p95_delta_ns": arms[after]["warm_p95_ns"] - arms[before]["warm_p95_ns"],
                "preparation_delta_ns": arms[after]["preparation_ns_median"] - arms[before]["preparation_ns_median"],
                "peak_rss_delta_bytes": arms[after]["peak_rss_bytes"] - arms[before]["peak_rss_bytes"],
            }
        summary[circuit] = {"arms": arms, "deltas": deltas}
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for arm in COMMITS:
        parser.add_argument(f"--{arm}-source", required=True, type=lambda value: Path(value).resolve())
        parser.add_argument(f"--{arm}-binary", required=True, type=lambda value: Path(value).resolve())
    parser.add_argument("--example", required=True, type=lambda value: Path(value).resolve())
    parser.add_argument("--fixtures", required=True, type=lambda value: Path(value).resolve())
    parser.add_argument("--manifest", required=True, type=lambda value: Path(value).resolve())
    parser.add_argument("--output", required=True, type=lambda value: Path(value).resolve())
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output directory must not exist")
    example_digest = digest(args.example)
    binaries = {}
    for arm, commit in COMMITS.items():
        source(getattr(args, f"{arm}_source"), commit, example_digest)
        binaries[arm] = getattr(args, f"{arm}_binary")
    if len({digest(binary) for binary in binaries.values()}) != len(COMMITS):
        raise ValueError("all three arms must have distinct binaries")
    pins = dict((name, checksum) for checksum, name in map(str.split, args.manifest.read_text().splitlines()))
    if len(pins) != 28 or any(digest(args.fixtures / name) != checksum for name, checksum in pins.items()):
        raise ValueError("fixture manifest does not match 28 pinned files")
    fixture_dirs = {circuit: sorted({(args.fixtures / name).parent for name in pins
                                     if name.startswith(f"requests/{circuit}/")})
                    for circuit in ("escrow", "withdrawal")}
    if any(len(directories) != 4 for directories in fixture_dirs.values()):
        raise ValueError("expected four requests per circuit")
    machine = host()
    topology_ok = (sys.platform.startswith("linux") and machine["physical_core_ids"] is not None
                   and len(machine["physical_core_ids"]) == 2
                   and len(set(machine["physical_core_ids"])) == 2)
    args.output.mkdir(mode=0o700)
    report = {"source_commits": COMMITS, "binary_sha256": {arm: digest(binary) for arm, binary in binaries.items()},
              "example_sha256": example_digest, "manifest_sha256": digest(args.manifest),
              "host": machine, "workers": 2, "topology_ok": topology_ok,
              "performance_eligible": False, "controls": [], "control_failures": [], "measurements": []}

    def invoke(circuit, arm, phase, block, count):
        return run(binaries[arm], "prepared", circuit, fixture_dirs[circuit],
                   args.fixtures / "reference" / circuit, count, 2, args.output,
                   f"{phase}-{circuit}-b{block}-{arm}") | {"arm": arm}

    for circuit in fixture_dirs:
        for arm in COMMITS:
            for block in (1, 2):
                report["controls"].append(invoke(circuit, arm, "control", block, 32))
    report["control_failures"] = control_failures(report["controls"])
    (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    if report["control_failures"] or not topology_ok:
        print(json.dumps({"performance_eligible": False, "control_failures": report["control_failures"],
                          "topology_ok": topology_ok}))
        return 2
    for circuit in fixture_dirs:
        for block, order in enumerate(ORDERS, start=1):
            for arm in order:
                report["measurements"].append(invoke(circuit, arm, "measure", block, 20))
    report["performance_eligible"] = True
    report["summary"] = summarize(report["measurements"])
    (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"performance_eligible": True, "summary": report["summary"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
