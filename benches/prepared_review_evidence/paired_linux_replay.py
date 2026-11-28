"""Gate and replay prepared audit versus satisfaction-only full proofs.

This script uses the same optimized binary for both arms. It never reads witness
values into its process; the proving binary reads the checked fixture files.
"""

import argparse
import json
import math
import os
import platform
import re
import statistics
import subprocess
import sys
import time
from pathlib import Path

from batch_parser import digest, parse


def p95(values):
    values = sorted(values)
    return values[math.ceil(0.95 * len(values)) - 1]


def drift(a, b):
    return max(a / b, b / a) - 1


def fixture_dirs(root, pins, circuit):
    dirs = sorted(
        {
            (root / name).parent
            for name in pins
            if name.startswith(f"requests/{circuit}/")
        }
    )
    if len(dirs) != 4:
        raise ValueError(f"expected four distinct {circuit} request directories")
    return dirs


def host_details():
    affinity = sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None
    cpu_model = None
    cores = None
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.exists():
        for line in cpuinfo.read_text().splitlines():
            if line.startswith("model name"):
                cpu_model = line.split(":", 1)[1].strip()
                break
    if affinity is not None:
        cores = []
        for cpu in affinity:
            topology = Path(f"/sys/devices/system/cpu/cpu{cpu}/topology")
            try:
                socket = (topology / "physical_package_id").read_text().strip()
                core = (topology / "core_id").read_text().strip()
            except OSError:
                cores = None
                break
            cores.append((socket, core))
    return {
        "platform": platform.platform(),
        "python": platform.python_version(),
        "cpu_model": cpu_model,
        "affinity": affinity,
        "physical_core_ids": cores,
        "load_1m": os.getloadavg()[0],
    }


def run_one(args, circuit, dirs, phase, block, arm, count):
    tag = f"{phase}-{circuit}-b{block}-{arm}"
    stdout = args.output / f"{tag}.stdout"
    stderr = args.output / f"{tag}.stderr"
    env = {
        name: value
        for name, value in os.environ.items()
        if not name.startswith(("BENCH_", "RAYON_", "XARK_SYNTHETIC_"))
    }
    env.update(BENCH_TIME="1", BENCH_PREPARED_SOLVER="1", RAYON_NUM_THREADS=str(args.workers))
    if arm == "satisfied":
        env["BENCH_SAT_ONLY"] = "1"
    reference = args.fixtures / "reference" / circuit
    command = [
        str(args.binary),
        "warm-requests",
        str(reference / "circuit.xbc"),
        str(reference / "test-key.bin"),
        "cpu",
        str(args.concurrency),
        str(count),
        *map(str, dirs),
    ]
    load_before = os.getloadavg()
    begin = time.monotonic_ns()
    with stdout.open("x") as out, stderr.open("x") as err:
        process = subprocess.Popen(command, stdout=out, stderr=err, env=env)
        _, status, usage = os.wait4(process.pid, 0)
        if os.waitstatus_to_exitcode(status):
            raise RuntimeError(f"{tag} failed; inspect {stderr}")
    process_ns = time.monotonic_ns() - begin
    parsed = parse(stdout.read_text(), "cpu", args.concurrency, args.workers, count)
    marks = stderr.read_text().splitlines()
    for receipt in ("prepared stream solver: 1", f"prepared satisfaction-only: {int(arm == 'satisfied')}"):
        if marks.count(receipt) != 1:
            raise ValueError(f"{tag} missing exact mode receipt: {receipt}")
    solved = [
        tuple(map(int, match.groups()))
        for line in marks
        if (match := re.fullmatch(r"request solver index=(\d+) solve_ns=(\d+)", line))
    ]
    if [index for index, _ in solved] != list(range(count)):
        raise ValueError(f"{tag} missing solver timing receipts")
    if not all(0 < ns <= service for (_, ns), service in zip(solved, parsed["services_ns"], strict=True)):
        raise ValueError(f"{tag} invalid solver duration")
    peak_rss = usage.ru_maxrss if sys.platform == "darwin" else 1024 * usage.ru_maxrss
    return {
        "circuit": circuit,
        "phase": phase,
        "block": block,
        "arm": arm,
        "position": tag,
        "count": count,
        "service_p50_ns": statistics.median(parsed["services_ns"]),
        "service_p95_ns": p95(parsed["services_ns"]),
        "solver_ns": [ns for _, ns in solved],
        "peak_rss_bytes": peak_rss,
        "process_ns": process_ns,
        "load_before": load_before,
        "load_after": os.getloadavg(),
        **parsed,
    }


def summary(rows):
    result = {}
    for circuit in ("escrow", "withdrawal"):
        for arm in ("audit", "satisfied"):
            group = [row for row in rows if row["circuit"] == circuit and row["arm"] == arm]
            values = [value for row in group for value in row["services_ns"]]
            waves = [wave["wall_ns"] for row in group for wave in row["waves"]]
            result[f"{circuit}/{arm}"] = {
                "samples": len(values),
                "p50_ns": statistics.median(values),
                "p95_ns": p95(values),
                "active_proofs_per_second": len(values) * 1e9 / sum(waves),
                "peak_rss_bytes": max(row["peak_rss_bytes"] for row in group),
            }
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("binary", "fixtures", "manifest", "output"):
        parser.add_argument(name, type=lambda value: Path(value).resolve())
    parser.add_argument("--source-dir", required=True, type=lambda value: Path(value).resolve())
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--concurrency", type=int, default=1)
    parser.add_argument("--requests", type=int, default=25)
    parser.add_argument("--blocks", type=int, default=4)
    parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args()
    if args.output.exists() or args.workers < args.concurrency or args.concurrency < 1:
        parser.error("output must not exist; workers must cover positive concurrency")
    if args.requests < 4 or args.blocks < 2 or args.blocks % 2:
        parser.error("requires at least four requests and an even block count >=2")
    pins = dict((name, expected) for expected, name in map(str.split, args.manifest.read_text().splitlines()))
    if len(pins) != 28:
        raise ValueError("expected 28 pinned fixture files")
    for name, expected in pins.items():
        if digest(args.fixtures / name) != expected:
            raise ValueError(f"fixture checksum mismatch: {name}")
    host = host_details()
    if not args.smoke and sys.platform.startswith("linux"):
        cores = host["physical_core_ids"]
        if cores is None or len(cores) != args.workers or len(set(map(tuple, cores))) != args.workers:
            parser.error("pin exactly one logical CPU from each requested physical core")
    args.output.mkdir(mode=0o700)
    source_commit = subprocess.check_output(
        ["git", "-C", str(args.source_dir), "rev-parse", "HEAD"], text=True
    ).strip()
    if subprocess.check_output(
        ["git", "-C", str(args.source_dir), "status", "--porcelain"], text=True
    ).strip():
        raise ValueError("benchmark source tree must be clean")
    report = {
        "source_branch": "bench/prepared-solver-soundness-phase",
        "source_commit": source_commit,
        "binary_sha256": digest(args.binary),
        "manifest_sha256": digest(args.manifest),
        "host": host,
        "workers": args.workers,
        "concurrency": args.concurrency,
        "requests_per_run": args.requests,
        "control_requests_per_run": 32,
        "blocks": args.blocks,
        "smoke": args.smoke,
        "performance_eligible": False,
        "host_control_failures": [],
        "control": [],
        "measurements": [],
    }
    dirs = {circuit: fixture_dirs(args.fixtures, pins, circuit) for circuit in ("escrow", "withdrawal")}
    if not args.smoke:
        for circuit in dirs:
            for block in (1, 2):
                for repeat in ("A", "B"):
                    # Both controls must use the same binary and mode.
                    row = run_one(args, circuit, dirs[circuit], f"control-{repeat}", block, "audit", 32)
                    row["position"] = len(report["control"]) + 1
                    report["control"].append(row)
        failures = []
        for circuit in dirs:
            controls = [row for row in report["control"] if row["circuit"] == circuit]
            for block in (1, 2):
                first, second = [row for row in controls if row["block"] == block]
                median = drift(first["service_p50_ns"], second["service_p50_ns"])
                tail = drift(first["service_p95_ns"], second["service_p95_ns"])
                if median > 0.02 or tail > 0.10:
                    failures.append({"circuit": circuit, "block": block, "median_drift": median, "p95_drift": tail})
        report["host_control_failures"] = failures
        (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        if failures:
            print(json.dumps({"host_control_passed": False, "failures": failures}), flush=True)
            return 2
    for circuit in dirs:
        blocks = (1,) if args.smoke else range(1, args.blocks + 1)
        for block in blocks:
            order = ("audit", "satisfied") if block % 2 else ("satisfied", "audit")
            for arm in order:
                row = run_one(args, circuit, dirs[circuit], "measure", block, arm, 4 if args.smoke else args.requests)
                report["measurements"].append(row)
                print(json.dumps({key: value for key, value in row.items() if key not in ("services_ns", "solver_ns", "waves")}), flush=True)
    report["summary"] = summary(report["measurements"])
    report["performance_eligible"] = (
        not args.smoke
        and not report["host_control_failures"]
        and sys.platform.startswith("linux")
        and args.requests * args.blocks >= 100
    )
    (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"performance_eligible": report["performance_eligible"], "summary": report["summary"]}), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
