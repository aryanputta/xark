#!/usr/bin/env python3
"""Measure checked resident proof scaling on the pinned Privacy Rings fixtures."""

import argparse
from contextlib import ExitStack
import csv
import hashlib
import io
import json
import math
import os
from pathlib import Path
import platform
import re
import statistics
import subprocess
import time

PROFILES = (("one-worker", 1, 1), ("two-workers", 1, 2), ("two-processes", 2, 1))
SHARED_PROFILES = (*PROFILES[1:], ("shared-resident", 1, 2))
WORKLOADS = ("escrow", "withdrawal")
INPUTS = (
    "circuit.xbc",
    "test-key.bin",
    "inputs.json",
    "public.json",
    "public-changed.json",
)
TIMING = re.compile(r"^warm prove: xark-groth16 ([0-9]+\.[0-9]+)s$", re.MULTILINE)
COMPLETION = re.compile(
    r"^warm batch completion: xark-groth16 ([1-9][0-9]*) ns$", re.MULTILINE
)
REJECTION = "changed statement rejected by Arkworks and Xark for each backend"
SHARED_VERIFIED = "shared resident proof lanes verified: two one-thread pools"


def verified_samples(log, expected, *, shared=False):
    text = log.read_text()
    timings = [float(value) for value in TIMING.findall(text)]
    if (
        len(timings) != expected
        or any(value <= 0 for value in timings)
        or REJECTION not in text
        or "witness row checker: compiled" not in text
        or (shared and SHARED_VERIFIED not in text.splitlines())
    ):
        raise RuntimeError(f"missing verification or timing evidence in {log}")
    return timings


def sha256(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def batch_completion_metrics(log, expected):
    completions = sorted(int(value) for value in COMPLETION.findall(log.read_text()))
    if len(completions) != expected:
        raise RuntimeError(f"missing batch completion evidence in {log}")
    return {
        "warm_batch_ms": round(completions[-1] / 1e6, 3),
        "warm_batch_completion_p95_ms": round(
            completions[math.ceil(expected * 0.95) - 1] / 1e6, 3
        ),
    }


def run_arm(binary, fixture, destination, profile, samples, shared_study):
    name, processes, threads = profile
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("BENCH_") and key != "NO_BATCH_AFFINE"
    }
    environment.update(
        BENCH_TIME="1",
        BENCH_WARM_BACKEND="cpu",
        BENCH_CHECK_ROWS="1",
        BENCH_MERGE_BELOW="0",
        BENCH_PUBLIC_STATEMENTS=str(fixture),
        RAYON_NUM_THREADS=str(threads),
    )
    if name == "shared-resident":
        environment["BENCH_SHARED_RESIDENT"] = "1"
    count = samples // processes
    command = [
        str(binary),
        "warm",
        *(str(fixture / name) for name in INPUTS[:3]),
        str(count),
        str(4 // processes),
    ]
    environment_receipt = {
        key: value
        for key, value in environment.items()
        if key.startswith("BENCH_") or key == "RAYON_NUM_THREADS"
    }
    (destination / "command.json").write_text(
        json.dumps({"argv": command, "env": environment_receipt}, indent=2) + "\n"
    )
    logs = [destination / f"worker-{worker}.log" for worker in range(1, processes + 1)]
    children = []
    peak_rss = []
    statuses = []
    with ExitStack() as cleanup:
        handles = [cleanup.enter_context(log.open("wb")) for log in logs]
        load_start = os.getloadavg()[0]
        start = time.perf_counter()
        try:
            for output in handles:
                children.append(
                    subprocess.Popen(
                        command,
                        env=environment,
                        stdout=output,
                        stderr=subprocess.STDOUT,
                    )
                )
            for child in children:
                _, status, usage = os.wait4(child.pid, 0)
                child.returncode = os.waitstatus_to_exitcode(status)
                statuses.append(child.returncode)
                peak_rss.append(
                    usage.ru_maxrss * (1 if platform.system() == "Darwin" else 1024)
                )
            makespan = time.perf_counter() - start
        finally:
            for child in children:
                if child.returncode is None:
                    child.kill()
                    child.wait()

    if any(statuses):
        raise RuntimeError(f"proof workers exited {statuses}. See {destination}")
    timings = sorted(
        value
        for log in logs
        for value in verified_samples(log, count, shared=name == "shared-resident")
    )
    metrics = {
        "samples": len(timings),
        "p50_ms": round(statistics.median(timings) * 1000, 3),
        "p95_ms": round(timings[math.ceil(len(timings) * 0.95) - 1] * 1000, 3),
        "verified_makespan_s": round(makespan, 3),
        "verified_proofs_s": round(samples / makespan, 4),
        "worker_peak_rss_sum_mib": round(sum(peak_rss) / 1024**2, 3),
        "one_min_load_start": round(load_start, 3),
        "one_min_load_end": round(os.getloadavg()[0], 3),
    }
    if shared_study:
        # Separate processes have no common measured-batch start time.
        metrics.update(
            batch_completion_metrics(logs[0], count)
            if processes == 1
            else {"warm_batch_ms": None, "warm_batch_completion_p95_ms": None}
        )
    return metrics


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("fixtures", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument(
        "--samples", type=int, default=20, help="even sample count per arm"
    )
    parser.add_argument(
        "--shared-resident",
        action="store_true",
        help="compare three schedules at a fixed two-thread proving budget",
    )
    args = parser.parse_args()
    if args.samples < 2 or args.samples % 2:
        parser.error("--samples must be an even integer of at least two")
    if platform.system() not in {"Darwin", "Linux"}:
        parser.error("run on Linux or macOS")
    binary, fixtures = args.binary.resolve(), args.fixtures.resolve()
    paths = [binary] + [
        fixtures / workload / name for workload in WORKLOADS for name in INPUTS
    ]
    fingerprints = {str(path): sha256(path) for path in paths}
    args.output.mkdir()
    (args.output / "host.json").write_text(
        json.dumps(
            {
                "platform": platform.platform(),
                "logical_cpus": os.cpu_count(),
                "sha256": fingerprints,
            },
            indent=2,
        )
        + "\n"
    )
    rows = []
    profiles = SHARED_PROFILES if args.shared_resident else PROFILES
    for rotation in range(len(profiles)):
        order = profiles[rotation:] + profiles[:rotation]
        workloads = WORKLOADS if rotation % 2 == 0 else WORKLOADS[::-1]
        for workload in workloads:
            for position, profile in enumerate(order, 1):
                name, processes, threads = profile
                label = f"{workload}-{rotation + 1}-{name}"
                destination = args.output / label
                destination.mkdir()
                metrics = run_arm(
                    binary,
                    fixtures / workload,
                    destination,
                    profile,
                    args.samples,
                    args.shared_resident,
                )
                rows.append(
                    {
                        "workload": workload,
                        "rotation": rotation + 1,
                        "position": position,
                        "profile": name,
                        "processes": processes,
                        "threads_per_process": threads,
                        **metrics,
                    }
                )
                print(label, json.dumps(metrics), flush=True)

    if fingerprints != {str(path): sha256(path) for path in paths}:
        raise RuntimeError("a fixture or benchmark binary changed during the run")
    summary = io.StringIO()
    writer = csv.DictWriter(summary, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)
    (args.output / "arms.csv").write_text(summary.getvalue())


if __name__ == "__main__":
    main()
