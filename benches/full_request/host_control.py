"""Reject unstable hosts using alternating, independently verified identical proofs."""

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
    ordered = sorted(values)
    return ordered[math.ceil(0.95 * len(ordered)) - 1]


def relative_drift(first, second):
    if first <= 0 or second <= 0:
        raise ValueError("nonpositive timing")
    return max(first / second, second / first) - 1


def assess(rows, blocks, max_median_drift, max_p95_drift):
    expected = {
        (fixture, block, arm)
        for fixture in ("escrow", "withdrawal")
        for block in range(1, blocks + 1)
        for arm in ("A", "B")
    }
    actual = [(r["fixture"], r["block"], r["arm"]) for r in rows]
    if len(actual) != len(expected) or set(actual) != expected:
        raise ValueError("incomplete or duplicate host-control matrix")
    pairs = []
    for fixture in ("escrow", "withdrawal"):
        for block in range(1, blocks + 1):
            arms = {
                r["arm"]: r
                for r in rows
                if r["fixture"] == fixture and r["block"] == block
            }
            if set(arms) != {"A", "B"}:
                raise ValueError(f"missing identical arm in {fixture} block {block}")
            a, b = arms["A"], arms["B"]
            median_drift = relative_drift(a["p50_ns"], b["p50_ns"])
            tail_drift = relative_drift(a["p95_ns"], b["p95_ns"])
            pairs.append(
                dict(
                    fixture=fixture,
                    block=block,
                    median_drift=median_drift,
                    p95_drift=tail_drift,
                    passed=median_drift <= max_median_drift
                    and tail_drift <= max_p95_drift,
                )
            )
    return dict(passed=bool(pairs) and all(p["passed"] for p in pairs), pairs=pairs)


def run(args):
    if args.output.exists():
        raise ValueError("output directory already exists")
    args.output.mkdir(mode=0o700)
    manifest = dict(
        (name, expected)
        for expected, name in map(str.split, args.manifest.read_text().splitlines())
    )
    if len(manifest) != 28:
        raise ValueError("expected 28 pinned fixture files")
    for name, expected in manifest.items():
        if digest(args.fixtures / name) != expected:
            raise ValueError(f"fixture checksum mismatch: {name}")
    env = {
        name: value
        for name, value in os.environ.items()
        if not name.startswith(("BENCH_", "RAYON_"))
    } | {"BENCH_TIME": "1", "RAYON_NUM_THREADS": str(args.workers)}
    rows = []
    for fixture in ("escrow", "withdrawal"):
        artifact = args.fixtures / "reference" / fixture
        dirs = sorted(
            {
                (args.fixtures / name).parent
                for name in manifest
                if name.startswith(f"requests/{fixture}/")
            }
        )
        if len(dirs) != 4:
            raise ValueError(f"expected four distinct {fixture} requests")
        for block in range(1, args.blocks + 1):
            for position, arm in enumerate(("A", "B") if block % 2 else ("B", "A"), 1):
                tag = f"{fixture}-b{block}-{arm}"
                command = [
                    str(args.binary),
                    "warm-requests",
                    str(artifact / "circuit.xbc"),
                    str(artifact / "test-key.bin"),
                    "cpu",
                    str(args.concurrency),
                    str(args.requests),
                    *map(str, dirs),
                ]
                stdout = args.output / f"{tag}.stdout"
                stderr = args.output / f"{tag}.stderr"
                load_start = os.getloadavg()
                start = time.monotonic_ns()
                with stdout.open("x") as out, stderr.open("x") as err:
                    process = subprocess.Popen(command, stdout=out, stderr=err, env=env)
                    _, status, usage = os.wait4(process.pid, 0)
                    if os.waitstatus_to_exitcode(status):
                        raise RuntimeError(f"{tag} failed; inspect its stderr")
                process_ns = time.monotonic_ns() - start
                parsed = parse(
                    stdout.read_text(),
                    "cpu",
                    args.concurrency,
                    args.workers,
                    args.requests,
                )
                marks = stderr.read_text().splitlines()
                if marks.count("upstream verified request wrapper: 1") != 1:
                    raise ValueError(f"{tag} missing baseline mode receipt")
                solve = [
                    tuple(map(int, match.groups()))
                    for line in marks
                    if (
                        match := re.fullmatch(
                            r"request solver index=(\d+) solve_ns=(\d+)", line
                        )
                    )
                ]
                if [index for index, _ in solve] != list(range(args.requests)):
                    raise ValueError(f"{tag} missing solver timings")
                if not all(
                    0 < ns <= service
                    for (_, ns), service in zip(
                        solve, parsed["services_ns"], strict=True
                    )
                ):
                    raise ValueError(f"{tag} invalid solver timing")
                rss = (
                    usage.ru_maxrss
                    if sys.platform == "darwin"
                    else 1024 * usage.ru_maxrss
                )
                rows.append(
                    dict(
                        fixture=fixture,
                        block=block,
                        arm=arm,
                        position=position,
                        p50_ns=statistics.median(parsed["services_ns"]),
                        p95_ns=p95(parsed["services_ns"]),
                        process_ns=process_ns,
                        peak_rss_bytes=rss,
                        load_start=load_start,
                        load_end=os.getloadavg(),
                        **parsed,
                    )
                )
                print(
                    json.dumps(
                        {
                            key: value
                            for key, value in rows[-1].items()
                            if key not in ("waves", "services_ns")
                        }
                    ),
                    flush=True,
                )
    assessment = assess(rows, args.blocks, args.max_median_drift, args.max_p95_drift)
    report = dict(
        binary_sha256=digest(args.binary),
        manifest_sha256=digest(args.manifest),
        host=platform.platform(),
        workers=args.workers,
        concurrency=args.concurrency,
        requests=args.requests,
        blocks=args.blocks,
        max_median_drift=args.max_median_drift,
        max_p95_drift=args.max_p95_drift,
        same_binary_control=assessment,
        performance_eligible=False,
        runs=rows,
    )
    (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(
        json.dumps({"same_binary_control": assessment, "performance_eligible": False}),
        flush=True,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("binary", "fixtures", "manifest", "output"):
        parser.add_argument(name, type=lambda value: Path(value).resolve())
    parser.add_argument("--requests", type=int, default=8)
    parser.add_argument("--blocks", type=int, default=4)
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--concurrency", type=int, choices=(1, 2), default=1)
    parser.add_argument("--max-median-drift", type=float, default=0.02)
    parser.add_argument("--max-p95-drift", type=float, default=0.10)
    args = parser.parse_args()
    if (
        args.requests < 4
        or args.blocks < 2
        or args.blocks % 2
        or args.workers < args.concurrency
    ):
        parser.error(
            "requires at least four requests, even blocks >= 2, and enough workers"
        )
    if not 0 <= args.max_median_drift < 1 or not 0 <= args.max_p95_drift < 1:
        parser.error("drift thresholds must be between zero and one")
    run(args)


if __name__ == "__main__":
    main()
