#!/usr/bin/env python3
"""Run an eight-arm resident B2 ablation on the verified Privacy Rings fixtures."""

import argparse
import csv
import importlib.util
import json
import math
import os
from pathlib import Path
import random
import re
import shutil
import statistics
import sys

RUNNER_SHA256 = "2a4fa1cd1013a3654c8868bb35cef386a5fecfc61b0569e77f9afaa7d3463b1a"
FIXTURE_MANIFEST_SHA256 = (
    "2c45d40821b98c428cbd48c6cbd55c42f4b8e61b866a7912e92f46f2ae77fca1"
)
ORDER = (0, 1, 7, 2, 6, 3, 5, 4)
WORKLOADS = ("escrow", "withdrawal")
ARITHMETIC_FACTORS = (
    ("BENCH_G2_TRIM_INVERSE_ENDPOINTS", "bench g2 trim inverse endpoints"),
    ("BENCH_G2_SPARSE_ENDOMORPHISM", "bench g2 sparse endomorphism"),
)
PRECOMPUTE = {
    "shifted": (
        "BENCH_G2_SHIFTED",
        re.compile(
            r"^bench g2 shifted: 1 setup_ns=(?P<ns>\d+) table_payload_bytes=(?P<table_payload_bytes>\d+)$",
            re.M,
        ),
    ),
    "cached-gls": (
        "BENCH_G2_CACHED_GLS",
        re.compile(
            r"^bench g2 cached GLS: 1 rounding=fixed-limb subgroup_points=(?P<subgroup_points>\d+) setup_ns=(?P<ns>\d+) table_payload_bytes=(?P<table_payload_bytes>\d+)$",
            re.M,
        ),
    ),
}
PERF_EVENTS = (
    "cycles",
    "instructions",
    "cache-references",
    "cache-misses",
    "branches",
    "branch-misses",
)
SPAN = re.compile(r"^resident task: (\d+) (\w+) (\d+) (\d+)$", re.M)


def physical_core_groups(affinity, cpu_root=Path("/sys/devices/system/cpu")):
    groups = {}
    for cpu in affinity:
        siblings = (
            (cpu_root / f"cpu{cpu}/topology/thread_siblings_list").read_text().strip()
        )
        if not siblings:
            raise ValueError(f"CPU {cpu} has no reported core sibling group")
        groups.setdefault(siblings, []).append(cpu)
    return groups


def runner_at(path):
    # Validate the archived, audited runner before executing its module.
    import hashlib

    if hashlib.sha256(path.read_bytes()).hexdigest() != RUNNER_SHA256:
        raise ValueError("competitive runner hash differs from the pinned revision")
    spec = importlib.util.spec_from_file_location("competitive_runner", path)
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    return runner


def arm_order(block, ranks):
    return [ranks[(number + block) % 8] for number in ORDER]


def paired_interval(deltas, seed):
    if len(deltas) < 8:
        return None
    rng = random.Random(seed)
    medians = sorted(
        statistics.median(rng.choices(deltas, k=len(deltas))) for _ in range(10_000)
    )
    return [medians[249], medians[9749]]


def summarize(runner, path, runs, seed, precompute):
    with path.open(newline="") as stream:
        samples = list(csv.DictReader(stream))
    result = {}
    factor = "shift" if precompute == "shifted" else "cached_gls"
    paired_key = f"median_paired_{factor}_savings_ns"
    interval_key = f"paired_block_{factor}_savings_interval_ns"
    runs_by_arm = {(r["workload"], r["block"], r["arm"]): r for r in runs}
    for workload in WORKLOADS:
        filtered = [row for row in samples if row["workload"] == workload]
        blocks = sorted({int(row["block"]) for row in filtered})
        arms = {}
        for arm in range(8):
            arms[str(arm)] = metrics = {}
            for field in ("proof_ns", "b2_ns", "profiled_join_ns"):
                series = {
                    choice: {
                        block: [
                            int(row[field])
                            for row in filtered
                            if int(row["arm"]) == choice and int(row["block"]) == block
                        ]
                        for block in blocks
                    }
                    for choice in {0, arm, arm & ~4}
                }
                deltas = [
                    statistics.median(series[0][block])
                    - statistics.median(series[arm][block])
                    for block in blocks
                ]
                value = runner.summarize(
                    [n for block in series[arm].values() for n in block]
                )
                value["median_paired_savings_ns"] = statistics.median(deltas)
                value["paired_block_savings_interval_ns"] = paired_interval(
                    deltas, seed
                )
                if arm & 4:
                    precompute_savings = [
                        statistics.median(series[arm & ~4][block])
                        - statistics.median(series[arm][block])
                        for block in blocks
                    ]
                    value[paired_key] = statistics.median(precompute_savings)
                    value[interval_key] = paired_interval(precompute_savings, seed)
                metrics[field] = value
            steps = [runs_by_arm[workload, block, arm] for block in blocks]
            setup = [step["setup"]["ns"] for step in steps if step["setup"] is not None]
            metrics[f"p50_{factor}_setup_ns"] = (
                statistics.median(setup) if setup else None
            )
            metrics[f"retained_{factor}_payload_bytes"] = sorted(
                {
                    step["setup"]["table_payload_bytes"]
                    for step in steps
                    if step["setup"] is not None
                }
            )
            observed_rss = [step["host"]["sampled_peak_rss_kib"] for step in steps]
            metrics["max_sampled_process_rss_kib"] = (
                max(observed_rss) if None not in observed_rss else None
            )
            if arm & 4:
                savings = metrics["proof_ns"][paired_key]
                low_interval = metrics["proof_ns"][interval_key]
                metrics["setup_divided_by_paired_proof_savings"] = (
                    math.ceil(statistics.median(setup) / savings)
                    if savings > 0
                    else None
                )
                metrics["break_even_supported_by_interval"] = bool(
                    low_interval and low_interval[0] > 0
                )
        result[workload] = arms
    return result


def run(args):
    runner = runner_at(args.runner.resolve(strict=True))
    root = args.fixtures.resolve(strict=True)
    binary = args.binary.resolve(strict=True)
    manifest = args.runner.with_name("fixtures.sha256")
    runner.require(
        runner.digest(manifest) == FIXTURE_MANIFEST_SHA256,
        "fixture manifest hash differs",
    )
    for line in manifest.read_text().splitlines():
        digest, name = line.split()
        runner.require(
            runner.digest(root / name) == digest, f"fixture mismatch: {name}"
        )
    source = runner.capture(["git", "-C", str(args.source), "rev-parse", "HEAD"])
    runner.require(
        not runner.capture(
            [
                "git",
                "-C",
                str(args.source),
                "status",
                "--porcelain",
                "--untracked-files=no",
            ]
        ),
        "dirty tracked source",
    )
    binary_hash = runner.digest(binary)
    host = runner.host()
    core_groups = None
    if not args.diagnostic:
        runner.require(
            sys.platform == "linux", "strict performance mode requires Linux"
        )
        runner.require(
            host["affinity"] and len(host["affinity"]) == args.threads,
            "pin the runner to exactly the requested CPUs",
        )
        runner.require(
            args.blocks >= 8
            and args.blocks % 8 == 0
            and args.samples * args.blocks >= 100,
            "use balanced blocks and at least 100 samples per arm",
        )
        runner.require(
            not runner.processes(os.getpgrp(), args.contention_percent),
            "host preflight detected contention",
        )
    if args.topology:
        runner.require(
            sys.platform == "linux" and host["affinity"],
            "Linux affinity is required for topology checks",
        )
        runner.require(
            len(host["affinity"]) == args.threads and args.threads >= 2,
            "pin the requested worker count before checking topology",
        )
        core_groups = physical_core_groups(host["affinity"])
        expected = 1 if args.topology == "siblings" else args.threads
        runner.require(
            len(core_groups) == expected,
            f"CPU affinity does not match {args.topology} topology: {core_groups}",
        )
    if args.perf_counters:
        runner.require(
            sys.platform == "linux" and shutil.which("perf"),
            "perf is unavailable on this host",
        )
    args.output = args.output.resolve()
    args.output.mkdir(mode=0o700)
    env = os.environ.copy()
    for key in ("NO_BATCH_AFFINE", "NO_GLV", "CHECK", "BENCH_ESCROW_STATEMENTS"):
        env.pop(key, None)
    env.update(
        BENCH_TIME="1",
        BENCH_CHECK_ROWS="1",
        BENCH_WARM_BACKEND="cpu",
        BENCH_MERGE_BELOW="0",
        BENCH_RESIDENT_PROFILE="1",
        RAYON_NUM_THREADS=str(args.threads),
    )
    for setting, _ in PRECOMPUTE.values():
        env[setting] = "0"
    precompute_setting, _ = PRECOMPUTE[args.precompute]
    factor_settings = [name for name, _ in ARITHMETIC_FACTORS] + [precompute_setting]
    rng = random.Random(args.seed)
    ranks = list(range(8))
    rng.shuffle(ranks)
    block_order = list(range(args.blocks))
    rng.shuffle(block_order)
    report = {
        "binary_sha256": binary_hash,
        "source_commit": source,
        "host": host,
        "fixture_manifest_sha256": FIXTURE_MANIFEST_SHA256,
        "seed": args.seed,
        "threads": args.threads,
        "requested_topology": args.topology,
        "physical_core_groups": core_groups,
        "diagnostic": args.diagnostic,
        "precompute": args.precompute,
        "arm_bits": factor_settings,
        "perf_scope": "whole benchmark process, including setup and verification"
        if args.perf_counters
        else None,
        "samples_per_block": args.samples,
        "warmups": args.warmups,
        "runs": [],
    }
    fieldnames = (
        "workload",
        "block",
        "position",
        "arm",
        "sample",
        "proof_ns",
        "b2_start_ns",
        "b2_ns",
        "peer_finish_ns",
        "profiled_join_ns",
    )
    with (args.output / "samples.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames, lineterminator="\n")
        writer.writeheader()
        for block in block_order:
            workloads = WORKLOADS if block % 2 == 0 else WORKLOADS[::-1]
            for workload in workloads:
                fixture = root / workload
                command = [
                    binary,
                    "warm",
                    fixture / "circuit.xbc",
                    fixture / "test-key.bin",
                    fixture / "inputs.json",
                    str(args.samples),
                    str(args.warmups),
                ]
                for position, arm in enumerate(arm_order(block, ranks)):
                    label = f"{workload}-block-{block}-arm-{arm}"
                    settings = {
                        name: str((arm >> index) & 1)
                        for index, name in enumerate(factor_settings)
                    }
                    invocation = command
                    counters = None
                    if args.perf_counters:
                        counters = args.output / f"{label}.perf.csv"
                        invocation = [
                            "perf",
                            "stat",
                            "--no-big-num",
                            "-x,",
                            "-e",
                            ",".join(PERF_EVENTS),
                            "-o",
                            str(counters),
                            "--",
                            *command,
                        ]
                    code, log, contention = runner.execute(
                        invocation,
                        env | settings | {"BENCH_PUBLIC_STATEMENTS": str(fixture)},
                        args.output,
                        label,
                        args.timeout,
                        args.contention_percent,
                    )
                    runner.require(code == 0, f"{label} failed, see its log")
                    if not args.diagnostic:
                        runner.require(
                            contention["polls"]
                            and not contention["observed"]
                            and not contention["error"],
                            f"{label} host control failed",
                        )
                    if counters is not None:
                        verify_counters(runner, counters)
                        contention[
                            "sampled_peak_rss_kib"
                        ] = None  # sampler sees the perf wrapper
                    rows, setup = parse_trial(runner, log, settings, args)
                    for sample, (proof, start, b2, peer_end) in enumerate(rows, 1):
                        writer.writerow(
                            dict(
                                zip(
                                    fieldnames,
                                    (
                                        workload,
                                        block,
                                        position,
                                        arm,
                                        sample,
                                        proof,
                                        start,
                                        b2,
                                        peer_end,
                                        max(start + b2, peer_end),
                                    ),
                                    strict=True,
                                )
                            )
                        )
                    stream.flush()
                    report["runs"].append(
                        {
                            "workload": workload,
                            "block": block,
                            "arm": arm,
                            "position": position,
                            "perf_csv": counters.name if counters else None,
                            "setup": setup,
                            "host": contention,
                            "verified_proofs": len(rows),
                            "log": f"{label}.log",
                        }
                    )
    runner.require(runner.digest(binary) == binary_hash, "binary changed during run")
    report["statistics"] = summarize(
        runner, args.output / "samples.csv", report["runs"], args.seed, args.precompute
    )
    report["performance_eligible"] = not args.diagnostic
    if args.diagnostic:
        for arms in report["statistics"].values():
            for metrics in arms.values():
                if "break_even_supported_by_interval" in metrics:
                    metrics["break_even_supported_by_interval"] = False
    (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(
        f"Verified {sum(row['verified_proofs'] for row in report['runs'])} complete proofs"
    )


def verify_counters(runner, path):
    with path.open(newline="") as stream:
        events = {
            row[2]: int(row[0])
            for row in csv.reader(stream)
            if len(row) >= 3 and row[2] in PERF_EVENTS and row[0].isdigit()
        }
    runner.require(
        set(events) == set(PERF_EVENTS), "missing or unsupported perf counters"
    )


def parse_trial(runner, log, settings, args):
    proof_ns = runner.proof_samples(log, "xark", args.samples, args.threads, True)[
        "proof"
    ]
    runner.require(
        re.search(r"^resident CPU: .* merge_below=0 merged=false$", log, re.M),
        "split CPU mode receipt missing",
    )
    for name, marker in ARITHMETIC_FACTORS:
        runner.require(
            f"{marker}: {settings[name]}" in log.splitlines(),
            f"{name} receipt mismatch",
        )
    setup = None
    for name, (setting, pattern) in PRECOMPUTE.items():
        matches = list(pattern.finditer(log))
        runner.require(
            len(matches) == int(settings.get(setting, "0")),
            f"{name} B2 receipt mismatch",
        )
        if matches:
            setup = {key: int(value) for key, value in matches[0].groupdict().items()}
    spans = {index: {} for index in range(1, args.samples + 1)}
    for sample, name, start, elapsed in SPAN.findall(log):
        trial = spans[int(sample)]
        runner.require(name not in trial, "duplicate task")
        trial[name] = (int(start), int(elapsed))
    rows = []
    for index, proof in enumerate(proof_ns, 1):
        trial = spans[index]
        b2_start, b2 = trial["msm_b2"]
        peers = ("msm_a", "msm_b1", "msm_l", "msm_h", "quotient")
        peer_end = max(sum(trial[name]) for name in peers)
        rows.append((proof, b2_start, b2, peer_end))
    return rows, setup


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("binary", "source", "runner", "fixtures", "output"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--blocks", type=int, default=8)
    parser.add_argument("--samples", type=int, default=13)
    parser.add_argument("--warmups", type=int, default=3)
    parser.add_argument("--threads", type=int, default=2)
    parser.add_argument("--seed", type=int, default=731)
    parser.add_argument("--timeout", type=float, default=300)
    parser.add_argument("--contention-percent", type=float, default=20)
    parser.add_argument("--diagnostic", action="store_true")
    parser.add_argument("--perf-counters", action="store_true")
    parser.add_argument("--precompute", choices=PRECOMPUTE, default="shifted")
    parser.add_argument("--topology", choices=("siblings", "distinct"))
    args = parser.parse_args()
    if (
        min(
            args.blocks,
            args.samples,
            args.warmups,
            args.threads,
            args.timeout,
            args.contention_percent,
        )
        <= 0
    ):
        parser.error("all run budgets must be positive")
    try:
        run(args)
    except (OSError, KeyError, ValueError) as error:
        parser.exit(1, f"ablation: {error}\n")


if __name__ == "__main__":
    main()
