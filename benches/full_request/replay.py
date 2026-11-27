"""Compare exact upstream and two prepared Xark settings on full requests."""

import argparse
import hashlib
import json
import os
import platform
import re
import statistics
import subprocess
import sys
import time
from pathlib import Path

from batch_parser import parse
from host_control import assess, host_binding, p95


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sha_json(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def validate_host_control(report, *, binary_sha256, manifest_sha256, workers, binding):
    if (
        not binding.get("boot_id")
        or not binding.get("affinity")
        or len(binding["affinity"]) != workers
    ):
        raise ValueError(
            "replay requires Linux boot identity and exact worker affinity"
        )
    if report.get("binary_sha256") != binary_sha256:
        raise ValueError("host control used a different upstream binary")
    if report.get("manifest_sha256") != manifest_sha256:
        raise ValueError("host control used a different fixture manifest")
    if report.get("workers") != workers or report.get("concurrency") != 1:
        raise ValueError("host control used a different worker budget or concurrency")
    if report.get("host_binding") != binding:
        raise ValueError("host control ran on a different host, boot, or CPU affinity")
    if report.get("requests", 0) < 8 or report.get("blocks", 0) < 2:
        raise ValueError("host control has too few requests or blocks")
    if (
        report.get("max_median_drift", 1) > 0.02
        or report.get("max_p95_drift", 1) > 0.10
    ):
        raise ValueError("host control used looser drift thresholds")
    try:
        for row in report["runs"]:
            services = row["services_ns"]
            if (
                len(services) != report["requests"]
                or any(value <= 0 for value in services)
                or row["p50_ns"] != statistics.median(services)
                or row["p95_ns"] != p95(services)
                or len(row["waves"]) != report["requests"]
            ):
                raise ValueError(
                    "host control has inconsistent verified request timings"
                )
        assessed = assess(
            report["runs"],
            report["blocks"],
            report["max_median_drift"],
            report["max_p95_drift"],
        )
    except (KeyError, TypeError) as exc:
        raise ValueError("host control report is incomplete") from exc
    if not assessed["passed"] or report.get("same_binary_control") != assessed:
        raise ValueError("host control did not pass its recorded stability gate")
    return sha_json(report)


def run(args):
    binary = {
        "upstream": args.upstream,
        "prepared-cpu": args.candidate,
        "prepared-gls": args.candidate,
    }
    plans = tuple(binary)
    mode = {"upstream": "cpu", "prepared-cpu": "cpu", "prepared-gls": "gls"}
    pins = dict(
        (name, digest)
        for digest, name in map(str.split, args.manifest.read_text().splitlines())
    )
    if len(pins) != 28:
        raise ValueError("expected the pinned circuit, key and request files")
    for name, digest in pins.items():
        if sha(args.fixtures / name) != digest:
            raise ValueError(f"fixture checksum mismatch: {name}")
    binary_hashes = {arm: sha(path) for arm, path in binary.items()}
    manifest_hash = sha(args.manifest)
    binding = host_binding()
    control = json.loads(args.host_control_report.read_text())
    control_hash = validate_host_control(
        control,
        binary_sha256=binary_hashes["upstream"],
        manifest_sha256=manifest_hash,
        workers=args.workers,
        binding=binding,
    )
    args.output.mkdir(mode=0o700)
    workers = args.workers
    count = args.requests
    base_env = {
        name: value
        for name, value in os.environ.items()
        if not name.startswith(("BENCH_", "RAYON_"))
    } | {"BENCH_TIME": "1", "RAYON_NUM_THREADS": str(workers)}
    rows = []
    for fixture in ("escrow", "withdrawal"):
        artifacts = args.fixtures / "reference" / fixture
        dirs = sorted(
            {
                (args.fixtures / name).parent
                for name in pins
                if name.startswith(f"requests/{fixture}/")
            }
        )
        if len(dirs) != 4:
            raise ValueError("expected four distinct pinned request directories")
        for concurrency in (1, 2):
            start_plans = plans if concurrency == 1 else plans[::-1]
            for block in range(args.blocks):
                rotate = block % len(start_plans)
                arms = start_plans[rotate:] + start_plans[:rotate]
                for position, arm in enumerate(arms):
                    tag = f"{fixture}-c{concurrency}-b{block + 1}-{arm}"
                    env = (
                        base_env
                        if arm == "upstream"
                        else base_env | {"BENCH_PREPARED_SOLVER": "1"}
                    )
                    argv = [
                        binary[arm],
                        "warm-requests",
                        artifacts / "circuit.xbc",
                        artifacts / "test-key.bin",
                        mode[arm],
                        str(concurrency),
                        str(count),
                        *dirs,
                    ]
                    load_start = os.getloadavg()
                    begin = time.monotonic_ns()
                    stdout = args.output / f"{tag}.stdout"
                    stderr = args.output / f"{tag}.stderr"
                    with stdout.open("x") as out, stderr.open("x") as err:
                        proc = subprocess.Popen(argv, env=env, stdout=out, stderr=err)
                        _, status, usage = os.wait4(proc.pid, 0)
                        proc.returncode = os.waitstatus_to_exitcode(status)
                        if proc.returncode:
                            raise RuntimeError(f"{tag} failed; see stderr")
                    elapsed = time.monotonic_ns() - begin
                    load_end = os.getloadavg()
                    verified = parse(
                        stdout.read_text(), mode[arm], concurrency, workers, count
                    )
                    marks = stderr.read_text().splitlines()
                    receipt = (
                        "upstream verified request wrapper: 1"
                        if arm == "upstream"
                        else "prepared stream solver: 1"
                    )
                    if marks.count(receipt) != 1:
                        raise ValueError(f"{tag} missing configuration receipt")
                    timings = [
                        tuple(map(int, m.groups()))
                        for row in marks
                        if (
                            m := re.fullmatch(
                                r"request solver index=(\d+) solve_ns=(\d+)", row
                            )
                        )
                    ]
                    if [i for i, _ in timings] != list(range(count)):
                        raise ValueError(f"{tag} missing solve phase timings")
                    solve = [ns for _, ns in timings]
                    if not all(
                        0 < ns <= service
                        for ns, service in zip(solve, verified["services_ns"])
                    ):
                        raise ValueError(f"{tag} invalid solve phase durations")
                    rss = (
                        usage.ru_maxrss
                        if sys.platform == "darwin"
                        else 1024 * usage.ru_maxrss
                    )
                    row = dict(
                        fixture=fixture,
                        concurrency=concurrency,
                        arm=arm,
                        block=block + 1,
                        position=position + 1,
                        process_ns=elapsed,
                        load_start=load_start,
                        load_end=load_end,
                        peak_rss_bytes=rss,
                        solve_ns=solve,
                        solve_median_ns=statistics.median(solve),
                        **verified,
                    )
                    rows.append(row)
                    print(
                        json.dumps(
                            {
                                k: v
                                for k, v in row.items()
                                if k not in ("waves", "solve_ns", "services_ns")
                            }
                        ),
                        flush=True,
                    )
    if (
        {arm: sha(path) for arm, path in binary.items()} != binary_hashes
        or sha(args.manifest) != manifest_hash
        or any(sha(args.fixtures / name) != digest for name, digest in pins.items())
        or host_binding() != binding
        or sha_json(json.loads(args.host_control_report.read_text())) != control_hash
    ):
        raise ValueError("binary, fixture, host, or host control changed during replay")
    report = {
        "binary_sha256": binary_hashes,
        "fixture_manifest_sha256": manifest_hash,
        "host_control_report_canonical_sha256": control_hash,
        "host_binding": binding,
        "parser_sha256": sha(Path(__file__).with_name("batch_parser.py")),
        "platform": platform.platform(),
        "performance_eligible": False,
        "workers": workers,
        "requests": count,
        "blocks": args.blocks,
        "runs": rows,
    }
    (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ("upstream", "candidate", "fixtures", "manifest", "output"):
        parser.add_argument(arg, type=lambda path: Path(path).resolve())
    parser.add_argument("--requests", type=int, default=8)
    parser.add_argument("--blocks", type=int, default=3)
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument(
        "--host-control-report", type=lambda path: Path(path).resolve(), required=True
    )
    args = parser.parse_args()
    if args.requests < 4 or args.workers < 2 or args.blocks <= 0 or args.blocks % 3:
        parser.error(
            "requires at least four requests and two workers, and blocks in multiples of three"
        )
    if args.upstream == args.candidate:
        parser.error("provide separate exact upstream and candidate builds")
    run(args)


if __name__ == "__main__":
    main()
