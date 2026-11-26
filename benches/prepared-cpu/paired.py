"""Paired serial Privacy Rings replay with matched in-request verification.

Run a same-binary control before comparing the prepared and upstream binaries.
This records measurements; it does not classify host stability as passing.
"""

import argparse
import hashlib
import json
import os
import platform
import re
import statistics
import subprocess
import sys
from pathlib import Path


UPSTREAM_MARKER = "upstream timed self-check and serialization: 1"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse(lines: list[str], arm: str, count: int) -> tuple[int, list[int]]:
    if not lines:
        raise ValueError("empty proof receipt")
    if arm == "upstream":
        pattern = re.compile(r"request verified index=(\d+) fixture=(\d+) service_ns=(\d+)")
        tail = re.fullmatch(
            rf"requests verified mode=cpu concurrency=1 threads=2 count={count} setup_ns=(\d+) altered=rejected cross_request=rejected",
            lines[-1],
        )
    elif arm == "prepared":
        pattern = re.compile(r"sample proof=(\d+) fixture=(\d+) request_ns=(\d+) verified=true")
        tail = re.fullmatch(
            rf"typed requests mode=prepared measured={count} warmups=1 setup_ns=(\d+) altered=rejected cross_request=rejected",
            lines[-1],
        )
    else:
        raise ValueError(f"unknown arm {arm}")
    samples = [tuple(map(int, match.groups())) for line in lines if (match := pattern.fullmatch(line))]
    if tail is None or len(samples) != count:
        raise ValueError("incomplete proof receipt")
    if any(index != i or fixture != i % 4 or ns <= 0 for i, (index, fixture, ns) in enumerate(samples)):
        raise ValueError("invalid request order or timing")
    return int(tail[1]), [ns for _, _, ns in samples]


def main() -> None:
    cli = argparse.ArgumentParser(description=__doc__)
    for name in ("upstream", "prepared", "fixtures", "manifest", "output"):
        cli.add_argument(name, type=lambda value: Path(value).resolve())
    cli.add_argument("--control", action="store_true", help="run the upstream binary in both arms")
    cli.add_argument("--blocks", type=int, default=4)
    cli.add_argument("--count", type=int, default=8)
    args = cli.parse_args()
    if args.blocks < 2 or args.count < 4 or args.count % 4:
        cli.error("require at least two blocks and a positive multiple of four requests")
    pins = dict((name, checksum) for checksum, name in map(str.split, args.manifest.read_text().splitlines()))
    if len(pins) != 28 or any(digest(args.fixtures / name) != checksum for name, checksum in pins.items()):
        raise ValueError("fixture manifest does not match 28 pinned files")
    args.output.mkdir(mode=0o700)
    env = {key: value for key, value in os.environ.items() if not key.startswith(("BENCH_", "RAYON_"))}
    env["RAYON_NUM_THREADS"] = "2"
    rows = []
    for fixture in ("escrow", "withdrawal"):
        artifact = args.fixtures / "reference" / fixture
        requests = sorted({(args.fixtures / name).parent for name in pins if name.startswith(f"requests/{fixture}/")})
        if len(requests) != 4:
            raise ValueError("expected four varied requests")
        for block in range(1, args.blocks + 1):
            arms = ("upstream", "prepared") if block % 2 else ("prepared", "upstream")
            for position, arm in enumerate(arms, 1):
                tag = f"{fixture}-b{block}-{arm}"
                actual = "upstream" if args.control else arm
                if actual == "upstream":
                    argv = [args.upstream, "warm-requests", artifact / "circuit.xbc", artifact / "test-key.bin", "cpu", "1", str(args.count), *requests]
                    binary = args.upstream
                else:
                    argv = [args.prepared, "prepared", artifact, artifact / "test-key.bin", str(args.count), "0", *requests]
                    binary = args.prepared
                stdout, stderr = args.output / f"{tag}.stdout", args.output / f"{tag}.stderr"
                before = os.getloadavg()
                with stdout.open("x") as out, stderr.open("x") as err:
                    proc = subprocess.Popen(argv, stdout=out, stderr=err, env=env)
                    _, status, usage = os.wait4(proc.pid, 0)
                    if os.waitstatus_to_exitcode(status):
                        raise RuntimeError(f"{tag} exited nonzero; see {stderr}")
                setup, request_ns = parse(stdout.read_text().splitlines(), actual, args.count)
                if actual == "upstream" and stderr.read_text().splitlines().count(UPSTREAM_MARKER) != 1:
                    raise ValueError("matched upstream binary receipt missing")
                rows.append({
                    "fixture": fixture, "block": block, "position": position, "arm": arm,
                    "setup_ns": setup, "request_ns": request_ns,
                    "p50_ns": statistics.median(request_ns), "load_before": before,
                    "load_after": os.getloadavg(),
                    "peak_rss_bytes": usage.ru_maxrss * (1 if sys.platform == "darwin" else 1024),
                    "binary_sha256": digest(binary),
                })
                print(f"{tag} p50_ms={statistics.median(request_ns) / 1e6:.2f}", flush=True)
    report = {
        "source_upstream": "a12b9a9", "source_prepared": None if args.control else "d6bb5ce8a39384d5ed881f046b654cf20c30e866",
        "fixture_manifest_sha256": digest(args.manifest),
        "platform": platform.platform(), "performance_eligible": False, "same_binary_control": args.control,
        "workers": 2, "measured_per_arm_per_circuit": args.blocks * args.count, "rows": rows,
    }
    (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
