"""Diagnostic same-binary G1 affine-batch screen on synthetic Privacy Rings requests."""

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
from pathlib import Path


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("fixtures", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700)
    manifest = args.fixtures / "fixtures.sha256"
    entries = [line.split() for line in manifest.read_text().splitlines()]
    if len(entries) != 28 or any(
        sha(args.fixtures / name) != digest for digest, name in entries
    ):
        raise ValueError("fixture manifest mismatch")
    clean_env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("BENCH_", "RAYON_"))
    }
    clean_env.update(
        BENCH_TIME="1",
        BENCH_PREPARED_SOLVER="1",
        BENCH_REQUEST_PROFILE="1",
        RAYON_NUM_THREADS="2",
    )
    rows = []
    for circuit in ("escrow", "withdrawal"):
        directories = sorted(
            path.parent
            for path in (args.fixtures / "requests" / circuit).glob("*/*/inputs.json")
        )
        if len(directories) != 4:
            raise ValueError("expected four distinct request fixtures")
        for block in range(3):
            arms = (128, 256, 512)
            arms = arms[block:] + arms[:block]
            for position, limit in enumerate(arms):
                tag = f"{circuit}-b{block + 1}-g1-{limit}"
                env = clean_env | {"BENCH_G1_BATCH": str(limit)}
                argv = [
                    args.binary,
                    "warm-requests",
                    args.fixtures / "reference" / circuit / "circuit.xbc",
                    args.fixtures / "reference" / circuit / "test-key.bin",
                    "cpu",
                    "1",
                    "4",
                    *directories,
                ]
                load_before = os.getloadavg()
                with (
                    (args.output / f"{tag}.stdout").open("x") as stdout,
                    (args.output / f"{tag}.stderr").open("x") as stderr,
                ):
                    process = subprocess.Popen(
                        argv, env=env, stdout=stdout, stderr=stderr
                    )
                    _, status, usage = os.wait4(process.pid, 0)
                    process.returncode = os.waitstatus_to_exitcode(status)
                if process.returncode:
                    raise RuntimeError(f"{tag} failed; inspect stderr")
                out = (args.output / f"{tag}.stdout").read_text()
                err = (args.output / f"{tag}.stderr").read_text()
                services = [
                    int(match.group(1))
                    for line in out.splitlines()
                    if (
                        match := re.fullmatch(
                            r"request verified index=\d+ fixture=\d+ service_ns=(\d+)",
                            line,
                        )
                    )
                ]
                phases = [
                    line
                    for line in err.splitlines()
                    if line.startswith("request phases index=")
                ]
                tasks = [
                    line
                    for line in err.splitlines()
                    if line.startswith("request task index=")
                ]
                if len(services) != 4 or len(phases) != 4 or len(tasks) != 36:
                    raise ValueError(f"{tag} missing proof or phase receipts")
                if (
                    err.count(f"bench G1 affine batch limit: {limit}") != 1
                    or "altered=rejected cross_request=rejected" not in out
                ):
                    raise ValueError(
                        f"{tag} missing configuration or rejection receipt"
                    )
                row = dict(
                    circuit=circuit,
                    block=block + 1,
                    limit=limit,
                    position=position + 1,
                    services_ns=services,
                    load_before=load_before,
                    load_after=os.getloadavg(),
                    peak_rss_bytes=usage.ru_maxrss
                    if sys.platform == "darwin"
                    else usage.ru_maxrss * 1024,
                )
                rows.append(row)
                print(
                    json.dumps(
                        {
                            key: value
                            for key, value in row.items()
                            if key != "services_ns"
                        }
                    ),
                    flush=True,
                )
    (args.output / "report.json").write_text(
        json.dumps(
            dict(
                source_binary_sha256=sha(args.binary),
                fixture_manifest_sha256=sha(manifest),
                platform=platform.platform(),
                workers=2,
                concurrency=1,
                requests_per_process=4,
                performance_eligible=False,
                runs=rows,
            ),
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
