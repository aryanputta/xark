"""Run verified, distinct Privacy Rings requests on one resident key per process."""

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

WAVE = re.compile(r"request wave first=(\d+) count=(\d+) active_ns=(\d+)")
REQUEST = re.compile(r"request verified index=(\d+) fixture=(\d+) service_ns=(\d+)")
DONE = re.compile(
    r"requests verified mode=(cpu|gls) concurrency=(\d+) threads=(\d+) count=(\d+) "
    r"setup_ns=(\d+) altered=rejected cross_request=rejected"
)


def parse(contents, mode, concurrency, workers, count):
    rows = iter(contents.splitlines())
    waves = []
    services = []
    for first in range(0, count, concurrency):
        hits = WAVE.fullmatch(next(rows))
        if hits is None:
            raise ValueError("missing wave timing")
        idx, n, wall = map(int, hits.groups())
        if (idx, n) != (first, min(concurrency, count - first)) or wall <= 0:
            raise ValueError("inconsistent wave coverage")
        wave = []
        for index in range(first, first + n):
            record = REQUEST.fullmatch(next(rows))
            if record is None:
                raise ValueError("missing request verification")
            i, fixture, ns = map(int, record.groups())
            if (i, fixture) != (index, index % 4) or not 0 < ns <= wall:
                raise ValueError("inconsistent request receipt")
            wave.append(ns)
        waves.append(dict(wall_ns=wall, overlap=sum(wave) > wall))
        services.extend(wave)
    done = DONE.fullmatch(next(rows))
    if done is None or done.groups()[:4] != tuple(
        map(str, (mode, concurrency, workers, count))
    ):
        raise ValueError("wrong final verification receipt")
    if next(rows, None) is not None:
        raise ValueError("unexpected output after final receipt")
    setup = int(done[5])
    throughput = count * 1e9 / sum(row["wall_ns"] for row in waves)
    return dict(
        setup_ns=setup,
        waves=waves,
        services_ns=services,
        active_proofs_per_second=throughput,
        service_median_ns=statistics.median(services),
        overlapped_waves=sum(row["overlap"] for row in waves),
    )


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(binary, package, pinned, output):
    output.mkdir(mode=0o700)
    manifest = dict(
        (name, expected)
        for expected, name in map(str.split, pinned.read_text().splitlines())
    )
    if len(manifest) != 28:
        raise ValueError("wrong fixture manifest size")
    for name, expected in manifest.items():
        if digest(package / name) != expected:
            raise ValueError(f"fixture checksum mismatch: {name}")
    env = {
        name: value
        for name, value in os.environ.items()
        if not name.startswith(("BENCH_", "RAYON_"))
    }
    count, workers = 4, 2
    env.update(BENCH_TIME="1", RAYON_NUM_THREADS=str(workers))
    output_rows = []
    for fixture in ("escrow", "withdrawal"):
        prefix = package / "reference" / fixture
        dirs = sorted(
            {
                (package / name).parent
                for name in manifest
                if name.startswith(f"requests/{fixture}/")
            }
        )
        if len(dirs) != 4:
            raise ValueError("expected four pinned requests")
        base = [
            binary,
            "warm-requests",
            prefix / "circuit.xbc",
            prefix / "test-key.bin",
        ]
        invalid = subprocess.run(
            [*base, "gls", "2", str(count), dirs[0], dirs[0]],
            env=env,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if (
            invalid.returncode == 0
            or invalid.stdout
            or "fixture public statements must be distinct" not in invalid.stderr
        ):
            raise ValueError(
                "duplicate fixture preflight was not rejected before proving"
            )
        (output / f"{fixture}-duplicate.stderr").write_text(invalid.stderr)
        for concurrency in (1, 2, 4):
            modes = ("gls", "cpu") if concurrency == 2 else ("cpu", "gls")
            for mode in modes:
                load_start = os.getloadavg()
                start = time.monotonic_ns()
                log = output / f"{fixture}-{mode}-{concurrency}.stdout"
                with log.open("x") as out, log.with_suffix(".stderr").open("x") as err:
                    process = subprocess.Popen(
                        [*base, mode, str(concurrency), str(count), *dirs],
                        stdout=out,
                        stderr=err,
                        env=env,
                    )
                    _, status, usage = os.wait4(process.pid, 0)
                    process.returncode = os.waitstatus_to_exitcode(status)
                    if process.returncode:
                        raise RuntimeError(
                            f"{log.name} exited with {process.returncode}"
                        )
                total_ns = time.monotonic_ns() - start
                rss = (
                    usage.ru_maxrss
                    if sys.platform == "darwin"
                    else 1024 * usage.ru_maxrss
                )
                row = dict(
                    fixture=fixture,
                    mode=mode,
                    concurrency=concurrency,
                    process_wall_ns=total_ns,
                    peak_rss_bytes=rss,
                    load_before=load_start,
                    load_after=os.getloadavg(),
                    **parse(log.read_text(), mode, concurrency, workers, count),
                )
                output_rows.append(row)
                print(json.dumps(row), flush=True)
    report = dict(
        machine=platform.platform(),
        performance_eligible=False,
        workers=workers,
        binary_sha256=digest(binary),
        fixtures_manifest_sha256=digest(pinned),
        runs=output_rows,
    )
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    run(*(Path(arg).resolve() for arg in sys.argv[1:]))
