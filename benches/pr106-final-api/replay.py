"""Matched replay of final PreparedCpuProver::prove and Xark 0.5 CPU requests.

Both binaries time request read through positive Xark self-check and canonical
serialization. Independent Xark/Arkworks checks run outside the timed interval.
A smoke run validates correctness only. A full run gates on same-binary drift.
"""

import argparse
import hashlib
import json
import math
import os
import platform
import re
import statistics
import subprocess
import sys
from pathlib import Path

UPSTREAM_PARENT = "03a7f519d28df6718f7ce6dda41f1e57e5ea55db"
UPSTREAM_HEAD = "d126d3cb2a306e7c53d9fc7638dc7860ce086b30"
PREPARED_PARENT = "98ef685895a9c594938ae6528e8e57bfaf637734"
UPSTREAM_MARKER = "upstream timed self-check and serialization: 1"
PREPARED_MARKER = "prepared final public API: 1"
RECEIPT = re.compile(r"request verified index=(\d+) fixture=(\d+) service_ns=(\d+)")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def p95(values):
    return sorted(values)[math.ceil(len(values) * .95) - 1]


def parse(lines, count, workers):
    tail = re.compile(rf"requests verified mode=cpu concurrency=1 threads={workers} count={count} setup_ns=(\d+) altered=rejected cross_request=rejected")
    samples = [tuple(map(int, match.groups())) for line in lines if (match := RECEIPT.fullmatch(line))]
    match = tail.fullmatch(lines[-1]) if lines else None
    if match is None or len(samples) != count:
        raise ValueError("missing complete verification receipts")
    if any(index != i or fixture != i % 4 or ns <= 0 for i, (index, fixture, ns) in enumerate(samples)):
        raise ValueError("invalid proof order or elapsed time")
    return int(match[1]), [ns for _, _, ns in samples]


def source_head(path, parent, is_upstream):
    def git(*args):
        return subprocess.check_output(["git", "-C", str(path), *args], text=True).strip()
    head = git("rev-parse", "HEAD")
    if git("merge-base", "HEAD", parent) != parent:
        raise ValueError(f"source {path} does not descend from required parent {parent}")
    if git("status", "--porcelain"):
        raise ValueError(f"source {path} must be clean")
    if is_upstream and head != UPSTREAM_HEAD:
        raise ValueError("upstream source must be the pinned benchmark-only wrapper")
    if not is_upstream:
        paths = git("diff", "--name-only", parent, "HEAD").splitlines()
        if any(not (name.startswith("benches/pr106-final-api/") or name == "crates/groth16/examples/bench_prepared_api.rs") for name in paths):
            raise ValueError("candidate source changes include non-benchmark code")
    return head


def host():
    affinity = sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None
    physical = []
    if affinity is not None:
        for cpu in affinity:
            topology = Path(f"/sys/devices/system/cpu/cpu{cpu}/topology")
            try:
                physical.append(((topology / "physical_package_id").read_text().strip(),
                                 (topology / "core_id").read_text().strip()))
            except OSError:
                physical = None
                break
    return {"platform": platform.platform(), "affinity": affinity, "physical_core_ids": physical,
            "load_1m": os.getloadavg()[0]}


def run(binary, arm, circuit, fixture_dirs, reference, count, workers, output, tag):
    stdout, stderr = output / f"{tag}.stdout", output / f"{tag}.stderr"
    env = {k: v for k, v in os.environ.items() if not k.startswith(("BENCH_", "RAYON_"))}
    env["RAYON_NUM_THREADS"] = str(workers)
    command = [str(binary), "warm-requests", str(reference / "circuit.xbc"),
               str(reference / "test-key.bin"), "cpu" if arm == "upstream" else "1",
               str(count), *map(str, fixture_dirs)]
    with stdout.open("x") as out, stderr.open("x") as err:
        proc = subprocess.Popen(command, stdout=out, stderr=err, env=env)
        _, status, usage = os.wait4(proc.pid, 0)
    if os.waitstatus_to_exitcode(status):
        raise RuntimeError(f"{tag} failed; inspect {stderr}")
    setup, services = parse(stdout.read_text().splitlines(), count, workers)
    marker = UPSTREAM_MARKER if arm == "upstream" else PREPARED_MARKER
    if stderr.read_text().splitlines().count(marker) != 1:
        raise ValueError(f"{tag} lacks exact boundary marker")
    return {"tag": tag, "circuit": circuit, "arm": arm, "setup_ns": setup,
            "services_ns": services, "p50_ns": statistics.median(services), "p95_ns": p95(services),
            "peak_rss_bytes": usage.ru_maxrss * (1 if sys.platform == "darwin" else 1024),
            "load_after": os.getloadavg()[0]}


def drift(a, b):
    return max(a / b, b / a) - 1


def control_failures(rows):
    failures = []
    for circuit in ("escrow", "withdrawal"):
        for arm in ("upstream", "prepared"):
            pair = [r for r in rows if r["circuit"] == circuit and r["arm"] == arm]
            if len(pair) != 2:
                failures.append(f"{circuit}/{arm}: missing control pair")
            elif drift(pair[0]["p50_ns"], pair[1]["p50_ns"]) > .02 or drift(pair[0]["p95_ns"], pair[1]["p95_ns"]) > .10:
                failures.append(f"{circuit}/{arm}: p50 or p95 drift exceeded 2% / 10%")
    return failures


def summarize(rows, eligible):
    result = {}
    for circuit in ("escrow", "withdrawal"):
        grouped = {}
        for arm in ("upstream", "prepared"):
            selected = [r for r in rows if r["circuit"] == circuit and r["arm"] == arm]
            services = [ns for row in selected for ns in row["services_ns"]]
            grouped[arm] = {"samples": len(services), "warm_p50_ns": statistics.median(services),
                            "warm_p95_ns": p95(services),
                            "preparation_ns_median": statistics.median(r["setup_ns"] for r in selected),
                            "peak_rss_bytes": max(r["peak_rss_bytes"] for r in selected)}
        saved = grouped["upstream"]["warm_p50_ns"] - grouped["prepared"]["warm_p50_ns"]
        extra_prep = grouped["prepared"]["preparation_ns_median"] - grouped["upstream"]["preparation_ns_median"]
        result[circuit] = {"arms": grouped, "p50_saved_ns": saved,
                           "extra_preparation_ns": extra_prep,
                           "break_even_requests": max(0, math.ceil(extra_prep / saved)) if eligible and saved > 0 else None}
    return result


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    for name in ("upstream", "prepared", "fixtures", "manifest", "output"):
        cli.add_argument(name, type=lambda s: Path(s).resolve())
    cli.add_argument("--upstream-source", required=True, type=lambda s: Path(s).resolve())
    cli.add_argument("--prepared-source", required=True, type=lambda s: Path(s).resolve())
    cli.add_argument("--workers", type=int, default=2)
    cli.add_argument("--count", type=int, default=25)
    cli.add_argument("--blocks", type=int, default=4)
    cli.add_argument("--smoke", action="store_true")
    args = cli.parse_args()
    if args.output.exists() or args.workers != 2 or args.count < 4 or args.blocks < 2 or args.blocks % 2:
        cli.error("new output path, two workers, at least four requests and even blocks >=2 required")
    if digest(args.upstream) == digest(args.prepared):
        cli.error("arms must use distinct binaries")
    pins = dict((name, checksum) for checksum, name in map(str.split, args.manifest.read_text().splitlines()))
    if len(pins) != 28 or any(digest(args.fixtures / name) != checksum for name, checksum in pins.items()):
        raise ValueError("fixture manifest does not match 28 pinned files")
    sources = {"upstream": source_head(args.upstream_source, UPSTREAM_PARENT, True),
               "prepared": source_head(args.prepared_source, PREPARED_PARENT, False)}
    fixture_dirs = {c: sorted({(args.fixtures / name).parent for name in pins if name.startswith(f"requests/{c}/")})
                    for c in ("escrow", "withdrawal")}
    if any(len(dirs) != 4 for dirs in fixture_dirs.values()):
        raise ValueError("expected four request fixtures per circuit")
    machine = host()
    topology_ok = sys.platform.startswith("linux") and machine["physical_core_ids"] is not None and len(machine["physical_core_ids"]) == args.workers and len(set(machine["physical_core_ids"])) == args.workers
    args.output.mkdir(mode=0o700)
    report = {"source_commits": sources,
              "binary_sha256": {arm: digest(getattr(args, arm)) for arm in ("upstream", "prepared")},
              "manifest_sha256": digest(args.manifest), "host": machine, "workers": args.workers,
              "topology_ok": topology_ok, "smoke": args.smoke, "performance_eligible": False,
              "controls": [], "control_failures": [], "measurements": []}
    def invoke(circuit, arm, phase, block, count):
        tag = f"{phase}-{circuit}-b{block}-{arm}"
        return run(getattr(args, arm), arm, circuit, fixture_dirs[circuit],
                   args.fixtures / "reference" / circuit, count, args.workers, args.output, tag)
    if not args.smoke:
        for circuit in fixture_dirs:
            for arm in ("upstream", "prepared"):
                for block in (1, 2):
                    report["controls"].append(invoke(circuit, arm, "control", block, 32))
        report["control_failures"] = control_failures(report["controls"])
        (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        if report["control_failures"] or not topology_ok:
            print(json.dumps({"performance_eligible": False,
                              "reason": "host control failed" if report["control_failures"] else "two physical Linux cores unavailable",
                              "control_failures": report["control_failures"]}))
            return 2
    for circuit in fixture_dirs:
        for block in ((1,) if args.smoke else range(1, args.blocks + 1)):
            for arm in (("upstream", "prepared") if block % 2 else ("prepared", "upstream")):
                report["measurements"].append(invoke(circuit, arm, "measure", block,
                                                     4 if args.smoke else args.count))
    report["performance_eligible"] = not args.smoke and topology_ok and not report["control_failures"] and args.count * args.blocks >= 100
    report["summary"] = summarize(report["measurements"], report["performance_eligible"])
    (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"performance_eligible": report["performance_eligible"],
                      "summary": report["summary"]}))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
