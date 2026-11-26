#!/usr/bin/env python3
"""Run paired, verified Privacy Rings benchmarks with pinned adapters."""

import argparse
import csv
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import signal
import shutil
import statistics
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
COMPETITORS = ("xark", "gnark", "rapidsnark", "constantine", "icicle")
QUERY = {
    "constantine": ("b1",),
    "icicle": ("b1", "b2"),
}
BENCH_ENV = {
    "BENCH_TIME",
    "BENCH_WARM_BACKEND",
    "BENCH_PUBLIC_STATEMENTS",
    "BENCH_CHECK_ROWS",
    "BENCH_MERGE_BELOW",
    "BENCH_RESIDENT_PROFILE",
    "NO_BATCH_AFFINE",
    "NO_GLV",
    "CHECK",
    "BENCH_ESCROW_STATEMENTS",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def capture(command):
    return subprocess.check_output(
        command, text=True, stderr=subprocess.DEVNULL, timeout=15
    ).strip()


def candidate_lanes(config):
    if "candidate" not in config:
        return []
    candidate = config["candidate"]
    require(isinstance(candidate, dict), "candidate must be an object")
    lanes = candidate.get("lanes", ["xark"])
    require(
        isinstance(lanes, list)
        and bool(lanes)
        and all(lane in ("xark", "gnark") for lane in lanes)
        and len(set(lanes)) == len(lanes),
        "candidate lanes must select xark, gnark, or both once",
    )
    if "gnark" in lanes:
        receipt = candidate.get("receipt")
        require(
            isinstance(receipt, str)
            and bool(receipt.strip())
            and len(receipt.splitlines()) == 1,
            "Gnark pairing requires a single-line Xark candidate receipt",
        )
    return lanes


def revisions(config, root, competitors):
    sources = config["sources"]
    needed = {"xark", "examples"}
    if set(competitors).intersection(candidate_lanes(config)):
        needed.add("xark_candidate")
    if (
        set(competitors) & {"gnark", "rapidsnark"}
        and "relation_exporter" in config["binaries"]
    ):
        needed.add("relation_exporter")
    needed.update(set(competitors) & {"rapidsnark", "constantine", "icicle"})
    require(needed <= sources.keys(), f"source pins required for {sorted(needed)}")
    result = {}
    for name in sorted(needed):
        entry = sources[name]
        checkout = (root / entry["path"]).resolve(strict=True)
        command = ["git", "-C", str(checkout)]
        actual = capture([*command, "rev-parse", "HEAD"])
        require(
            actual == entry["commit"] and re.fullmatch(r"[0-9a-f]{40}", actual),
            f"{name} checkout does not match the pinned commit",
        )
        require(
            not capture([*command, "status", "--porcelain", "--untracked-files=no"]),
            f"{name} checkout has modified tracked files",
        )
        result[name] = {"path": str(checkout), "commit": actual}
    return result


def fingerprint(paths):
    return {
        name: {"path": str(path), "sha256": digest(path)}
        for name, path in paths.items()
    }


def host():
    affinity = (
        sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None
    )
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.exists():
        cpu = re.search(r"^model name\s*:\s*(.+)$", cpuinfo.read_text(), re.M)
        cpu = cpu[1] if cpu else platform.machine()
    elif sys.platform == "darwin":
        try:
            cpu = capture(["sysctl", "-n", "machdep.cpu.brand_string"])
        except (OSError, subprocess.SubprocessError):
            cpu = None
    else:
        cpu = platform.processor()
    cpu_max = Path("/sys/fs/cgroup/cpu.max")
    return {
        "platform": platform.platform(),
        "cpu": cpu,
        "architecture": platform.machine(),
        "online_cpus": os.cpu_count(),
        "affinity": affinity,
        "cpu_max": cpu_max.read_text().strip() if cpu_max.exists() else None,
        "cpu_topology": topology(),
    }


def topology():
    try:
        if sys.platform == "darwin":
            return capture(["sysctl", "hw.physicalcpu", "hw.logicalcpu", "hw.memsize"])
        if sys.platform == "linux" and shutil.which("lscpu"):
            return capture(["lscpu", "-e=CPU,CORE,SOCKET,NODE,ONLINE"])
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def processes(group, threshold):
    observed = []
    for line in capture(["ps", "-axo", "pid=,pgid=,pcpu=,comm="]).splitlines():
        pid, pgid, percent, name = line.split(maxsplit=3)
        if (
            int(pid) != os.getpid()
            and int(pgid) != group
            and float(percent) >= threshold
        ):
            observed.append(
                {"pid": int(pid), "cpu_percent": float(percent), "command": name}
            )
    return observed


def execute(argv, env, out, label, timeout, threshold=None):
    log = out / f"{label}.log"
    observations = {}
    load_before = os.getloadavg()
    polls = 0
    observation_error = None
    peak_rss = None
    deadline = time.monotonic() + timeout
    with log.open("w") as stream:
        with subprocess.Popen(
            argv,
            cwd=out,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=stream,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        ) as process:
            try:
                while process.poll() is None:
                    if threshold is not None and sys.platform == "linux":
                        try:
                            status = Path(f"/proc/{process.pid}/status").read_text()
                        except OSError:
                            status = ""
                        rss = re.search(r"^VmHWM:\s+(\d+) kB$", status, re.M)
                        if rss:
                            peak_rss = max(peak_rss or 0, int(rss[1]))
                    if threshold is not None and observation_error is None:
                        try:
                            observed = processes(process.pid, threshold)
                            polls += 1
                        except (OSError, subprocess.SubprocessError) as exc:
                            observed = []
                            observation_error = str(exc)
                        for item in observed:
                            previous = observations.get(item["pid"])
                            if (
                                previous is None
                                or item["cpu_percent"] > previous["cpu_percent"]
                            ):
                                observations[item["pid"]] = item
                    remaining = deadline - time.monotonic()
                    require(remaining > 0, f"{label} timed out")
                    try:
                        process.wait(timeout=min(1, remaining))
                    except subprocess.TimeoutExpired:
                        continue
            except BaseException:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                raise
    return (
        process.returncode,
        log.read_text(),
        {
            "polls": polls,
            "observed": list(observations.values()),
            "error": observation_error,
            "sampled_peak_rss_kib": peak_rss,
            "load_average_before": load_before,
            "load_average_after": os.getloadavg(),
        },
    )


def proof_samples(log, backend, count, threads, row_checks):
    if backend == "gnark":
        marker = rf"^verified constraints=[1-9]\d* wires=[1-9]\d* threads={threads}$"
        rejection = "changed statement rejected by Gnark"
        matches = re.findall(r"^gnark_prove_ns=(\d+)$", log, re.M)
        times = [int(value) for value in matches]
    else:
        if backend == "rapidsnark":
            marker = rf"^verified {count} proofs with snarkjs$"
            rejection = "changed statement rejected by snarkjs"
            require(
                f"OpenMP thread limit: {threads}" in log.splitlines(),
                "Rapidsnark thread receipt missing",
            )
            require(
                f"OS CPU count reported to the process: {threads}" in log.splitlines(),
                "Rapidsnark process pool does not match the thread budget",
            )
        else:
            marker = rf"^resident includes row checks: {str(row_checks).lower()}$"
            rejection = (
                "changed statement rejected by Arkworks and Xark for each backend"
            )
        matches = re.findall(
            rf"^warm prove: {backend if backend != 'xark' else 'xark-groth16'} ([0-9]+\.[0-9]{{6}})s$",
            log,
            re.M,
        )
        times = [
            int(seconds) * 1_000_000_000 + int(micros) * 1000
            for seconds, micros in (value.split(".") for value in matches)
        ]
    require(
        re.search(marker, log, re.M) and rejection in log.splitlines(),
        f"{backend} missing verification or altered-statement receipt",
    )
    require(
        len(times) == count and all(value > 0 for value in times),
        f"{backend} invalid sample count or duration",
    )
    return {"proof": times}


def query_samples(log, backend, queries, count, threads):
    budget = "thread_cap" if backend == "icicle" else "threads"
    headers = re.findall(rf"^query msm {backend} verified: (.*)$", log, re.M)
    require(len(headers) == 1, f"{backend} needs one verified query receipt")
    fields = dict(field.split("=", 1) for field in headers[0].split())
    require(
        fields.get(budget) == str(threads) and fields.get("samples") == str(count),
        f"{backend} query sample or thread receipt mismatch",
    )
    require(int(fields["terms"]) > 0, f"{backend} query term receipt is invalid")
    if backend == "xark":
        require(
            fields.get("xark_glv") == "true"
            and fields.get("xark_batch_affine") == "true",
            "Xark query arithmetic configuration mismatch",
        )
    else:
        require(
            fields.get("bundle") == "XKQMSM01"
            and fields.get("reference") == "arkworks",
            f"{backend} missing the verified bundle and reference receipt",
        )
    if backend == "icicle":
        expected = {
            "backend": "CPU:0",
            "precompute_factor": "1",
            "batch_size": "1",
            "canonical_host": "1",
            "async": "0",
        }
        require(
            all(fields.get(key) == value for key, value in expected.items()),
            "ICICLE CPU timing configuration mismatch",
        )
    result = {}
    for query in queries:
        matches = re.findall(
            rf"^query msm {backend}: query={query} sample=(\d+) {backend}_ns=(\d+)$",
            log,
            re.M,
        )
        require(
            [int(index) for index, _ in matches] == list(range(1, count + 1)),
            f"{backend} {query} has missing or repeated indices",
        )
        times = [int(value) for _, value in matches]
        require(
            all(value > 0 for value in times),
            f"{backend} {query} has nonpositive times",
        )
        result[query] = times
    return result


def write_pair(output, rows, report):
    with (output / "samples.csv").open("w", newline="") as stream:
        fieldnames = [
            "workload",
            "lane",
            "pair",
            "order",
            "arm",
            "backend",
            "metric",
            "sample",
            "duration_ns",
        ]
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")


def summarize(times):
    ordered = sorted(times)
    return {
        "count": len(ordered),
        "p50_ns": statistics.median(ordered),
        "p95_ns": ordered[math.ceil(0.95 * len(ordered)) - 1]
        if len(ordered) >= 30
        else None,
        "p99_ns": ordered[math.ceil(0.99 * len(ordered)) - 1]
        if len(ordered) >= 100
        else None,
    }


def changed_oracle(vector, output, query):
    data = vector.read_bytes()
    require(len(data) >= 12 and data[:8] == b"XKQMSM01", "invalid query vector header")
    count = int.from_bytes(data[8:12], "little")
    end = 12 + count * 224
    require(count > 0 and len(data) == end + 192, "invalid query vector size")
    offset, size, oracle = (32, 64, end) if query == "b1" else (96, 128, end + 64)
    expected = data[oracle : oracle + size]
    alternate = next(
        (
            point
            for start in range(12 + offset, end, 224)
            if any(point := data[start : start + size]) and point != expected
        ),
        None,
    )
    require(
        alternate is not None, f"query fixture needs a distinct nonzero {query} point"
    )
    wrong = output / f"wrong-oracle-{query}.bin"
    wrong.write_bytes(data[:oracle] + alternate + data[oracle + size :])
    return wrong


WORKLOADS = ("escrow", "withdrawal")
FIXTURE_NAMES = (
    "circuit.xbc",
    "test-key.bin",
    "inputs.json",
    "public.json",
    "public-changed.json",
)
BINARY_NAMES = {
    "xark": ("bench",),
    "gnark": ("gnark",),
    "rapidsnark": ("rapidsnark_library", "node"),
    "constantine": ("constantine",),
    "icicle": (
        "icicle",
        "icicle_curve_bn254",
        "icicle_field_bn254",
        "icicle_hash",
        "icicle_device",
    ),
}
SOURCE_PINS = {
    "constantine": "4083170f19ec8dba15604bf0d443b5d852d634d6",
    "icicle": "6c77775961b0e4dc2be359feec1ac11536c18043",
    "rapidsnark": "81eddf1a536d26497b237c0b8a04fe90baf7e439",
}
SCOPES = {
    "xark": "checked-resident-proof",
    "gnark": "checked-resident-proof",
    "rapidsnark": "resident-proof-boundary-differs",
    "constantine": "resident-query-b1",
    "icicle": "resident-query-b1-b2",
}
VERIFY = {
    "xark": "Each proof checked with Arkworks and Xark",
    "gnark": "Each proof checked with Gnark",
    "rapidsnark": "Each proof checked with snarkjs",
    "constantine": "Each B1 result checked against Arkworks",
    "icicle": "Each B1 and B2 result checked against Arkworks",
}


def run_suite(args):
    config_path = args.config.resolve(strict=True)
    root = config_path.parent
    config = json.loads(config_path.read_text())
    require(config["version"] == 1, "unsupported config version")
    competitors = args.competitor or list(COMPETITORS)
    workloads = args.workload or list(WORKLOADS)
    require(len(set(competitors)) == len(competitors), "select each competitor once")
    require(len(set(workloads)) == len(workloads), "select each workload once")
    require(
        args.samples >= (1 if args.smoke else 30)
        and args.threads > 0
        and args.warmups > 0,
        "invalid run budget",
    )
    require(
        args.pairs >= 2 and args.pairs % 2 == 0,
        "use an even number of pairs (at least two)",
    )
    require(
        math.isfinite(args.timeout)
        and args.timeout > 0
        and 0 < args.contention_percent <= 100,
        "invalid timeout or CPU threshold",
    )
    require(
        "rapidsnark" not in competitors or os.cpu_count() == args.threads,
        "Rapidsnark needs a host/VM with online CPU count equal to the thread budget",
    )
    lanes = set(competitors).intersection(candidate_lanes(config))
    candidate = config["candidate"] if lanes else None
    require(
        not args.xark_query or "xark" in lanes,
        "Xark query comparison needs a candidate",
    )
    files = {
        "config": config_path,
        "harness": Path(__file__).resolve(),
        "python": Path(sys.executable).resolve(),
    }
    sources = revisions(config, root, competitors)
    for name, pin in SOURCE_PINS.items():
        if name in competitors:
            require(
                sources[name]["commit"] == pin,
                f"{name} requires adapter source pin {pin}",
            )
    for backend in {"xark", *competitors}:
        for name in BINARY_NAMES[backend]:
            files[name] = (root / config["binaries"][name]).resolve(strict=True)
            if name not in {"rapidsnark_library", *BINARY_NAMES["icicle"][1:]}:
                require(os.access(files[name], os.X_OK), f"{name} must be executable")
    gnark_independent = (
        "gnark" in competitors and "gnark_verifier" in config["binaries"]
    )
    if "gnark" in lanes or ("gnark" in competitors and not args.smoke):
        require(
            gnark_independent,
            "Gnark live and candidate comparisons require an independent verifier",
        )
    if gnark_independent:
        files["gnark_verifier"] = (root / config["binaries"]["gnark_verifier"]).resolve(
            strict=True
        )
        require(
            os.access(files["gnark_verifier"], os.X_OK),
            "gnark_verifier must be executable",
        )
    if "relation_exporter" in sources:
        files["relation_exporter"] = (
            root / config["binaries"]["relation_exporter"]
        ).resolve(strict=True)
        require(
            os.access(files["relation_exporter"], os.X_OK),
            "relation_exporter must be executable",
        )
    candidate_env = {}
    if candidate:
        candidate_env = candidate.get("environment", {})
        require(
            all(
                re.fullmatch(r"BENCH_[A-Z0-9_]+", key)
                and key not in BENCH_ENV
                and isinstance(value, str)
                for key, value in candidate_env.items()
            ),
            "invalid candidate environment override",
        )
        files["candidate"] = (root / candidate["binary"]).resolve(strict=True)
        require(
            os.access(files["candidate"], os.X_OK),
            "candidate binary must be executable",
        )
    for name, path in config.get("additional_artifacts", {}).items():
        require(f"extra:{name}" not in files, f"duplicate additional artifact: {name}")
        files[f"extra:{name}"] = (root / path).resolve(strict=True)
    fixture_root = (root / config["fixtures"]).resolve(strict=True)
    pinned = {
        path: sha
        for sha, path in (
            line.split(maxsplit=1)
            for line in (HERE / "fixtures.sha256").read_text().splitlines()
        )
    }
    for workload in workloads:
        for name in FIXTURE_NAMES:
            key = f"{workload}/{name}"
            path = fixture_root / key
            require(digest(path) == pinned[key], f"fixture digest mismatch: {key}")
            files[key] = path
        if "rapidsnark" in competitors:
            for name in ("zkey", "vk"):
                files[f"{workload}/{name}"] = (
                    root / config["rapidsnark_keys"][workload][name]
                ).resolve(strict=True)
            for name in ("rapidsnark_resident.py", "verify_rapidsnark_resident.cjs"):
                files[name] = HERE / name
    if "rapidsnark" in competitors:
        snarkjs = (root / config["binaries"]["snarkjs"]).resolve(strict=True)
        files["snarkjs_manifest"] = snarkjs / "package.json"
        files["snarkjs_verifier"] = snarkjs / "build/main.cjs"
    toolchains = config["toolchains"]
    require(
        isinstance(toolchains, dict) and bool(toolchains), "record the build toolchains"
    )
    initial_files = fingerprint(files)
    env = {
        name: value
        for name, value in os.environ.items()
        if name not in BENCH_ENV
        and name != "GNARK_PROOF_RECEIPT"
        and not name.startswith(("BENCH_", "RAYON_", "OMP_", "GOMAXPROCS"))
    }
    budget = str(args.threads)
    controlled = {
        "BENCH_TIME": "1",
        "BENCH_WARM_BACKEND": "cpu",
        "BENCH_MERGE_BELOW": "0",
        "RAYON_NUM_THREADS": budget,
        "GOMAXPROCS": budget,
        "OMP_NUM_THREADS": budget,
        "OMP_THREAD_LIMIT": budget,
        "OMP_DYNAMIC": "FALSE",
        "LC_ALL": "C",
    }
    env.update(controlled)
    if "icicle" in competitors:
        library_dirs = sorted(
            {str(files[name].parent) for name in BINARY_NAMES["icicle"][1:]}
        )
        require(
            len(library_dirs) == 1,
            "ICICLE shared library paths must be in one directory",
        )
        require(
            not env.get("LD_PRELOAD") and not env.get("DYLD_INSERT_LIBRARIES"),
            "remove library injection before benchmarking",
        )
        env["LD_LIBRARY_PATH"] = controlled["LD_LIBRARY_PATH"] = library_dirs[0]
        env["DYLD_LIBRARY_PATH"] = controlled["DYLD_LIBRARY_PATH"] = library_dirs[0]
    if "rapidsnark" in competitors:
        # The adapter explicitly resolves node from PATH.
        require(
            Path(shutil.which("node", path=env.get("PATH")) or "/missing").resolve()
            == files["node"],
            "the pinned node binary must be the node found on PATH",
        )
    hardware = host()
    affinity = hardware["affinity"]
    require(
        not affinity or len(affinity) >= args.threads,
        "thread budget exceeds CPU affinity",
    )
    if "gnark" in competitors and not args.smoke:
        require(
            sys.platform == "linux"
            and affinity
            and len(affinity) == args.threads
            and args.strict_contention,
            "live Gnark pairing requires Linux, exact CPU affinity and strict contention sampling",
        )
    if args.strict_contention:
        try:
            competing = processes(os.getpgrp(), args.contention_percent)
        except (OSError, subprocess.SubprocessError) as exc:
            raise ValueError(
                "host process monitoring unavailable; strict run did not start"
            ) from exc
        require(
            not competing,
            "host process preflight detected contention; strict run did not start",
        )
    output = args.output.resolve()
    output.mkdir(mode=0o700)
    report = {
        "version": 1,
        "mode": "smoke" if args.smoke else "live",
        "status": "verified",
        "runner_commit": capture(["git", "-C", str(HERE), "rev-parse", "HEAD"]),
        "workloads": workloads,
        "competitors": competitors,
        "sources": sources,
        "toolchains": toolchains,
        "artifacts": initial_files,
        "hardware": hardware,
        "budget": {
            "threads": args.threads,
            "samples": args.samples,
            "warmups": args.warmups,
            "pairs": args.pairs,
            "timeout_seconds": args.timeout,
            "environment": controlled,
        },
        "contention": {
            "process_cpu_percent_threshold": args.contention_percent,
            "strict": args.strict_contention,
        },
        "steps": [],
        "comparisons": [],
        "summary": [],
    }

    def invoke(argv, label, *, additions=None, measured=False, rejection=None):
        argv = list(map(str, argv))
        additions = additions or {}
        code, log, observation = execute(
            argv,
            env | additions,
            output,
            label,
            args.timeout,
            args.contention_percent if measured else None,
        )
        step = {
            "argv": argv,
            "environment": additions,
            "log": f"{label}.log",
            "log_sha256": digest(output / f"{label}.log"),
            "exit": code,
        }
        if measured:
            step["contention"] = observation
            require(
                not args.strict_contention
                or (
                    observation["polls"]
                    and not observation["observed"]
                    and not observation["error"]
                ),
                f"contention monitoring flagged {label}; see {output}",
            )
        if rejection:
            require(
                code > 0
                and rejection in log
                and not re.search(r"^query msm .*_ns=", log, re.M),
                f"{label} did not reject the wrong oracle before reporting samples",
            )
        else:
            require(
                code == 0, f"{label} failed (exit {code}); see {output / step['log']}"
            )
        report["steps"].append(step)
        return log

    rows = []
    summaries = {}
    parameters = tuple(map(str, (args.samples, args.warmups)))
    for workload in workloads:
        fixture = fixture_root / workload
        circuit, key, inputs, public, altered = (
            fixture / name for name in FIXTURE_NAMES
        )
        export = output / workload
        export.mkdir()
        bench = files["bench"]
        iden3 = export / "iden3"
        vector = export / "queries.bin"
        if set(competitors) & {"gnark", "rapidsnark"}:
            # The exporter creates the private directory and refuses existing paths.
            export_log = invoke(
                (
                    files.get("relation_exporter", bench),
                    "export-iden3",
                    circuit,
                    fixture,
                    iden3,
                ),
                f"{workload}-iden3",
            )
            require(
                "fixture witness matches public statement" in export_log.splitlines(),
                f"{workload} missing relation export statement check",
            )
            require(
                all(
                    (iden3 / name).is_file()
                    for name in ("circuit.r1cs", "witness.wtns")
                ),
                f"{workload} export did not produce both iden3 artifacts",
            )
        if set(competitors) & QUERY.keys():
            invoke(
                (bench, "query-msm-export", circuit, key, fixture, vector),
                f"{workload}-query-export",
            )
        r1cs, witness = iden3 / "circuit.r1cs", iden3 / "witness.wtns"
        derived = {
            str(path.relative_to(output)): path
            for path in (r1cs, witness, vector)
            if path.exists()
        }
        expected_derived = fingerprint(derived)
        report["artifacts"].update(expected_derived)
        for competitor in competitors:
            lane = SCOPES[competitor]
            queries = QUERY.get(competitor)
            candidate_active = competitor == "xark" and "xark" in lanes
            gnark_candidate = competitor == "gnark" and "gnark" in lanes
            xark_reference = "xark-candidate" if gnark_candidate else "xark"
            if candidate_active and args.xark_query:
                lane = "resident-query-" + args.xark_query
                queries = (args.xark_query,)
            control = {"BENCH_PUBLIC_STATEMENTS": str(fixture)}
            if competitor != "rapidsnark":
                control["BENCH_CHECK_ROWS"] = "1"
            command = (
                files["candidate"] if gnark_candidate else bench,
                "warm",
                circuit,
                key,
                inputs,
                *parameters,
            )
            adapter = None
            if queries:
                control = {}
                command = (bench, "query-msm-xark", circuit, key, fixture, *parameters)
                adapter = (
                    None
                    if candidate_active
                    else (files[competitor], vector, budget, *parameters)
                )
                for query in () if candidate_active else queries:
                    wrong = changed_oracle(vector, export, query)
                    invoke(
                        (files[competitor], wrong, budget, "1", "0"),
                        f"{workload}-{competitor}-wrong-{query}",
                        rejection=f"{query} disagrees with the Arkworks result",
                    )
            elif competitor == "gnark":
                adapter = (
                    files["gnark"],
                    r1cs,
                    witness,
                    public,
                    altered,
                    budget,
                    *parameters,
                )
            elif competitor == "rapidsnark":
                adapter = (
                    sys.executable,
                    HERE / "rapidsnark_resident.py",
                    "--library",
                    files["rapidsnark_library"],
                    "--r1cs",
                    r1cs,
                    "--wtns",
                    witness,
                    "--zkey",
                    files[f"{workload}/zkey"],
                    "--vk",
                    files[f"{workload}/vk"],
                    "--fixture",
                    fixture,
                    "--snarkjs",
                    snarkjs,
                    "--threads",
                    budget,
                    "--samples",
                    parameters[0],
                    "--warmups",
                    parameters[1],
                )
            if candidate_active:
                adapter = (files["candidate"], *command[1:])
            paired_backend = "xark-candidate" if candidate_active else competitor
            for index in range(args.pairs):
                arms = [
                    (
                        xark_reference,
                        command,
                        control | candidate_env if gnark_candidate else control,
                    )
                ]
                if adapter:
                    arms.append(
                        (
                            paired_backend,
                            adapter,
                            control | candidate_env if candidate_active else {},
                        )
                    )
                    if index % 2:
                        arms.reverse()
                medians = {}
                arm_statistics = {}
                gnark_receipt = None
                for order, (backend, argv, additions) in enumerate(arms, 1):
                    label = f"{workload}-{competitor}-{index + 1}-{backend}"
                    if gnark_independent and backend == "gnark":
                        gnark_receipt = output / f"{label}-public-proofs.json"
                        additions = additions | {
                            "GNARK_PROOF_RECEIPT": str(gnark_receipt)
                        }
                    log = invoke(argv, label, additions=additions, measured=True)
                    parser_backend = "xark" if backend == "xark-candidate" else backend
                    if backend == "xark-candidate" and candidate.get("receipt"):
                        require(
                            candidate["receipt"] in log.splitlines(),
                            f"{label} missing candidate receipt",
                        )
                    if (
                        gnark_independent
                        and competitor == "gnark"
                        and backend == xark_reference
                    ):
                        require(
                            f"warm proofs verified by Arkworks and Xark: xark-groth16 warmups={args.warmups} measured={args.samples}"
                            in log.splitlines(),
                            f"{label} missing complete Xark proof verification receipt",
                        )
                    if queries:
                        timings = query_samples(
                            log, parser_backend, queries, args.samples, args.threads
                        )
                        if parser_backend != "xark":
                            require(
                                f"{backend}_commit={sources[backend]['commit']}" in log,
                                f"{label} binary reports a different upstream revision",
                            )
                    else:
                        timings = proof_samples(
                            log,
                            parser_backend,
                            args.samples,
                            args.threads,
                            competitor != "rapidsnark",
                        )
                        if parser_backend == "xark":
                            require(
                                re.search(
                                    r"^resident CPU: .* merge_below=0 merged=false$",
                                    log,
                                    re.M,
                                ),
                                "Xark split resident CPU receipt missing",
                            )
                            if competitor != "rapidsnark":
                                require(
                                    "witness row checker: compiled" in log.splitlines(),
                                    "Xark compiled row-check receipt missing",
                                )
                    report["steps"][-1]["verification"] = (
                        "Each query result checked against Arkworks"
                        if queries
                        else VERIFY[parser_backend]
                    )
                    medians[backend] = {}
                    arm_statistics[backend] = {
                        metric: summarize(times) for metric, times in timings.items()
                    }
                    for metric, times in timings.items():
                        medians[backend][metric] = statistics.median(times)
                        summaries.setdefault(
                            (workload, competitor, lane, backend, metric), []
                        ).extend(times)
                        rows.extend(
                            dict(
                                workload=workload,
                                lane=lane,
                                pair=index + 1,
                                order=order,
                                arm=competitor,
                                backend=backend,
                                metric=metric,
                                sample=sample,
                                duration_ns=duration,
                            )
                            for sample, duration in enumerate(times, 1)
                        )
                if gnark_receipt is not None:
                    expected = args.samples + args.warmups
                    require(
                        gnark_receipt.is_file(),
                        "Gnark adapter did not emit its public proof receipt",
                    )
                    receipt_hash = digest(gnark_receipt)
                    verification = invoke(
                        (
                            files["gnark_verifier"],
                            gnark_receipt,
                            public,
                            altered,
                            expected,
                        ),
                        f"{workload}-gnark-{index + 1}-arkworks",
                    )
                    marker = f"Arkworks verified {expected} Gnark proofs and rejected every altered statement"
                    require(
                        verification.splitlines().count(marker) == 1,
                        "missing independent Gnark proof check",
                    )
                    require(
                        digest(gnark_receipt) == receipt_hash,
                        "Gnark receipt changed during independent verification",
                    )
                    report["artifacts"][gnark_receipt.name] = {
                        "sha256": receipt_hash,
                        "path": str(gnark_receipt),
                    }
                ratios = None
                if adapter and competitor != "rapidsnark":
                    ratios = {
                        metric: medians[paired_backend][metric] / value
                        for metric, value in medians[xark_reference].items()
                    }
                report["comparisons"].append(
                    {
                        "workload": workload,
                        "competitor": competitor,
                        "lane": lane,
                        "pair": index + 1,
                        "order": [backend for backend, _, _ in arms],
                        "median_ns": medians,
                        "arm_statistics": arm_statistics,
                        "competitor_over_xark": ratios,
                        "xark_reference": xark_reference,
                    }
                )
        require(
            fingerprint(derived) == expected_derived,
            f"{workload} export changed during benchmarking",
        )
    require(
        fingerprint(files) == initial_files
        and revisions(config, root, competitors) == sources,
        "a pinned input, binary, or checkout changed during benchmarking",
    )
    for (workload, competitor, lane, backend, metric), times in summaries.items():
        report["summary"].append(
            dict(
                workload=workload,
                competitor=competitor,
                lane=lane,
                backend=backend,
                metric=metric,
                **summarize(times),
            )
        )
    report["contention"]["flagged_steps"] = [
        step["log"]
        for step in report["steps"]
        if "contention" in step
        and (
            not step["contention"]["polls"]
            or step["contention"]["observed"]
            or step["contention"]["error"]
        )
    ]
    report["performance_eligible"] = (
        not args.smoke and not report["contention"]["flagged_steps"]
    )
    write_pair(output, rows, report)
    print(f"Verified {len(rows)} samples; see {output / 'report.json'}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument(
        "--output", type=Path, required=True, help="new output directory"
    )
    parser.add_argument(
        "--competitor",
        choices=COMPETITORS,
        action="append",
        help="repeat to select lanes",
    )
    parser.add_argument(
        "--workload",
        choices=WORKLOADS,
        action="append",
        help="repeat to select fixtures",
    )
    parser.add_argument(
        "--xark-query", choices=("b1", "b2"), help="pair two Xark builds on one query"
    )
    parser.add_argument(
        "--smoke", action="store_true", help="permit fewer than 30 samples"
    )
    parser.add_argument("--threads", type=int, default=2)
    parser.add_argument("--samples", type=int, default=30)
    parser.add_argument("--warmups", type=int, default=3)
    parser.add_argument("--pairs", type=int, default=4)
    parser.add_argument(
        "--timeout", type=float, default=300, help="seconds per process"
    )
    parser.add_argument(
        "--contention-percent",
        type=float,
        default=35,
        help="flag external processes above this CPU percent",
    )
    parser.add_argument(
        "--strict-contention",
        action="store_true",
        help="fail without a verified report if contention is flagged",
    )
    args = parser.parse_args()
    try:
        run_suite(args)
    except (OSError, KeyError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f"benchmark failed: {error}\n")


if __name__ == "__main__":
    main()
