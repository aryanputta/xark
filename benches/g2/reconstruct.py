#!/usr/bin/env python3
"""Reconstruct numeric G2 benchmark evidence without extracting private fixtures."""

import argparse
from collections import defaultdict
import csv
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import re
import statistics
import tarfile

# These are the downloaded Colab receipts, not interchangeable with new runs.
ARCHIVES = {
    "gnark-query": (
        "aaa-xark-gnark-query-msm",
        "55a3c22b0e1db6611cf9ceb9b1a381869281283bcf44c1c2b191dd2b3f0f8cfb",
    ),
    "gnark-proof": (
        "aaa-xark-x86-versus-gnark",
        "00266bea7ead72636e721f4f6bbfd47d0a4dd023b6af2443aa45e744721dbba4",
    ),
    "fq2-proof": (
        "aaa-xark-g2-fq2-proofs",
        "e1c9c8d87a540b75f7a78b76cfccf9202458d252629d4af9ad21d9f0e82fe8b6",
    ),
    "fq2-query": (
        "aaa-xark-g2-fq2",
        "2d296111578da2f9fddd7efcc19f84e3e4c51f734d2db431577919ee8f7b5c20",
    ),
    "window": (
        "aaa-xark-g2-window",
        "6940a89b631c7302b9ac9b43156c718f7739c2ad340e71ad8e483061f4e44b9d",
    ),
    "constantine": (
        "aaa-xark-constantine-fixed",
        "0dd952f206109a34c62b19519b1db20865458b40dc08a47dc4c7931010f9e670",
    ),
    "linux-perf": (
        "aaa-xark-linux-withdrawal-profile",
        "5ac3634fe6b42aa0208af861f7676134723683f1f2ea553a46a39d79a0a29295",
    ),
    "task-profile": (
        "xark-resident-task-profile",
        "cdace3a7b85d9f2eb7b53048f071049b12d7c8dd8d191bd380605e71648e154b",
    ),
    "affine": (
        "xark-affine-paired",
        "dc6769608e2cb367b9bc8255590f4c5cb702c581a5969d13aac4d0c6b36f17cf",
    ),
    "merge": (
        "aaa-xark-targeted-merge",
        "c1f0b176d9e91a71b6d58f410cec31341a469db16fbd674a44d22f819b036077",
    ),
    "fixtures": (
        "aaa-xark-offline-fixtures",
        "82caa7cee2b155afc2bd32cdc9661ba8cfb758888f4837bf9d6af31eb05c36a7",
    ),
}
QUERY = re.compile(r"^query msm (\w+): query=(b[12]) sample=(\d+) \w+_ns=(\d+)$")
TASK = re.compile(r"^resident task: (\d+) (\w+) (\d+) (\d+)$")
PROOF = re.compile(r"^warm prove: (\S+) (\d+)\.(\d{6})s$")
GNARK = re.compile(r"^gnark_prove_ns=(\d+)$")
RSS = re.compile(r"^sampled_high_water_rss_kib=(\d+)$")
MAX_PARSE_BYTES = 4 * 1024 * 1024
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
PROVENANCE = {
    "host.log",
    "binary.sha256",
    "commands.log",
    "status.log",
    "initial-processes.log",
}
ASSESSMENT = {
    "gnark-query": "verified; withdrawal B2 repeats, escrow B2 reverses with order",
    "gnark-proof": "verified paired checked resident proof baseline",
    "fq2-proof": "verified; Karatsuba slows all four full-proof medians",
    "fq2-query": "verified result parity; timing outcome varies with order",
    "window": "verified result parity; width changes miss repeatability gate",
    "constantine": "verified B1 only; no G2 result",
    "linux-perf": "verified saved raw inputs; initial wrapper marker check failed",
    "task-profile": "verified instrumented runs; task durations may overlap",
    "affine": "verified; disabling batch affine regresses full-proof median",
    "merge": "verified; order-sensitive escrow and higher RSS",
    "fixtures": "verified input fingerprints; no timing",
}


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def members(path):
    with tarfile.open(path, mode="r:gz") as archive:
        seen = set()
        size = 0
        for member in archive:
            name = PurePosixPath(member.name)
            if name.is_absolute() or ".." in name.parts or "\\" in member.name:
                raise ValueError(f"unsafe archive path {member.name!r}")
            if member.isdir():
                continue
            size += member.size
            if not member.isfile() or member.size < 0 or size > MAX_ARCHIVE_BYTES:
                raise ValueError(f"unsupported archive member {member.name!r}")
            if name in seen or len(seen) >= 256:
                raise ValueError(f"duplicate or excess archive member {member.name!r}")
            seen.add(name)
            with archive.extractfile(member) as file:
                if member.size <= MAX_PARSE_BYTES and (
                    name.suffix in {".log", ".rss"} or name.name in PROVENANCE
                ):
                    data = file.read()
                    yield str(name), hashlib.sha256(data).hexdigest(), data
                else:
                    yield str(name), hashlib.file_digest(
                        file, "sha256"
                    ).hexdigest(), None


def parse(run, name, log):
    filename = PurePosixPath(name).name
    workload = next(
        (w for w in ("escrow", "withdrawal") if filename.startswith(w + "-")), ""
    )
    if run == "linux-perf" and filename in ("query.log", "resident.log"):
        workload = "withdrawal"
    if not workload:
        return []
    rows = []

    def add(backend, metric, sample, duration, start=None):
        rows.append(
            dict(
                run=run,
                member=name,
                workload=workload,
                backend=backend,
                metric=metric,
                sample=sample,
                duration=duration,
                unit="KiB" if metric == "rss" else "ns",
                start_ns=start,
            )
        )

    proof_number = 0
    for line in log.splitlines():
        if matched := QUERY.fullmatch(line):
            backend, query, sample, duration = matched.groups()
            add(backend, query, int(sample), int(duration))
        elif matched := PROOF.fullmatch(line):
            backend, seconds, fraction = matched.groups()
            proof_number += 1
            add(
                backend,
                "proof",
                proof_number,
                int(seconds) * 10**9 + int(fraction) * 1000,
            )
        elif matched := GNARK.fullmatch(line):
            proof_number += 1
            add("gnark", "proof", proof_number, int(matched[1]))
        elif matched := TASK.fullmatch(line):
            sample, task, start, elapsed = matched.groups()
            add("xark-groth16", task, int(sample), int(elapsed), int(start))
        elif matched := RSS.fullmatch(line):
            add("xark-groth16", "rss", 1, int(matched[1]))

    if any(row["metric"] in {"b1", "b2"} for row in rows) and not re.search(
        r"^query msm \w+ verified:", log, re.M
    ):
        raise ValueError(f"missing query parity receipt in {name}")
    if (
        any(row["metric"] == "proof" for row in rows)
        and "changed statement rejected" not in log.lower()
    ):
        raise ValueError(f"missing altered-statement receipt in {name}")
    return rows


def reconstruct(downloads, output):
    rows = []
    inputs = []
    tasks = defaultdict(list)
    for run, (stem, expected) in ARCHIVES.items():
        path = downloads / f"{stem}.tar.gz"
        if sha256(path) != expected:
            raise ValueError(f"archive digest differs for {path.name}")
        receipts = {}
        provenance = {}
        for name, fingerprint, data in members(path):
            receipts[name] = fingerprint
            if run != "fixtures" and data is not None:
                receipt = data.decode("utf-8", errors="replace")
                rows.extend(parse(run, name, receipt))
                if name in PROVENANCE and len(data) <= 16 * 1024:
                    provenance[name] = receipt.splitlines()
        inputs.append(
            dict(
                run=run,
                file=path.name,
                sha256=expected,
                members=receipts,
                assessment=ASSESSMENT[run],
                provenance=provenance,
            )
        )

    cohorts = defaultdict(list)
    for row in rows:
        cohorts[row["run"], row["member"], row["metric"]].append(row["duration"])
        if row["start_ns"] is not None:
            tasks[row["member"], row["sample"]].append(row)
    summary = []
    for (run, member, metric), durations in sorted(cohorts.items()):
        sorted_times = sorted(durations)
        if min(sorted_times) < 0 or (metric != "rss" and max(sorted_times) == 0):
            raise ValueError(f"invalid durations in {member}")
        summary.append(
            dict(
                run=run,
                member=member,
                metric=metric,
                n=len(durations),
                p50=statistics.median(durations),
                p95=sorted_times[math.ceil(0.95 * len(durations)) - 1]
                if len(durations) >= 30
                else None,
            )
        )
    finishes = defaultdict(lambda: defaultdict(int))
    for (member, _), items in tasks.items():
        top_level = [
            row
            for row in items
            if row["metric"].startswith("msm_") or row["metric"] == "quotient"
        ]
        last = max(top_level, key=lambda row: row["start_ns"] + row["duration"])
        finishes[member][last["metric"]] += 1

    output.mkdir(mode=0o700)
    with (output / "samples.csv").open("w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    (output / "reconstructed.json").write_text(
        json.dumps(
            {
                "archives": inputs,
                "summary": summary,
                "last_profiled_top_level_task": finishes,
                "interpretation": "These are archived observations with differing timing scopes. See the decision log before comparing them.",
            },
            indent=2,
        )
        + "\n"
    )
    print(
        f"{len(inputs)} pinned archives, {len(rows)} numeric records, {len(cohorts)} cohorts"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("downloads", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        reconstruct(args.downloads, args.output)
    except (OSError, ValueError, tarfile.TarError) as error:
        parser.exit(1, f"reconstruction: {error}\n")


if __name__ == "__main__":
    main()
