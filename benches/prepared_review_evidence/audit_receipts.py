"""Recompute the published prepared-prover receipt from raw proof logs."""

import hashlib
import json
import math
import statistics
import tarfile
from pathlib import Path

from batch_parser import parse


ROOT = Path(__file__).resolve().parent


def require(condition, message):
    if not condition:
        raise ValueError(message)


def p95(values):
    values = sorted(values)
    return values[math.ceil(0.95 * len(values)) - 1]


def check_fixture_archive():
    archive = ROOT / "fixtures-synthetic.tar.gz"
    with tarfile.open(archive, "r:gz") as tar:
        members = tar.getmembers()
        require(all(
            (member.isfile() or member.isdir())
            and not Path(member.name).is_absolute()
            and ".." not in Path(member.name).parts
            for member in members
        ), "unsafe fixture archive member")
        pins = tar.extractfile("fixtures.sha256").read().decode().splitlines()
        require(len(pins) == 28, "fixture pin count")
        for line in pins:
            expected, name = line.split(maxsplit=1)
            data = tar.extractfile(name).read()
            require(hashlib.sha256(data).hexdigest() == expected, f"fixture hash: {name}")
    return hashlib.sha256(archive.read_bytes()).hexdigest()


def check_run(directory, expected_source, expected_controls, expected_measured):
    report = json.loads((directory / "report.json").read_text())
    require(report["source_commit"] == expected_source, "source commit")
    require(sum(row["count"] for row in report["control"]) == expected_controls, "control count")
    require(sum(row["count"] for row in report["measurements"]) == expected_measured, "measurement count")
    for row in report["control"] + report["measurements"]:
        tag = f"{row['phase']}-{row['circuit']}-b{row['block']}-{row['arm']}"
        receipt = directory / f"{tag}.stdout"
        parsed = parse(receipt.read_text(), "cpu", report["concurrency"], report["workers"], row["count"])
        require(parsed["services_ns"] == row["services_ns"], f"service samples: {receipt}")
        require(parsed["waves"] == row["waves"], f"waves: {receipt}")
        require(parsed["setup_ns"] == row["setup_ns"], f"setup: {receipt}")
        require(statistics.median(parsed["services_ns"]) == row["service_p50_ns"], f"run p50: {receipt}")
        require(p95(parsed["services_ns"]) == row["service_p95_ns"], f"run p95: {receipt}")
        stderr = (directory / f"{tag}.stderr").read_text().splitlines()
        require(stderr.count("prepared stream solver: 1") == 1, f"solver mode: {receipt}")
        require(stderr.count(f"prepared satisfaction-only: {int(row['arm'] == 'satisfied')}") == 1, f"satisfaction mode: {receipt}")
        require(sum(line.startswith("request solver index=") for line in stderr) == row["count"], f"request count: {receipt}")
    for circuit in ("escrow", "withdrawal"):
        controls = [row for row in report["control"] if row["circuit"] == circuit]
        for block in (1, 2):
            pair = [row for row in controls if row["block"] == block]
            require(len(pair) == 2, f"control pair: {circuit} {block}")
            median = max(pair[0]["service_p50_ns"] / pair[1]["service_p50_ns"], pair[1]["service_p50_ns"] / pair[0]["service_p50_ns"]) - 1
            tail = max(pair[0]["service_p95_ns"] / pair[1]["service_p95_ns"], pair[1]["service_p95_ns"] / pair[0]["service_p95_ns"]) - 1
            failed = median > 0.02 or tail > 0.10
            require(failed == any(item["circuit"] == circuit and item["block"] == block for item in report["host_control_failures"]), f"host gate: {circuit} {block}")
    calculated = {}
    for circuit in ("escrow", "withdrawal"):
        for arm in ("audit", "satisfied"):
            rows = [row for row in report["measurements"] if (row["circuit"], row["arm"]) == (circuit, arm)]
            if not rows:
                continue
            samples = [ns for row in rows for ns in row["services_ns"]]
            stated = report["summary"][f"{circuit}/{arm}"]
            require(len(samples) == stated["samples"], f"sample count: {circuit}/{arm}")
            require(statistics.median(samples) == stated["p50_ns"], f"p50: {circuit}/{arm}")
            require(p95(samples) == stated["p95_ns"], f"p95: {circuit}/{arm}")
            calculated[f"{circuit}/{arm}"] = stated["p50_ns"]
    return report, calculated


def main():
    fixture_sha = check_fixture_archive()
    old, medians = check_run(
        ROOT / "historical-one-core-linux/control-cpu0",
        "c2a3922480b1d60b285f065c941bd1dbf84b8cdd",
        256,
        400,
    )
    require(old["performance_eligible"] and not old["host_control_failures"], "historical host gate")
    mac, _ = check_run(
        ROOT / "final-cleanup-mac-gate",
        "89b43b11510a068d62e078a14fd95b084fe0dca2",
        256,
        0,
    )
    require(not mac["performance_eligible"] and len(mac["host_control_failures"]) == 4, "Mac host gate")
    for circuit in ("escrow", "withdrawal"):
        audit = medians[f"{circuit}/audit"]
        satisfied = medians[f"{circuit}/satisfied"]
        print(f"{circuit}: historical one-core prepared p50 {audit / 1e6:.3f} -> {satisfied / 1e6:.3f} ms; {(audit - satisfied) / audit:.2%} reduction")
    print(f"fixture archive sha256: {fixture_sha}")
    print("final-cleanup Mac: 256 verified control proofs, four failed host pairs, zero measured candidate proofs")


if __name__ == "__main__":
    main()
