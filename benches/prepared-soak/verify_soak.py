#!/usr/bin/env python3
"""Validate every receipt in a prepared resident proof memory soak.

Usage: python3 verify_soak.py RESULT_DIR escrow|withdrawal
The directory holds CIRCUIT.stdout, CIRCUIT.stderr and CIRCUIT-process.json.
"""

import argparse
import json
import re
from pathlib import Path


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def rows(pattern: str, data: str) -> list[tuple[int, ...]]:
    matches = re.findall(pattern, data, re.MULTILINE)
    return [
        tuple(map(int, (match,) if isinstance(match, str) else match))
        for match in matches
    ]


def verify(root: Path, circuit: str) -> dict[str, int | str | bool | None]:
    metadata = json.loads((root / f"{circuit}-process.json").read_text())
    stdout = (root / f"{circuit}.stdout").read_text()
    stderr = (root / f"{circuit}.stderr").read_text()
    count = metadata["requests"]
    concurrency = metadata["concurrency"]
    require(metadata["exit_code"] == 0, "prover process failed")
    require(count >= 4 and 1 <= concurrency <= count, "invalid request metadata")
    require(metadata["rayon_workers"] >= 1, "invalid worker metadata")

    waves = rows(r"^request wave first=(\d+) count=(\d+) active_ns=(\d+)$", stdout)
    verified = rows(
        r"^request verified index=(\d+) fixture=(\d+) service_ns=(\d+)$", stdout
    )
    solver = rows(r"^request solver index=(\d+) solve_ns=(\d+)$", stderr)
    memory = rows(
        r"^request memory completed=(\d+) live_heap_bytes=(\d+) peak_heap_bytes=(\d+)$",
        stderr,
    )
    expected_first = list(range(0, count, concurrency))
    require(
        len(waves) == len(memory) == len(expected_first),
        "missing wave or memory receipt",
    )
    require(len(verified) == len(solver) == count, "missing proof or solver receipt")
    require([first for first, _, _ in waves] == expected_first, "noncontiguous waves")
    require(
        all(
            size == min(concurrency, count - first) and elapsed > 0
            for first, size, elapsed in waves
        ),
        "invalid wave receipt",
    )
    require(
        [index for index, _, _ in verified] == list(range(count)),
        "noncontiguous proof receipts",
    )
    require(
        all(
            fixture == index % 4 and elapsed > 0 for index, fixture, elapsed in verified
        ),
        "invalid proof fixture or service duration",
    )
    require(
        [index for index, _ in solver] == list(range(count)),
        "noncontiguous solver receipts",
    )
    require(all(elapsed > 0 for _, elapsed in solver), "invalid solver duration")
    require(
        [completed for completed, _, _ in memory]
        == [min(count, first + concurrency) for first in expected_first],
        "noncontiguous memory receipts",
    )
    require(all(peak >= live > 0 for _, live, peak in memory), "invalid memory receipt")
    require(
        (
            f"requests verified mode=cpu concurrency={concurrency} "
            f"threads={metadata['rayon_workers']} count={count} "
        )
        in stdout,
        "missing final verification marker",
    )
    require(
        "altered=rejected cross_request=rejected" in stdout,
        "negative statement check missing",
    )
    require("prepared stream solver: 1" in stderr, "prepared solver was not active")
    require("shared B scalars: 0" in stderr, "unexpected shared B scalar mode")
    validated_key = metadata.get("proving_key_validated", False)
    key_validation = rows(
        r"^proving key validation: complete duration_ns=(\d+)$", stderr
    )
    if validated_key:
        require(
            len(key_validation) == 1 and key_validation[0][0] > 0,
            "full key validation receipt missing",
        )
    else:
        require(not key_validation, "key validation marker conflicts with metadata")
    live = [value for _, value, _ in memory]
    return {
        "circuit": circuit,
        "proving_key_validated": validated_key,
        "key_validation_ns": key_validation[0][0] if validated_key else None,
        "verified_proofs": count,
        "verified_waves": len(waves),
        "live_heap_first_bytes": live[0],
        "live_heap_last_bytes": live[-1],
        "live_heap_min_bytes": min(live),
        "live_heap_max_bytes": max(live),
        "peak_process_rss_bytes": metadata["peak_rss_bytes"],
        "binary_sha256": metadata["binary_sha256"],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("result_dir", type=Path)
    parser.add_argument("circuit", choices=("escrow", "withdrawal"))
    args = parser.parse_args()
    print(json.dumps(verify(args.result_dir, args.circuit), indent=2))
