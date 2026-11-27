#!/usr/bin/env python3
"""Validate every receipt in a prepared resident proof memory soak.

Usage: python3 verify_soak.py RESULT_DIR escrow|withdrawal
The directory holds CIRCUIT.stdout, CIRCUIT.stderr and CIRCUIT-process.json.
"""

import argparse
import json
import re
from pathlib import Path


def rows(pattern: str, data: str) -> list[tuple[int, ...]]:
    return [tuple(map(int, match)) for match in re.findall(pattern, data, re.MULTILINE)]


def verify(root: Path, circuit: str) -> dict[str, int | str]:
    metadata = json.loads((root / f"{circuit}-process.json").read_text())
    stdout = (root / f"{circuit}.stdout").read_text()
    stderr = (root / f"{circuit}.stderr").read_text()
    count = metadata["requests"]
    concurrency = metadata["concurrency"]
    assert metadata["exit_code"] == 0
    assert count >= 4 and 1 <= concurrency <= count
    assert metadata["rayon_workers"] >= 1

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
    assert len(waves) == len(memory) == len(expected_first)
    assert len(verified) == len(solver) == count
    assert [first for first, _, _ in waves] == expected_first
    assert all(
        size == min(concurrency, count - first) and elapsed > 0
        for first, size, elapsed in waves
    )
    assert [index for index, _, _ in verified] == list(range(count))
    assert all(
        fixture == index % 4 and elapsed > 0 for index, fixture, elapsed in verified
    )
    assert [index for index, _ in solver] == list(range(count))
    assert all(elapsed > 0 for _, elapsed in solver)
    assert [completed for completed, _, _ in memory] == [
        min(count, first + concurrency) for first in expected_first
    ]
    assert all(peak >= live > 0 for _, live, peak in memory)
    assert (
        f"requests verified mode=cpu concurrency={concurrency} "
        f"threads={metadata['rayon_workers']} count={count} "
    ) in stdout
    assert "altered=rejected cross_request=rejected" in stdout
    assert "prepared stream solver: 1" in stderr
    assert "shared B scalars: 0" in stderr
    live = [value for _, value, _ in memory]
    return {
        "circuit": circuit,
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
