"""Check Constantine query rejection paths using a digest-verified fixture."""

import struct
import subprocess
import sys
import tempfile
from pathlib import Path


def expect_rejection(binary, path, data, fragment):
    path.write_bytes(data)
    result = subprocess.run(
        [str(binary), str(path), "2", "1", "0"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 1 or result.stdout or fragment not in result.stderr:
        raise RuntimeError(
            f"{path.stem}: expected {fragment!r} with exit 1 and empty stdout. "
            f"Observed exit {result.returncode}, stdout {result.stdout!r}, "
            f"stderr {result.stderr!r}"
        )
    print(f"{path.stem}: rejected before timing output")


def main(binary, fixture, query="b1"):
    original = fixture.read_bytes()
    if len(original) < 12 or original[:8] != b"XKQMSM01":
        raise ValueError("control requires a valid XKQMSM01 fixture")
    count = struct.unpack_from("<I", original, 8)[0]
    reference_offset = 12 + count * 224
    if count == 0 or len(original) != reference_offset + 192:
        raise ValueError("control requires an exactly framed fixture")
    group_offset, point_size = {"b1": (0, 64), "b2": (64, 128)}[query]
    expected_offset = reference_offset + group_offset
    first_point = 12 + 32 + group_offset
    expected = original[expected_offset : expected_offset + point_size]
    wrong = bytearray(original)
    for offset in range(first_point, reference_offset, 224):
        # The supplied bases are independently validated points. Use a finite
        # point that differs from the correct output to exercise parity.
        candidate = original[offset : offset + point_size]
        if any(candidate) and candidate != expected:
            wrong[expected_offset : expected_offset + point_size] = candidate
            break
    else:
        raise ValueError(f"fixture lacks a distinct finite {query} point for the control")

    noncanonical = bytearray(original)
    noncanonical[first_point : first_point + 32] = bytes.fromhex(
        "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47"
    )
    with tempfile.TemporaryDirectory(dir=Path.cwd()) as scratch:
        scratch = Path(scratch)
        expect_rejection(
            binary, scratch / f"wrong-{query}.test-vector", wrong,
            f"{query} disagrees with the Arkworks result",
        )
        expect_rejection(
            binary, scratch / "noncanonical-fq.test-vector", noncanonical,
            "noncanonical field in query bundle",
        )
        expect_rejection(
            binary, scratch / "truncated.test-vector", original[:-1],
            "invalid XKQMSM01 size or term count",
        )
        expect_rejection(
            binary, scratch / "extra-byte.test-vector", original + b"\0",
            "invalid XKQMSM01 size or term count",
        )


if __name__ == "__main__":
    if len(sys.argv) not in (3, 4) or (
        len(sys.argv) == 4 and sys.argv[3] not in ("b1", "b2")
    ):
        raise SystemExit("usage: check_rejection.py <constantine> <verified.test-vector> [b1|b2]")
    query = sys.argv[3] if len(sys.argv) == 4 else "b1"
    main(Path(sys.argv[1]).resolve(strict=True), Path(sys.argv[2]), query)
