"""Recompute bounded PR #101 and #103 p50/p95 results from raw proof logs."""

from decimal import Decimal
from hashlib import sha256
from math import ceil
from pathlib import Path
import re
import statistics


ROOT = Path(__file__).resolve().parent
PROVE = re.compile(r"^warm prove: xark-groth16 ([0-9.]+)s$", re.MULTILINE)
ROW = re.compile(r"^warm row check: xark-groth16 ([0-9]+) ns$", re.MULTILINE)


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def check_manifest(directory: Path) -> None:
    rows = (directory / "files.sha256").read_text().splitlines()
    require(bool(rows), f"empty manifest: {directory}")
    for row in rows:
        expected, name = row.split(maxsplit=1)
        actual = sha256((directory / name).read_bytes()).hexdigest()
        require(actual == expected, f"hash mismatch: {directory / name}")


def samples(directory: Path, name: str, mode: str) -> tuple[Decimal, Decimal]:
    contents = (directory / name).read_text()
    require(f"witness row checker: {mode}" in contents, f"mode: {name}")
    require(
        contents.count("changed statement rejected by Arkworks and Xark for each backend") == 1,
        f"proof negative check: {name}",
    )
    require("resident includes row checks: true" in contents, f"row preflight: {name}")
    proving = [Decimal(value) * 1000 for value in PROVE.findall(contents)]
    checking = [Decimal(value) / 1000000 for value in ROW.findall(contents)]
    require(len(proving) == len(checking) == 30, f"sample count: {name}")
    return statistics.median(proving), sorted(proving)[ceil(0.95 * len(proving)) - 1]


def report(label: str, baseline: tuple[Decimal, Decimal], candidate: tuple[Decimal, Decimal]) -> None:
    p50_saved = baseline[0] - candidate[0]
    p95_saved = baseline[1] - candidate[1]
    require(p50_saved > 0, f"nonpositive p50 reduction: {label}")
    print(
        f"{label}: p50 {baseline[0]:.4f} -> {candidate[0]:.4f} ms; "
        f"saved {p50_saved:.4f} ms ({p50_saved / baseline[0]:.2%}); "
        f"p95 saved {p95_saved:.4f} ms"
    )


def main() -> None:
    row_dir = ROOT / "pr101-row-checks"
    x86_dir = ROOT / "pr103-adx-bmi2"
    for directory in (row_dir, x86_dir):
        check_manifest(directory)
    require(
        (row_dir / "escrow.sha256").read_bytes() == (x86_dir / "escrow.sha256").read_bytes(),
        "escrow fixture hashes differ",
    )
    require(
        (row_dir / "withdrawal.sha256").read_bytes() == (x86_dir / "withdrawal.sha256").read_bytes(),
        "withdrawal fixture hashes differ",
    )
    for circuit in ("escrow", "withdrawal"):
        for pair in (1, 2):
            old = samples(row_dir, f"{circuit}-{pair}-expanded.log", "expanded")
            new = samples(row_dir, f"{circuit}-{pair}-1.log", "compiled")
            report(f"PR101 {circuit} pair {pair}", old, new)
        order = ("portable", "targeted", "targeted", "portable")
        if circuit == "withdrawal":
            order = ("targeted", "portable", "portable", "targeted")
        data = {
            (index, mode): samples(x86_dir, f"{circuit}-{index}-{mode}.log", "compiled")
            for index, mode in enumerate(order, start=1)
        }
        for first, second in ((1, 2), (3, 4)):
            portable = next(data[(index, mode)] for index in (first, second) for mode in ("portable",) if (index, mode) in data)
            targeted = next(data[(index, mode)] for index in (first, second) for mode in ("targeted",) if (index, mode) in data)
            report(f"PR103 {circuit} pair {(first + 1) // 2}", portable, targeted)


if __name__ == "__main__":
    main()
