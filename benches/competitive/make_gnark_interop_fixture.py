#!/usr/bin/env python3
"""Build one public format-regression case, with no benchmark input files."""

from pathlib import Path
from struct import pack
import sys


MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617


def fe(value):
    return value.to_bytes(32, "little")


def section(number, data):
    return pack("<IQ", number, len(data)) + data


def main(directory):
    directory.mkdir()
    field = pack("<I", 32) + fe(MODULUS)
    # Public product at wire 1 and the two private factors at wires 2 and 3.
    header = field + pack("<IIIIQI", 4, 0, 1, 0, 4, 2)
    product_row = b"".join(pack("<II", 1, wire) + fe(1) for wire in (2, 3, 1))
    labels = pack("<QQQQ", 0, 1, 2, 3)
    (directory / "circuit.r1cs").write_bytes(
        b"r1cs"
        + pack("<II", 1, 3)
        + section(1, header)
        + section(2, product_row * 2)
        + section(3, labels)
    )
    witness = b"".join(fe(value) for value in (1, 42, 6, 7))
    (directory / "witness.wtns").write_bytes(
        b"wtns"
        + pack("<II", 2, 2)
        + section(1, field + pack("<I", 4))
        + section(2, witness)
    )
    (directory / "public.json").write_text('{"public_hash":"42"}\n')
    (directory / "public-changed.json").write_text('{"public_hash":"43"}\n')


if __name__ == "__main__":
    main(Path(sys.argv[1]))
