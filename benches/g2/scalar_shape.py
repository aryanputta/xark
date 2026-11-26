#!/usr/bin/env python3
"""Compare aggregate B2 scalar shapes on the pinned public test fixtures."""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

FR = int("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001", 16)
FIXTURES = {
    "617fcfa09ff2eb37b7c44535d0ceb8b9878b18d5ddca4b98c6feafdc4bbe2cbc": (
        7606,
        "escrow",
    ),
    "a9978e8bc01658ee04fe09b0bc261759ed41ce4f5c3c52c5d1f569a7a5414e0b": (
        5406,
        "withdrawal",
    ),
}
CLASSES = (0, 1, 16, 32, 64, 128, 256)
CHUNK = 1 << 128


def magnitude(scalar):
    return min(scalar, FR - scalar)


def classes(scalars):
    histogram = Counter(
        next(limit for limit in CLASSES if magnitude(scalar).bit_length() <= limit)
        for scalar in scalars
    )
    return dict(sorted(histogram.items()))


def booth(scalar, position, width):
    bits = (scalar >> position) & ((1 << width) - 1)
    carry = ((scalar >> (position - 1)) & 1) if position else 0
    return bits + carry - ((bits >> (width - 1)) << width)


def occupancy(scalars, width):
    windows = []
    for position in range(0, 129, width):
        buckets = Counter(abs(booth(s, position, width)) for s in scalars)
        buckets.pop(0, None)
        hits = sum(buckets.values())
        windows.append(
            {
                "window": position // width,
                "digit_hits": hits,
                "nonempty_buckets": len(buckets),
                "collisions_after_first_hit": hits - len(buckets),
                "largest_bucket": max(buckets.values(), default=0),
            }
        )
    return windows


def inspect(path):
    data = path.read_bytes()
    fingerprint = hashlib.sha256(data).hexdigest()
    if fingerprint not in FIXTURES:
        raise ValueError(
            "B2 export fingerprint is not a known shared synthetic fixture"
        )
    terms, workload = FIXTURES[fingerprint]
    if data[:8] != b"XKQMSM01" or int.from_bytes(data[8:12], "little") != terms:
        raise ValueError("malformed B2 export")
    if len(data) != 12 + terms * 224 + 192:
        raise ValueError("wrong B2 export length")
    scalars = [
        int.from_bytes(data[i : i + 32], "big")
        for i in range(12, 12 + terms * 224, 224)
        if any(data[i + 96 : i + 224])
    ]
    if any(not 0 <= scalar < FR for scalar in scalars):
        raise ValueError("noncanonical fixture scalar")
    pure = [(s % CHUNK, s // CHUNK) for s in scalars]
    preserved = [
        (s, 0) if magnitude(s) < CHUNK else pair
        for s, pair in zip(scalars, pure, strict=True)
    ]
    for pairs in (pure, preserved):
        assert all(
            (lo + hi * CHUNK) % FR == s
            for s, (lo, hi) in zip(scalars, pairs, strict=True)
        )
    width = 11
    return {
        "workload": workload,
        "bundle_sha256": fingerprint,
        "terms": terms,
        "nonidentity": len(scalars),
        "width_for_occupancy_inspection": width,
        "ordinary_magnitude_classes": classes(scalars),
        "unsigned_component_classes": classes(t for pair in pure for t in pair),
        "signed_magnitude_preserved_classes": classes(
            t for pair in preserved for t in pair
        ),
        "negative_short": sum(s >= CHUNK and magnitude(s) < CHUNK for s in scalars),
        "unsigned_fixed_width_occupancy": occupancy(
            [t for pair in pure for t in pair], width
        ),
        "signed_preserved_fixed_width_occupancy": occupancy(
            [magnitude(t) for pair in preserved for t in pair], width
        ),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundles", nargs="+", type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps([inspect(path) for path in args.bundles], indent=2))
    except (OSError, ValueError) as error:
        parser.exit(1, f"scalar-shape: {error}\n")


if __name__ == "__main__":
    main()
