#!/usr/bin/env python3
"""Attribute archived Linux perf samples to recognizable Xark G2 phases."""

import argparse
from collections import Counter
import gzip
import json
from pathlib import Path
import re
import tarfile

from reconstruct import ARCHIVES, sha256

HEADER = re.compile(rb"^bench_prove\s+\d+/\d+\s+[\d.]+:\s*$")
FRAME = re.compile(rb"^\s+[0-9a-f]+\s+(.+?)\s+\(")
LEAF_PHASES = {
    "base_field_two_products": (b"sum_of_productsKj2",),
    "base_field_mul": (b"mul_assign",),
    "base_field_square": (b"square_in_place",),
    "base_field_inverse": (b"inverse",),
}
SAMPLES = ("./query-script.log", "./resident-script.log")


def stacks(lines):
    current = None
    for line in lines:
        if HEADER.fullmatch(line):
            if current is not None:
                yield current
            current = []
        elif current is not None and (frame := FRAME.match(line)):
            current.append(frame[1])
    if current is not None:
        yield current


def profile(lines):
    counts = Counter()
    for frames in stacks(lines):
        counts["samples"] += 1
        if not frames:
            counts["empty_unwind"] += 1
            continue
        leaf = frames[0]
        g2 = [
            frame
            for frame in frames
            if b"2g26Config" in frame
            and (b"pippenger_core" in frame or b"AffineBuckets" in frame)
        ]
        if not g2:
            if any(word in leaf for word in (b"futex", b"park", b"wait_until_cold")):
                counts["global_sync_leaf"] += 1
            continue

        counts["g2_scope"] += 1
        flush = any(b"AffineBuckets" in frame and b"5flush" in frame for frame in g2)
        counts["g2_affine_flush_scope"] += flush
        tags = []
        if b"fq8FqConfig" in leaf:
            tags.extend(
                phase
                for phase, patterns in LEAF_PHASES.items()
                if any(p in leaf for p in patterns)
            )
        elif b"QuadExtField" in leaf:
            for phase, pattern in (
                ("fq2_mul", b"mul_assign"),
                ("fq2_square", b"square"),
                ("fq2_inverse", b"inverse"),
            ):
                if pattern in leaf:
                    tags.append(phase)
        if b"short_weierstrass" in leaf:
            if b"double" in leaf:
                tags.append("point_doubling")
            elif b"add_assign" in leaf:
                tags.append("point_addition")
        if any(name in leaf for name in (b"recode", b"glv_decompose", b"split_scalar")):
            tags.append("scalar_recoding")
        if b"pippenger_core" in leaf:
            tags.append("bucket_loop_leaf")
        if any(
            name in leaf
            for name in (b"malloc", b"__rust_alloc", b"realloc", b"jemalloc")
        ):
            tags.append("allocation_leaf")
        if any(name in leaf for name in (b"futex", b"park", b"wait_until_cold")):
            tags.append("sync_leaf")
        if not tags:
            counts["g2_unclassified_leaf"] += 1
        for tag in tags:
            counts["g2_" + tag] += 1
            if flush:
                counts["g2_flush_" + tag] += 1
    return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    args = parser.parse_args()
    if sha256(args.archive) != ARCHIVES["linux-perf"][1]:
        parser.exit(1, "perf archive digest differs\n")
    with gzip.open(args.archive, "rb") as archive_stream:
        with tarfile.open(fileobj=archive_stream, mode="r|") as archive:
            results = {
                member.name: profile(archive.extractfile(member))
                for member in archive
                if member.name in SAMPLES
                and member.isfile()
                and member.size <= 32 * 1024 * 1024
            }
    if set(results) != set(SAMPLES) or any(
        not counts["samples"] for counts in results.values()
    ):
        parser.exit(1, "missing profiling samples\n")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
