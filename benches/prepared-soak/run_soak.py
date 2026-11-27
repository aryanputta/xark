#!/usr/bin/env python3
"""Run a verified prepared CPU proof soak with a pinned synthetic fixture set."""

import argparse
import hashlib
import json
import os
import platform
import resource
import subprocess
from pathlib import Path

PINNED_MANIFEST_SHA256 = (
    "0436bedbae33912331d7306b9c1406956be5695d43f85f5c750f19bbb9bcce41"
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check_manifest(root: Path) -> str:
    manifest = root / "fixtures.sha256"
    manifest_digest = sha256(manifest)
    if manifest_digest != PINNED_MANIFEST_SHA256:
        raise ValueError("fixture manifest does not match the pinned synthetic set")
    entries = manifest.read_text().splitlines()
    assert len(entries) == 28, "expected the pinned 28-file synthetic fixture set"
    for entry in entries:
        expected, name = entry.split("  ", 1)
        member = Path(name)
        assert not member.is_absolute() and ".." not in member.parts
        assert sha256(root / member) == expected, f"fixture checksum mismatch: {name}"
    return manifest_digest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("fixture_root", type=Path)
    parser.add_argument("result_dir", type=Path)
    parser.add_argument("circuit", choices=("escrow", "withdrawal"))
    parser.add_argument("--requests", type=int, default=1000)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--threads", type=int, default=2)
    args = parser.parse_args()
    assert args.requests >= 4 and 1 <= args.concurrency <= args.requests
    assert args.threads >= 1
    manifest_sha256 = check_manifest(args.fixture_root)
    directories = sorted(
        path.parent
        for path in (args.fixture_root / "requests" / args.circuit).glob(
            "*/**/inputs.json"
        )
    )
    assert len(directories) == 4
    assert all((directory / "public.json").is_file() for directory in directories)
    assert all(
        (directory / "public-changed.json").is_file() for directory in directories
    )
    reference = args.fixture_root / "reference" / args.circuit
    xbc = reference / "circuit.xbc"
    key = reference / "test-key.bin"
    assert xbc.is_file() and key.is_file()
    binary_sha256 = sha256(args.binary)

    args.result_dir.mkdir(parents=True, exist_ok=True)
    os.umask(0o077)
    stdout_path = args.result_dir / f"{args.circuit}.stdout"
    stderr_path = args.result_dir / f"{args.circuit}.stderr"
    process_path = args.result_dir / f"{args.circuit}-process.json"
    assert not any(
        path.exists() for path in (stdout_path, stderr_path, process_path)
    ), "refusing to overwrite a prior run"
    command = [
        str(args.binary),
        "warm-requests",
        str(xbc),
        str(key),
        "cpu",
        str(args.concurrency),
        str(args.requests),
        *map(str, directories),
    ]
    env = {
        key: value for key, value in os.environ.items() if not key.startswith("BENCH_")
    }
    env.update(
        BENCH_MEMORY="1",
        BENCH_PREPARED_SOLVER="1",
        BENCH_SHARED_B_SCALARS="0",
        RAYON_NUM_THREADS=str(args.threads),
    )
    with stdout_path.open("x") as stdout, stderr_path.open("x") as stderr:
        result = subprocess.run(
            command, env=env, stdout=stdout, stderr=stderr, check=False
        )
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    process = {
        "circuit": args.circuit,
        "requests": args.requests,
        "concurrency": args.concurrency,
        "rayon_workers": args.threads,
        "exit_code": result.returncode,
        "peak_rss_bytes": usage.ru_maxrss
        * (1024 if platform.system() == "Linux" else 1),
        "binary_sha256": binary_sha256,
        "fixture_manifest_sha256": manifest_sha256,
        "host_os": platform.system(),
        "host_arch": platform.machine(),
    }
    process_path.write_text(json.dumps(process, indent=2) + "\n")
    print(json.dumps(process, indent=2))
    if result.returncode:
        raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
