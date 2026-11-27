#!/usr/bin/env python3
"""Build the pinned Xark benchmark executable in a fresh Cargo target directory."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def output(command, *, cwd=None):
    return subprocess.check_output(command, cwd=cwd, text=True, timeout=30).strip()


def source_revision(source, expected):
    if not re.fullmatch(r"[0-9a-f]{40}", expected):
        raise ValueError("expected commit must be a full lowercase SHA")
    actual = output(["git", "rev-parse", "HEAD"], cwd=source)
    if actual != expected:
        raise ValueError(f"source revision differs from expected commit: {actual}")
    if output(["git", "status", "--porcelain", "--untracked-files=all"], cwd=source):
        raise ValueError("source checkout contains changed or untracked files")
    return actual


def verify_manifest(manifest_path, source, binary):
    """Verify a recorded Xark build before using its executable for timing."""
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("version") != 1:
        raise ValueError("unsupported Xark build manifest version")
    source = source.resolve(strict=True)
    binary = binary.resolve(strict=True)
    if manifest.get("source") != str(source):
        raise ValueError("build manifest source path differs from selected checkout")
    source_commit = manifest.get("source_commit")
    if not isinstance(source_commit, str):
        raise ValueError("build manifest lacks a source commit")
    source_revision(source, source_commit)
    if manifest.get("cargo_lock_sha256") != sha256(source / "Cargo.lock"):
        raise ValueError("Cargo.lock differs from the build manifest")
    if manifest.get("binary") != str(binary):
        raise ValueError("build manifest binary path differs from selected executable")
    if manifest.get("binary_sha256") != sha256(binary):
        raise ValueError("benchmark binary differs from the build manifest")
    target_name = manifest.get("target_dir")
    if not isinstance(target_name, str):
        raise ValueError("build manifest lacks a target directory")
    target = Path(target_name).resolve(strict=True)
    if target not in binary.parents:
        raise ValueError("benchmark binary is outside the isolated target directory")
    for name in ("stdout", "stderr"):
        if manifest.get(f"build_{name}_sha256") != sha256(target / f"build.{name}"):
            raise ValueError(f"build {name} log differs from the manifest")
    return manifest


def build(args):
    source = args.source.resolve(strict=True)
    target = args.target_dir.resolve()
    expected = source_revision(source, args.expected_commit)
    if source == target or source in target.parents:
        raise ValueError("target directory must be outside the source checkout")
    if target.exists():
        raise ValueError("target directory already exists; use a fresh path")
    target.mkdir(mode=0o700, parents=True)
    profile = args.profile
    binary = target / profile / "examples" / "bench_prove"
    command = [
        "cargo",
        "build",
        "--locked",
        "--profile",
        profile,
        "-p",
        "xark-groth16",
        "--example",
        "bench_prove",
    ]
    if args.features:
        command.extend(["--features", args.features])
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = str(target)
    for name in (
        "RUSTC_WRAPPER",
        "CARGO_BUILD_RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
    ):
        env.pop(name, None)
    if args.offline:
        command.insert(2, "--offline")
    lock_sha = sha256(source / "Cargo.lock")
    stdout_path = target / "build.stdout"
    stderr_path = target / "build.stderr"
    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        result = subprocess.run(
            command,
            cwd=source,
            env=env,
            stdout=stdout,
            stderr=stderr,
            check=False,
        )
    if result.returncode:
        raise RuntimeError(f"Cargo exited {result.returncode}; inspect {stderr_path}")
    source_revision(source, expected)
    if sha256(source / "Cargo.lock") != lock_sha:
        raise ValueError("Cargo.lock changed during the build")
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise ValueError("Cargo succeeded without the expected executable")
    manifest = {
        "version": 1,
        "built_at_utc": datetime.now(timezone.utc).isoformat(),
        "source": str(source),
        "source_commit": expected,
        "cargo_lock_sha256": lock_sha,
        "target_dir": str(target),
        "binary": str(binary),
        "binary_sha256": sha256(binary),
        "binary_bytes": binary.stat().st_size,
        "profile": profile,
        "features": args.features,
        "command": command,
        "rustc": output(["rustc", "-Vv"]),
        "cargo": output(["cargo", "-V"]),
        "rustflags": env.get("RUSTFLAGS"),
        "cargo_encoded_rustflags": env.get("CARGO_ENCODED_RUSTFLAGS"),
        "build_stderr_sha256": sha256(stderr_path),
        "build_stdout_sha256": sha256(stdout_path),
    }
    path = target / "xark-build-manifest.json"
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    path.chmod(0o600)
    verify_manifest(path, source, binary)
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--target-dir", type=Path, required=True)
    parser.add_argument("--profile", choices=("release", "ci"), default="release")
    parser.add_argument("--features", default="")
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    try:
        print(build(args))
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"build_xark: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
