#!/usr/bin/env python3
"""Build the pinned Gnark adapter and record its source and binary identity."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys

from build_xark import sha256, source_revision


ADAPTER = Path("benches/privacy-rings-gnark")
SOURCE_FILES = ("main.go", "go.mod", "go.sum")


def output(command, *, cwd=None):
    return subprocess.check_output(command, cwd=cwd, text=True, timeout=30).strip()


def verify_manifest(manifest_path, source, binary):
    """Reject a changed source, Go module lock, executable, or build receipt."""
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("version") != 1:
        raise ValueError("unsupported Gnark build manifest version")
    source = source.resolve(strict=True)
    binary = binary.resolve(strict=True)
    if manifest.get("source") != str(source):
        raise ValueError("Gnark build manifest source path differs")
    source_revision(source, manifest["source_commit"])
    adapter = source / ADAPTER
    for name in SOURCE_FILES:
        if manifest["source_sha256"].get(name) != sha256(adapter / name):
            raise ValueError(f"Gnark {name} differs from build manifest")
    if manifest.get("binary") != str(binary) or manifest.get("binary_sha256") != sha256(binary):
        raise ValueError("Gnark executable differs from build manifest")
    target = Path(manifest["target_dir"]).resolve(strict=True)
    if target not in binary.parents:
        raise ValueError("Gnark executable is outside isolated target")
    for name in ("stdout", "stderr"):
        if manifest.get(f"build_{name}_sha256") != sha256(target / f"build.{name}"):
            raise ValueError(f"Gnark build {name} log differs")
    if manifest.get("go_version_m") != output(["go", "version", "-m", str(binary)]):
        raise ValueError("Gnark embedded Go module information differs")
    return manifest


def build(args):
    source = args.source.resolve(strict=True)
    target = args.target_dir.resolve()
    commit = source_revision(source, args.expected_commit)
    if source == target or source in target.parents:
        raise ValueError("target directory must be outside the source checkout")
    if target.exists():
        raise ValueError("target directory already exists")
    target.mkdir(mode=0o700, parents=True)
    adapter = source / ADAPTER
    binary = target / "privacy-rings-gnark"
    command = ["go", "build", "-mod=readonly", "-trimpath", "-o", str(binary), "."]
    before = {name: sha256(adapter / name) for name in SOURCE_FILES}
    with (target / "build.stdout").open("wb") as stdout, (target / "build.stderr").open("wb") as stderr:
        result = subprocess.run(command, cwd=adapter, stdout=stdout, stderr=stderr, check=False)
    if result.returncode:
        raise RuntimeError(f"Go exited {result.returncode}; inspect {target / 'build.stderr'}")
    source_revision(source, commit)
    if before != {name: sha256(adapter / name) for name in SOURCE_FILES}:
        raise ValueError("Gnark source files changed during build")
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise ValueError("Go succeeded without an executable")
    manifest = {
        "version": 1,
        "built_at_utc": datetime.now(timezone.utc).isoformat(),
        "source": str(source),
        "source_commit": commit,
        "source_sha256": before,
        "target_dir": str(target),
        "binary": str(binary),
        "binary_sha256": sha256(binary),
        "build_stdout_sha256": sha256(target / "build.stdout"),
        "build_stderr_sha256": sha256(target / "build.stderr"),
        "command": command,
        "go_version": output(["go", "version"]),
        "goamd64": output(["go", "env", "GOAMD64"]),
        "go_version_m": output(["go", "version", "-m", str(binary)]),
    }
    path = target / "gnark-build-manifest.json"
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    verify_manifest(path, source, binary)
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--target-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(build(args))
    except (OSError, ValueError, RuntimeError, KeyError, subprocess.SubprocessError) as exc:
        print(f"build_gnark: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
