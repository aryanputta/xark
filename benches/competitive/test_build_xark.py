"""Artifact integrity checks for the isolated Xark benchmark builder."""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from build_xark import build, sha256, source_revision, verify_manifest
from run import xark_build_record


class BuildManifestTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        root = Path(self.scratch.name).resolve()
        self.source = root / "source"
        self.source.mkdir()
        subprocess.run(["git", "init", "-q", str(self.source)], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(self.source),
                "config",
                "user.email",
                "benchmark@example.test",
            ],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(self.source), "config", "user.name", "Benchmark Test"],
            check=True,
        )
        (self.source / "Cargo.lock").write_text("# pinned lock\n")
        subprocess.run(["git", "-C", str(self.source), "add", "Cargo.lock"], check=True)
        subprocess.run(
            ["git", "-C", str(self.source), "commit", "-q", "-m", "pin lock"],
            check=True,
        )
        self.commit = subprocess.check_output(
            ["git", "-C", str(self.source), "rev-parse", "HEAD"], text=True
        ).strip()
        self.target = root / "fresh-target"
        self.binary = self.target / "ci" / "examples" / "bench_prove"
        self.binary.parent.mkdir(parents=True)
        self.binary.write_bytes(b"benchmark executable")
        self.binary.chmod(0o700)
        for name in ("stdout", "stderr"):
            (self.target / f"build.{name}").write_text(f"{name} build log\n")
        self.manifest = self.target / "xark-build-manifest.json"
        self.data = {
            "version": 1,
            "source": str(self.source),
            "source_commit": self.commit,
            "cargo_lock_sha256": sha256(self.source / "Cargo.lock"),
            "target_dir": str(self.target),
            "binary": str(self.binary),
            "binary_sha256": sha256(self.binary),
            "build_stdout_sha256": sha256(self.target / "build.stdout"),
            "build_stderr_sha256": sha256(self.target / "build.stderr"),
        }
        self.manifest.write_text(json.dumps(self.data))

    def test_manifest_matches_pinned_checkout_and_binary(self):
        self.assertEqual(
            verify_manifest(self.manifest, self.source, self.binary)["source_commit"],
            self.commit,
        )
        config = {"version": 2, "xark_build_manifest": str(self.manifest)}
        source = {"path": str(self.source), "commit": self.commit}
        self.assertEqual(
            xark_build_record(config, self.source.parent, source, self.binary),
            self.manifest,
        )

    def test_new_runner_version_requires_build_record(self):
        source = {"path": str(self.source), "commit": self.commit}
        with self.assertRaisesRegex(ValueError, "requires an isolated"):
            xark_build_record({"version": 2}, self.source.parent, source, self.binary)
        self.assertIsNone(
            xark_build_record({"version": 1}, self.source.parent, source, self.binary)
        )

    def test_binary_and_log_changes_are_rejected(self):
        self.binary.write_bytes(b"different executable")
        with self.assertRaisesRegex(ValueError, "benchmark binary differs"):
            verify_manifest(self.manifest, self.source, self.binary)
        self.binary.write_bytes(b"benchmark executable")
        (self.target / "build.stderr").write_text("changed log\n")
        with self.assertRaisesRegex(ValueError, "build stderr log differs"):
            verify_manifest(self.manifest, self.source, self.binary)

    def test_lockfile_change_is_rejected(self):
        (self.source / "Cargo.lock").write_text("# changed lock\n")
        with self.assertRaisesRegex(ValueError, "changed or untracked"):
            verify_manifest(self.manifest, self.source, self.binary)

    def test_source_changes_and_wrong_commit_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "differs from expected"):
            source_revision(self.source, "0" * 40)
        (self.source / "untracked.txt").write_text("unexpected build input\n")
        with self.assertRaisesRegex(ValueError, "untracked"):
            verify_manifest(self.manifest, self.source, self.binary)

    def test_build_refuses_existing_target_before_running_cargo(self):
        from argparse import Namespace

        args = Namespace(
            source=self.source,
            expected_commit=self.commit,
            target_dir=self.target,
            profile="ci",
            features="",
            offline=True,
        )
        with self.assertRaisesRegex(ValueError, "already exists"):
            build(args)


if __name__ == "__main__":
    unittest.main()
