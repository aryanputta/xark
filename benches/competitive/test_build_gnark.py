"""Gnark build provenance rejects changed source and executable artifacts."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from build_gnark import SOURCE_FILES, verify_manifest
from build_xark import sha256


class GnarkManifestTests(unittest.TestCase):
    def test_verified_manifest_rejects_changed_inputs(self):
        commit = "a" * 40
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            source = root / "source"
            adapter = source / "benches/privacy-rings-gnark"
            adapter.mkdir(parents=True)
            for name in SOURCE_FILES:
                (adapter / name).write_text(name)
            target = root / "target"
            target.mkdir()
            binary = target / "privacy-rings-gnark"
            binary.write_bytes(b"go executable")
            for name in ("stdout", "stderr"):
                (target / f"build.{name}").write_text(name)
            manifest = {
                "version": 1,
                "source": str(source.resolve()),
                "source_commit": commit,
                "source_sha256": {
                    name: sha256(adapter / name) for name in SOURCE_FILES
                },
                "target_dir": str(target.resolve()),
                "binary": str(binary.resolve()),
                "binary_sha256": sha256(binary),
                "build_stdout_sha256": sha256(target / "build.stdout"),
                "build_stderr_sha256": sha256(target / "build.stderr"),
                "go_version_m": "pinned module receipt",
            }
            receipt = target / "gnark-build-manifest.json"
            receipt.write_text(json.dumps(manifest))
            with patch("build_gnark.source_revision", return_value=commit), patch(
                "build_gnark.output", return_value="pinned module receipt"
            ):
                self.assertEqual(
                    verify_manifest(receipt, source, binary)["source_commit"], commit
                )
                binary.write_bytes(b"changed")
                with self.assertRaisesRegex(ValueError, "executable differs"):
                    verify_manifest(receipt, source, binary)
                binary.write_bytes(b"go executable")
                (adapter / "go.sum").write_text("changed")
                with self.assertRaisesRegex(ValueError, "go.sum differs"):
                    verify_manifest(receipt, source, binary)


if __name__ == "__main__":
    unittest.main()
