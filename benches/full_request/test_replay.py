"""The full-request replay must reject an unstable or mismatched host first."""

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from host_control import assess
from replay import run, validate_host_control


BINDING = {
    "node": "quiet-host",
    "platform": "Linux-test",
    "boot_id": "boot-123",
    "affinity": [2, 4],
}


def passing_control():
    rows = [
        dict(
            fixture=fixture,
            block=block,
            arm=arm,
            p50_ns=1000,
            p95_ns=1200,
            services_ns=[1000] * 7 + [1200],
            waves=[{"wall_ns": 1200, "overlap": False}] * 8,
        )
        for fixture in ("escrow", "withdrawal")
        for block in (1, 2)
        for arm in ("A", "B")
    ]
    return dict(
        binary_sha256="binary",
        manifest_sha256="manifest",
        host_binding=BINDING,
        workers=2,
        concurrency=1,
        requests=8,
        blocks=2,
        max_median_drift=0.02,
        max_p95_drift=0.10,
        runs=rows,
        same_binary_control=assess(rows, 2, 0.02, 0.10),
    )


class ReplayGateTests(unittest.TestCase):
    def checked(self, control, **changes):
        return validate_host_control(
            control,
            binary_sha256=changes.get("binary", "binary"),
            manifest_sha256=changes.get("manifest", "manifest"),
            workers=changes.get("workers", 2),
            binding=changes.get("binding", BINDING),
        )

    def test_matching_passing_control_is_accepted(self):
        self.assertEqual(len(self.checked(passing_control())), 64)

    def test_changed_binary_fixture_host_or_affinity_is_rejected(self):
        for change in (
            {"binary": "other"},
            {"manifest": "other"},
            {"workers": 4},
            {"binding": {**BINDING, "boot_id": "other"}},
            {"binding": {**BINDING, "affinity": [1, 3]}},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.checked(passing_control(), **change)

    def test_failed_tampered_or_weak_control_is_rejected(self):
        for change in (
            {"same_binary_control": {"passed": True}},
            {"max_median_drift": 0.50},
            {"requests": 4},
            {"runs": passing_control()["runs"][:-1]},
        ):
            with self.subTest(change=tuple(change)), self.assertRaises(ValueError):
                self.checked(passing_control() | change)

    def test_tampered_summary_disagrees_with_request_samples(self):
        control = passing_control()
        control["runs"][0]["p50_ns"] = 990
        control["same_binary_control"] = assess(control["runs"], 2, 0.02, 0.10)
        with self.assertRaisesRegex(
            ValueError, "inconsistent verified request timings"
        ):
            self.checked(control)

    def test_missing_linux_boot_or_exact_affinity_is_rejected(self):
        for binding in (
            {**BINDING, "boot_id": None},
            {**BINDING, "affinity": None},
            {**BINDING, "affinity": [2, 4, 6]},
        ):
            with self.subTest(binding=binding), self.assertRaises(ValueError):
                self.checked(passing_control(), binding=binding)

    def test_failed_gate_does_not_create_output_or_launch_proofs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = root / "fixtures"
            fixture.mkdir()
            entries = []
            for index in range(28):
                name = f"pinned-{index}"
                (fixture / name).write_bytes(bytes([index]))
                entries.append(
                    f"{hashlib.sha256(bytes([index])).hexdigest()}  {name}\n"
                )
            manifest = root / "fixtures.sha256"
            manifest.write_text("".join(entries))
            upstream, candidate = root / "upstream", root / "candidate"
            upstream.write_bytes(b"upstream")
            candidate.write_bytes(b"candidate")
            control = passing_control()
            control["binary_sha256"] = "wrong"
            receipt = root / "control.json"
            receipt.write_text(json.dumps(control))
            output = root / "replay-output"
            args = SimpleNamespace(
                upstream=upstream,
                candidate=candidate,
                fixtures=fixture,
                manifest=manifest,
                host_control_report=receipt,
                output=output,
                workers=2,
                requests=8,
                blocks=4,
            )
            with (
                patch("replay.host_binding", return_value=BINDING),
                patch(
                    "replay.subprocess.Popen",
                    side_effect=AssertionError("prover launched"),
                ),
                self.assertRaisesRegex(ValueError, "different upstream binary"),
            ):
                run(args)
            self.assertFalse(output.exists())

    def test_identical_binaries_are_rejected_before_host_gate_or_proofs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = root / "fixtures"
            fixture.mkdir()
            entries = []
            for index in range(28):
                name = f"pinned-{index}"
                content = bytes([index])
                (fixture / name).write_bytes(content)
                entries.append(f"{hashlib.sha256(content).hexdigest()}  {name}\n")
            manifest = root / "fixtures.sha256"
            manifest.write_text("".join(entries))
            upstream, candidate = root / "upstream", root / "candidate"
            upstream.write_bytes(b"same binary")
            candidate.write_bytes(b"same binary")
            output = root / "replay-output"
            args = SimpleNamespace(
                upstream=upstream,
                candidate=candidate,
                fixtures=fixture,
                manifest=manifest,
                host_control_report=root / "missing-control.json",
                output=output,
                workers=2,
                requests=8,
                blocks=4,
            )
            with self.assertRaisesRegex(ValueError, "binaries are identical"):
                run(args)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
