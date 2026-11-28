"""ABBA build-mode audit rejects host drift and changed build identity."""

import csv
import json
import tempfile
import unittest
from pathlib import Path

from run import summarize
from xark_modes_gate import ORDER, audit


class XarkModesGateTests(unittest.TestCase):
    def make_receipts(self, root, *, drift=False):
        for mode in ("portable", "tuned"):
            (root / f"{mode}-build-manifest.json").write_text(json.dumps({
                "source_commit": "a" * 40,
                "binary_sha256": mode,
                "rustflags": None if mode == "portable" else "-C target-feature=+adx,+bmi2",
            }))
        for name in ORDER:
            directory = root / name
            directory.mkdir(exist_ok=True)
            mode = name.split("-")[0]
            rows = []
            summary = []
            for workload in ("escrow", "withdrawal"):
                values = []
                for pair in (1, 2):
                    times = [100, 101, 102]
                    if drift and name == "tuned-b" and workload == "withdrawal":
                        times = [120, 121, 122]
                    values.extend(times)
                    for index, value in enumerate(times, 1):
                        rows.append({
                            "workload": workload, "pair": pair, "backend": "xark",
                            "arm": "xark", "lane": "checked-resident-proof",
                            "metric": "proof", "sample": index, "duration_ns": value,
                        })
                summary.append({
                    "workload": workload, "competitor": "xark", "backend": "xark",
                    "metric": "proof", **summarize(values),
                })
            report = {
                "status": "verified", "competitors": ["xark"],
                "workloads": ["escrow", "withdrawal"],
                "xark_build_provenance": "self_consistent",
                "contention": {"flagged_steps": []},
                "budget": {"pairs": 2, "samples": 3, "threads": 2, "warmups": 3},
                "hardware": {"cpu": "test", "affinity": [1, 2]},
                "sources": {"xark": {"commit": "a" * 40}},
                "artifacts": {
                    "bench": {"sha256": mode},
                    "escrow/circuit.xbc": {"sha256": "escrow"},
                    "withdrawal/circuit.xbc": {"sha256": "withdrawal"},
                },
                "summary": summary,
            }
            (directory / "report.json").write_text(json.dumps(report))
            with (directory / "samples.csv").open("w", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=rows[0])
                writer.writeheader()
                writer.writerows(rows)

    def test_eligible_and_unstable_receipts(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            self.make_receipts(root)
            result = audit(root, 3)
            self.assertTrue(result["eligible"])
            self.assertEqual(result["sample_count"], 48)
            self.make_receipts(root, drift=True)
            self.assertFalse(audit(root, 3)["eligible"])

    def test_changed_source_or_report_is_rejected(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            self.make_receipts(root)
            path = root / "tuned-b/report.json"
            report = json.loads(path.read_text())
            report["sources"]["xark"]["commit"] = "b" * 40
            path.write_text(json.dumps(report))
            with self.assertRaisesRegex(ValueError, "source, build, or fixture identity"):
                audit(root, 3)
            report["sources"]["xark"]["commit"] = "a" * 40
            report["summary"][0]["p50_ns"] += 1
            path.write_text(json.dumps(report))
            with self.assertRaisesRegex(ValueError, "aggregate disagrees"):
                audit(root, 3)


if __name__ == "__main__":
    unittest.main()
