"""The competitor gate checks raw samples before accepting a timing claim."""

import csv
import json
import tempfile
import unittest
from pathlib import Path

from gnark_gate import audit
from run import summarize


class GnarkGateTests(unittest.TestCase):
    def write_receipt(self, root, *, unstable=False):
        rows = []
        summary = []
        for workload in ("escrow", "withdrawal"):
            for backend in ("xark", "gnark"):
                all_times = []
                for pair in (1, 2):
                    times = [100, 101, 102]
                    if unstable and workload == "withdrawal" and backend == "gnark" and pair == 2:
                        times = [120, 121, 122]
                    all_times.extend(times)
                    for sample, value in enumerate(times, 1):
                        rows.append(
                            {
                                "workload": workload,
                                "backend": backend,
                                "pair": pair,
                                "sample": sample,
                                "duration_ns": value,
                                "metric": "proof",
                                "lane": "checked-resident-proof",
                            }
                        )
                summary.append(
                    {
                        "workload": workload,
                        "backend": backend,
                        "competitor": "gnark",
                        "metric": "proof",
                        **summarize(all_times),
                    }
                )
        report = {
            "status": "verified",
            "competitors": ["gnark"],
            "workloads": ["escrow", "withdrawal"],
            "xark_build_provenance": "self_consistent",
            "contention": {"flagged_steps": []},
            "budget": {"pairs": 2, "samples": 3},
            "summary": summary,
        }
        (root / "report.json").write_text(json.dumps(report))
        with (root / "samples.csv").open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=rows[0])
            writer.writeheader()
            writer.writerows(rows)

    def test_eligible_raw_receipt(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            self.write_receipt(root)
            result = audit(root, 2, 3)
            self.assertTrue(result["eligible"])
            self.assertEqual(result["samples_audited"], 24)

    def test_unstable_same_binary_control_stops_claim(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            self.write_receipt(root, unstable=True)
            result = audit(root, 2, 3)
            self.assertFalse(result["eligible"])
            self.assertGreater(
                next(
                    row["p50_drift"]
                    for row in result["controls"]
                    if row["workload"] == "withdrawal" and row["backend"] == "gnark"
                ),
                0.02,
            )

    def test_tampered_report_is_rejected(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            self.write_receipt(root)
            report = json.loads((root / "report.json").read_text())
            report["summary"][0]["p50_ns"] += 1
            (root / "report.json").write_text(json.dumps(report))
            with self.assertRaisesRegex(ValueError, "disagrees with raw samples"):
                audit(root, 2, 3)


if __name__ == "__main__":
    unittest.main()
