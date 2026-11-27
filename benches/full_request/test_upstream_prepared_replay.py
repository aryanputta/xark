"""Gate tests; proof correctness is exercised by the real replay binaries."""

import unittest

from batch_parser import parse
from upstream_prepared_replay import control_failures


def controls():
    return [
        {
            "circuit": circuit,
            "arm": arm,
            "service_p50_ns": 1000,
            "service_p95_ns": 1200,
        }
        for circuit in ("escrow", "withdrawal")
        for arm in ("upstream", "prepared")
        for _ in range(2)
    ]


class ReplayGateTests(unittest.TestCase):
    def test_stable_pairs_pass(self):
        self.assertEqual(control_failures(controls()), [])

    def test_missing_arm_cannot_pass(self):
        rows = controls()
        rows.pop()
        self.assertEqual(control_failures(rows)[0]["reason"], "missing pair")

    def test_tail_drift_rejects_even_with_stable_median(self):
        rows = controls()
        rows[-1]["service_p95_ns"] = 1400
        self.assertEqual(control_failures(rows)[0]["arm"], "prepared")

    def test_receipt_requires_altered_and_cross_request_rejection(self):
        text = (
            "request wave first=0 count=1 active_ns=100\n"
            "request verified index=0 fixture=0 service_ns=90\n"
            "requests verified mode=cpu concurrency=1 threads=1 count=1 "
            "setup_ns=50 altered=rejected cross_request=accepted\n"
        )
        with self.assertRaises(ValueError):
            parse(text, "cpu", 1, 1, 1)


if __name__ == "__main__":
    unittest.main()
