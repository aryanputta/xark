"""Regression tests for accepting or rejecting adapter receipts."""

import tempfile
import unittest
from pathlib import Path

from run import candidate_lanes, changed_oracle, proof_samples, query_samples, summarize


class ReceiptTests(unittest.TestCase):
    def test_gnark_candidate_requires_explicit_lane_and_single_line_receipt(self):
        self.assertEqual(candidate_lanes({}), [])
        self.assertEqual(candidate_lanes({"candidate": {}}), ["xark"])
        self.assertEqual(
            candidate_lanes(
                {
                    "candidate": {
                        "lanes": ["xark", "gnark"],
                        "receipt": "configured mode",
                    }
                }
            ),
            ["xark", "gnark"],
        )
        for candidate in (
            {"lanes": ["gnark"]},
            {"lanes": ["gnark"], "receipt": "mode\nother mode"},
            {"lanes": ["gnark", "gnark"], "receipt": "mode"},
            {"lanes": ["rapidsnark"], "receipt": "mode"},
            {"lanes": "gnark", "receipt": "mode"},
        ):
            with self.assertRaises(ValueError):
                candidate_lanes({"candidate": candidate})

    def test_xark_requires_positive_timing_and_rejection(self):
        log = (
            "resident includes row checks: true\n"
            "changed statement rejected by Arkworks and Xark for each backend\n"
            "warm prove: xark-groth16 0.365733s\n"
        )
        self.assertEqual(proof_samples(log, "xark", 1, 2, True), {"proof": [365733000]})
        for bad in (
            log.replace("rejected", "accepted"),
            log.replace("0.365733", "0"),
            log * 2,
        ):
            with self.assertRaises(ValueError):
                proof_samples(bad, "xark", 1, 2, True)

    def test_gnark_requires_reported_threads(self):
        log = (
            "verified constraints=7626 wires=7606 threads=2\n"
            "changed statement rejected by Gnark\n"
            "gnark_prove_ns=316146394\n"
        )
        self.assertEqual(
            proof_samples(log, "gnark", 1, 2, True), {"proof": [316146394]}
        )
        with self.assertRaises(ValueError):
            proof_samples(log, "gnark", 1, 1, True)

    def test_rapidsnark_checks_fixed_pool_and_verification_count(self):
        log = (
            "OpenMP thread limit: 2\n"
            "OS CPU count reported to the process: 2\n"
            "verified 1 proofs with snarkjs\n"
            "changed statement rejected by snarkjs\n"
            "warm prove: rapidsnark 1.307261s\n"
        )
        self.assertEqual(
            proof_samples(log, "rapidsnark", 1, 2, False), {"proof": [1307261000]}
        )
        with self.assertRaises(ValueError):
            proof_samples(
                log.replace("reported to the process: 2", "reported to the process: 8"),
                "rapidsnark",
                1,
                2,
                False,
            )

    def test_query_preserves_groups_and_rejects_repeated_indices(self):
        b1 = "query msm icicle: query=b1 sample=1 icicle_ns=12\n"
        b2 = "query msm icicle: query=b2 sample=1 icicle_ns=40\n"
        check = (
            "query msm icicle verified: terms=7606 thread_cap=2 samples=1 "
            "bundle=XKQMSM01 reference=arkworks backend=CPU:0 precompute_factor=1 "
            "batch_size=1 canonical_host=1 async=0\n"
        )
        log = check + b1 + b2
        self.assertEqual(
            query_samples(log, "icicle", ("b1", "b2"), 1, 2), {"b1": [12], "b2": [40]}
        )
        for bad in (
            log + b2,
            log.replace("thread_cap=2", "thread_cap=3"),
            log.replace(b2, ""),
        ):
            with self.assertRaises(ValueError):
                query_samples(bad, "icicle", ("b1", "b2"), 1, 2)

    def test_control_changes_only_expected_b1_bytes(self):
        header = b"XKQMSM01" + (1).to_bytes(4, "little")
        point = bytes(range(1, 65))
        row = bytes(32) + point + bytes(128)
        expected_b2 = bytes(range(128))
        contents = header + row + bytes(64) + expected_b2
        with tempfile.TemporaryDirectory() as scratch:
            directory = Path(scratch)
            vector = directory / "original.bin"
            vector.write_bytes(contents)
            amended = changed_oracle(vector, directory, "b1")
            self.assertEqual(amended.read_bytes(), header + row + point + expected_b2)
            self.assertEqual(vector.read_bytes(), contents)

    def test_tail_suppressed_when_sample_count_is_small(self):
        self.assertIsNone(summarize([12, 20])["p95_ns"])
        self.assertEqual(summarize(list(range(1, 31)))["p95_ns"], 29)


if __name__ == "__main__":
    unittest.main()
