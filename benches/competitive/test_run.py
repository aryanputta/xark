"""Regression tests for accepting or rejecting adapter receipts."""

import os
import tempfile
import unittest
from pathlib import Path

from run import (
    changed_oracle,
    contention_flagged,
    proof_samples,
    query_samples,
    summarize,
)


class ReceiptTests(unittest.TestCase):
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
            "query msm icicle verified: terms=7606 thread_cap=2 samples=1 warmups=0 "
            "backend=CPU:0 precompute_factor=1 batch_size=1 canonical_host=1 async=0 "
            "bundle=XKQMSM01 reference=arkworks\n"
        )
        log = check + b1 + b2
        self.assertEqual(
            query_samples(log, "icicle", ("b1", "b2"), 1, 2), {"b1": [12], "b2": [40]}
        )
        for bad in (
            log + b2,
            log + check,
            log.replace("CPU:0", "CUDA:0"),
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

    def test_nearest_rank_tails_and_median(self):
        self.assertEqual(
            summarize([20, 12]),
            {
                "count": 2,
                "p50_ns": 16,
                "p95_ns": 20,
                "p99_ns": 20,
            },
        )
        samples = summarize(list(range(1, 121)))
        self.assertEqual((samples["p95_ns"], samples["p99_ns"]), (114, 119))

    def test_contention_requires_successful_observations(self):
        self.assertFalse(
            contention_flagged({"polls": 1, "error": None, "observed": []})
        )
        self.assertTrue(contention_flagged({"polls": 0, "error": None, "observed": []}))
        self.assertTrue(
            contention_flagged({"polls": 1, "error": "ps denied", "observed": []})
        )
        self.assertTrue(
            contention_flagged({"polls": 1, "error": None, "observed": [{"pid": 4}]})
        )

    def test_wrong_b2_preserves_b1_oracle_and_source(self):
        header = b"XKQMSM01" + (1).to_bytes(4, "little")
        point = bytes(range(1, 129))
        row = bytes(96) + point
        b1_oracle = bytes(range(64))
        contents = header + row + b1_oracle + bytes(128)
        with tempfile.TemporaryDirectory() as scratch:
            directory = Path(scratch)
            vector = directory / "original.bin"
            vector.write_bytes(contents)
            wrong = changed_oracle(vector, directory, "b2")
            self.assertEqual(wrong.read_bytes(), header + row + b1_oracle + point)
            self.assertEqual(vector.read_bytes(), contents)


@unittest.skipUnless(
    os.environ.get("XARK_ARCHIVED_RECEIPTS"),
    "set XARK_ARCHIVED_RECEIPTS for real archived runs",
)
class ArchivedReceiptTests(unittest.TestCase):
    def test_all_paired_process_arms(self):
        root = Path(os.environ["XARK_ARCHIVED_RECEIPTS"])
        lanes = (
            ("2026-11-25-colab-x86-versus-gnark", "gnark", "gnark", "targeted", ()),
            (
                "2026-11-25-colab-rapidsnark-resident",
                "rapidsnark",
                "rapids",
                "xark",
                (),
            ),
            (
                "2026-11-26-colab-constantine-b1",
                "constantine",
                "constantine",
                "xark",
                ("b1",),
            ),
            ("2026-11-26-colab-icicle-query", "icicle", "icicle", "xark", ("b1", "b2")),
        )
        for dirname, competitor, competitor_label, xark_label, queries in lanes:
            for workload, terms in (("escrow", 7606), ("withdrawal", 5406)):
                for index in range(1, 5):
                    base = root / dirname / f"{workload}-{index}"
                    paths = [
                        (backend, Path(f"{base}-{label}.log"))
                        for backend, label in (
                            ("xark", xark_label),
                            (competitor, competitor_label),
                        )
                    ]
                    with self.subTest(lane=competitor, fixture=workload, arm=index):
                        existing = [
                            (backend, path) for backend, path in paths if path.is_file()
                        ]
                        self.assertEqual(len(existing), 1)
                        backend, path = existing[0]
                        receipt = path.read_text()
                        if queries:
                            samples = query_samples(
                                receipt, backend, queries, 30, 2, 3, terms
                            )
                        else:
                            samples = proof_samples(
                                receipt, backend, 30, 2, competitor != "rapidsnark"
                            )
                        self.assertTrue(
                            all(len(timings) == 30 for timings in samples.values())
                        )


if __name__ == "__main__":
    unittest.main()
