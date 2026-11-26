"""Test the evidence parser and acceptance gates."""

import io
from pathlib import Path
import tarfile
import tempfile
import unittest

from reconstruct import members, parse
from tune import ratios, stable


class G2EvidenceTests(unittest.TestCase):
    def test_query_receipt_is_required(self):
        sample = "query msm gnark: query=b2 sample=1 gnark_ns=84701234"
        with self.assertRaisesRegex(ValueError, "missing query parity"):
            parse("gnark-query", "withdrawal-1-gnark.log", sample)
        rows = parse(
            "gnark-query",
            "withdrawal-1-gnark.log",
            "query msm gnark verified: terms=5406\n" + sample,
        )
        self.assertEqual((rows[0]["metric"], rows[0]["duration"]), ("b2", 84701234))

    def test_archive_rejects_path_traversal_and_links(self):
        for name, kind in (("../file", tarfile.REGTYPE), ("link", tarfile.SYMTYPE)):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                path = Path(temp) / "input.tar.gz"
                with tarfile.open(path, mode="w:gz") as archive:
                    member = tarfile.TarInfo(name)
                    member.type = kind
                    archive.addfile(member, io.BytesIO())
                with self.assertRaises(ValueError):
                    list(members(path))

    def test_tuner_preserves_order_specific_tail_regressions(self):
        traces = dict(
            comparisons=[
                dict(
                    workload="withdrawal",
                    pair=1,
                    arm_statistics={
                        "xark": {"b2": {"p50_ns": 100, "p95_ns": 120}},
                        "xark-candidate": {"b2": {"p50_ns": 75, "p95_ns": 130}},
                    },
                ),
            ]
        )
        pairs = ratios(traces, "withdrawal", "b2")
        self.assertEqual(pairs[0]["p50"], 0.75)
        self.assertFalse(stable(pairs, 0.80))
        traces["comparisons"][0]["arm_statistics"]["xark-candidate"]["b2"][
            "p95_ns"
        ] = 121
        self.assertTrue(stable(ratios(traces, "withdrawal", "b2"), 0.80))


if __name__ == "__main__":
    unittest.main()
