import unittest

from paired import UPSTREAM_MARKER, parse


class ReceiptTest(unittest.TestCase):
    def test_matched_upstream_receipt(self):
        lines = [f"request verified index={i} fixture={i % 4} service_ns={i + 1}" for i in range(8)]
        lines.append("requests verified mode=cpu concurrency=1 threads=2 count=8 setup_ns=10 altered=rejected cross_request=rejected")
        self.assertEqual(parse(lines, "upstream", 8), (10, list(range(1, 9))))
        self.assertEqual(UPSTREAM_MARKER, "upstream timed self-check and serialization: 1")

    def test_prepared_receipt(self):
        lines = [f"sample proof={i} fixture={i % 4} request_ns={i + 1} verified=true" for i in range(8)]
        lines.append("typed requests mode=prepared measured=8 warmups=1 setup_ns=11 altered=rejected cross_request=rejected")
        self.assertEqual(parse(lines, "prepared", 8), (11, list(range(1, 9))))

    def test_rejects_missing_or_reordered_proofs(self):
        lines = [f"sample proof={i} fixture=0 request_ns={i + 1} verified=true" for i in range(8)]
        lines.append("typed requests mode=prepared measured=8 warmups=1 setup_ns=11 altered=rejected cross_request=rejected")
        with self.assertRaises(ValueError):
            parse(lines, "prepared", 8)
        with self.assertRaises(ValueError):
            parse(lines[:7] + lines[-1:], "prepared", 8)


if __name__ == "__main__":
    unittest.main()
