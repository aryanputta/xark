import unittest

from replay import control_failures, parse, summarize


class ReceiptTest(unittest.TestCase):
    def test_complete_receipt(self):
        lines = [f"request verified index={i} fixture={i % 4} service_ns={i + 1}" for i in range(8)]
        lines.append("requests verified mode=cpu concurrency=1 threads=2 count=8 setup_ns=10 altered=rejected cross_request=rejected")
        self.assertEqual(parse(lines, 8, 2), (10, list(range(1, 9))))

    def test_rejects_incomplete_or_reordered_receipt(self):
        lines = [f"request verified index={i} fixture=0 service_ns={i + 1}" for i in range(8)]
        lines.append("requests verified mode=cpu concurrency=1 threads=2 count=8 setup_ns=10 altered=rejected cross_request=rejected")
        with self.assertRaises(ValueError):
            parse(lines, 8, 2)
        with self.assertRaises(ValueError):
            parse(lines[:7] + lines[-1:], 8, 2)

    def test_host_control_rejects_drift(self):
        rows = []
        for circuit in ("escrow", "withdrawal"):
            for arm in ("upstream", "prepared"):
                rows.extend([{"circuit": circuit, "arm": arm, "p50_ns": 100, "p95_ns": 100},
                             {"circuit": circuit, "arm": arm, "p50_ns": 103 if circuit == "escrow" and arm == "prepared" else 100, "p95_ns": 100}])
        self.assertEqual(len(control_failures(rows)), 1)

    def test_break_even_requires_eligible_replay(self):
        rows = [
            {"circuit": circuit, "arm": arm, "services_ns": [100 if arm == "upstream" else 80],
             "setup_ns": 1000 if arm == "upstream" else 1200, "peak_rss_bytes": 1}
            for circuit in ("escrow", "withdrawal") for arm in ("upstream", "prepared")
        ]
        self.assertIsNone(summarize(rows, False)["escrow"]["break_even_requests"])
        self.assertEqual(summarize(rows, True)["escrow"]["break_even_requests"], 10)


if __name__ == "__main__":
    unittest.main()
