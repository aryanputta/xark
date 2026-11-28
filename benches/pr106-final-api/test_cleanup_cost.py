import unittest

from cleanup_cost import COMMITS, ORDERS, control_failures, summarize


class CleanupCostTest(unittest.TestCase):
    def test_orders_balance_arm_positions(self):
        self.assertEqual(len(ORDERS), 6)
        for arm in COMMITS:
            self.assertEqual([order.index(arm) for order in ORDERS].count(0), 2)
            self.assertEqual([order.index(arm) for order in ORDERS].count(1), 2)
            self.assertEqual([order.index(arm) for order in ORDERS].count(2), 2)

    def test_control_rejects_only_unstable_pair(self):
        rows = []
        for circuit in ("escrow", "withdrawal"):
            for arm in COMMITS:
                for block, p95 in ((1, 100), (2, 100)):
                    rows.append({"circuit": circuit, "arm": arm, "p50_ns": 100,
                                 "p95_ns": p95, "tag": f"{circuit}-{arm}-{block}"})
        self.assertEqual(control_failures(rows), [])
        rows[-1]["p95_ns"] = 111
        self.assertEqual(control_failures(rows),
                         ["withdrawal/guarded: p50 or p95 drift exceeded 2% / 10%"])

    def test_summary_keeps_cleanup_and_guard_deltas_separate(self):
        rows = []
        for circuit in ("escrow", "withdrawal"):
            for arm, value in (("before", 100), ("cleanup", 105), ("guarded", 107)):
                rows.append({"circuit": circuit, "arm": arm, "services_ns": [value] * 4,
                             "setup_ns": value * 10, "peak_rss_bytes": value * 100})
        result = summarize(rows)["escrow"]["deltas"]
        self.assertEqual(result["before_to_cleanup"]["p50_delta_ns"], 5)
        self.assertEqual(result["cleanup_to_guarded"]["p50_delta_ns"], 2)
        self.assertEqual(result["before_to_guarded"]["p50_delta_ns"], 7)


if __name__ == "__main__":
    unittest.main()
