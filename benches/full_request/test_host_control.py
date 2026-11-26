import unittest

from host_control import assess


def matrix():
    return [
        dict(fixture=fixture, block=block, arm=arm, p50_ns=1000, p95_ns=1200)
        for fixture in ("escrow", "withdrawal")
        for block in (1, 2)
        for arm in ("A", "B")
    ]


class HostControlTests(unittest.TestCase):
    def test_identical_runs_pass(self):
        result = assess(matrix(), 2, 0.02, 0.10)
        self.assertTrue(result["passed"])
        self.assertEqual(len(result["pairs"]), 4)

    def test_one_noisy_tail_rejects_the_host(self):
        rows = matrix()
        rows[1]["p95_ns"] = 1500
        result = assess(rows, 2, 0.02, 0.10)
        self.assertFalse(result["passed"])
        self.assertFalse(result["pairs"][0]["passed"])

    def test_missing_or_duplicate_arm_cannot_pass(self):
        rows = matrix()
        with self.assertRaisesRegex(ValueError, "incomplete"):
            assess(rows[:-1], 2, 0.02, 0.10)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            assess(rows + rows[:1], 2, 0.02, 0.10)


if __name__ == "__main__":
    unittest.main()
