"""Regression checks for parsed proof receipt numbers."""

import unittest

from verify_soak import rows


class ReceiptNumberTests(unittest.TestCase):
    def test_single_capture_preserves_whole_nanosecond_value(self) -> None:
        line = "proving key validation: complete duration_ns=1123965042\n"
        self.assertEqual(
            rows(r"^proving key validation: complete duration_ns=(\d+)$", line),
            [(1123965042,)],
        )

    def test_multiple_captures_preserve_receipt_fields(self) -> None:
        self.assertEqual(
            rows(
                r"^request verified index=(\d+) fixture=(\d+)$",
                "request verified index=12 fixture=3\n",
            ),
            [(12, 3)],
        )


if __name__ == "__main__":
    unittest.main()
