"""Exact arithmetic regression checks independent of the Rust implementation."""

from fractions import Fraction
import random
import unittest

from model import (
    FQ,
    FR,
    RADIX,
    break_even,
    end_to_end_bound,
    endpoint_batch_inverse,
    fixed_schedule_join_gain,
    fq2_inverse,
    fq2_mul,
    fq2_square,
    max_fused_products,
    montgomery_reduce,
    signed_digits,
    window_cost,
)


class ExactModelTests(unittest.TestCase):
    def test_fused_montgomery_bound_and_boundary_products(self):
        inverse = pow(RADIX, -1, FQ)
        k = max_fused_products()
        self.assertEqual(k, 5)
        maximum = (FQ - 1) ** 2
        product_sum = k * maximum
        self.assertEqual(montgomery_reduce(product_sum), product_sum * inverse % FQ)
        with self.assertRaises(ValueError):
            montgomery_reduce((k + 1) * maximum)
        factors = [0, 1, FQ // 2, FQ - 2, FQ - 1]
        for a in factors:
            for b in factors:
                total = a * b + (FQ - a - 1) * (FQ - b - 1)
                self.assertEqual(montgomery_reduce(total), total * inverse % FQ)

    def test_fq2_square_inverse_and_batches(self):
        rng = random.Random(947)
        values = [(1, 0), (0, 1), (FQ - 1, FQ - 1)]
        values += [(rng.randrange(FQ), rng.randrange(FQ)) for _ in range(30)]
        for value in values:
            self.assertEqual(fq2_square(value), fq2_mul(value, value))
            self.assertEqual(fq2_mul(value, fq2_inverse(value)), (1, 0))
        for n in (0, 1, 2, 3, 17, len(values)):
            inverses, products = endpoint_batch_inverse(values[:n])
            self.assertEqual(inverses, [fq2_inverse(value) for value in values[:n]])
            self.assertEqual(products, max(0, 3 * (n - 1)))

    def test_radix_reconstruction_at_scalar_boundaries(self):
        for width in (2, 5, 8, 12, 16):
            for value in (0, 1, (1 << width) - 1, 1 << width, FR - 1):
                digits = signed_digits(value, width)
                self.assertEqual(
                    sum(digit << (width * i) for i, digit in enumerate(digits)), value
                )
                self.assertTrue(
                    all(abs(digit) <= (1 << (width - 1)) for digit in digits)
                )
                self.assertLessEqual(
                    len(digits), window_cost(254, width, 5406)["windows_upper_bound"]
                )

    def test_fixed_schedule_join_saturates_at_the_next_task(self):
        self.assertEqual(fixed_schedule_join_gain(5, 10, 18, Fraction(1, 5)), 0)
        self.assertEqual(fixed_schedule_join_gain(5, 10, 14, Fraction(2, 5)), 1)
        self.assertEqual(fixed_schedule_join_gain(5, 10, 2, Fraction(1, 5)), 2)
        with self.assertRaises(ValueError):
            fixed_schedule_join_gain(5, 10, 2, Fraction(6, 5))

    def test_estimates_do_not_mix_setup_and_repeated_cost(self):
        self.assertEqual(break_even(10, 3), 4)
        with self.assertRaises(ValueError):
            break_even(10, 0)
        self.assertEqual(end_to_end_bound(Fraction(2, 5), 2), Fraction(5, 4))


if __name__ == "__main__":
    unittest.main()
