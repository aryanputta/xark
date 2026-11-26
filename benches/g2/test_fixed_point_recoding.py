"""Exhaust small residue rings and compare the scalar action with an oracle."""

from collections import Counter
import random
import unittest

from bn254_twist_frobenius import GENERATOR, R, point_add, point_neg, psi_squared, scalar_mul
from fixed_point_recoding import (
    HEX_WINDOWS,
    INT_RADIX,
    INT_WINDOWS,
    KERNEL_GENERATOR,
    PHI_EIGENVALUE,
    RADIX,
    RADIX_NORM,
    UNITS,
    ZERO,
    conjugate,
    evaluate,
    hex_buckets,
    hex_lookup,
    integer_buckets,
    integer_lookup,
    lift,
    multiply,
    norm,
    recode_hex,
    recode_integer,
    residue,
)


class FixedPointRecodingTests(unittest.TestCase):
    def test_fan_integer_corrected_coverage_and_carry(self):
        buckets = integer_buckets()
        table = integer_lookup()
        self.assertEqual(len(buckets), 448)
        self.assertEqual(max(b - a for a, b in zip(buckets, buckets[1:])), 6)
        self.assertEqual(set(table), set(range(INT_RADIX)))
        for key, (bucket, multiplier) in table.items():
            self.assertIn(bucket, buckets)
            self.assertIn(abs(multiplier), (1, 2, 3))
            self.assertEqual(bucket * multiplier % INT_RADIX, key)

        # This exact bound gives an integer top residual of at most one in magnitude.
        self.assertLess(4 * R, INT_RADIX**INT_WINDOWS)
        self.assertLess(6 * INT_RADIX, 7 * (INT_RADIX - 1))
        rng = random.Random(750)
        edges = (0, 1, 1024, INT_RADIX**23 - 1, -1, R, R - 1)
        for scalar in (*edges, *(rng.randrange(R) for _ in range(128))):
            digits, tail = recode_integer(scalar)
            reconstructed = tail
            for bucket, multiplier in reversed(digits):
                reconstructed = reconstructed * INT_RADIX + bucket * multiplier
            self.assertLessEqual(abs(tail), 1)
            self.assertEqual(reconstructed, scalar % R)

    def test_hexagon_quotient_coverage_and_prime_strata(self):
        buckets = hex_buckets()
        table = hex_lookup()
        self.assertEqual(len(buckets), 2802)
        self.assertEqual(set(table), set(range(RADIX_NORM)))
        self.assertEqual(norm(RADIX), RADIX_NORM)
        self.assertLessEqual(3 * max(map(norm, buckets)), RADIX_NORM)

        counts = Counter()
        for bucket in buckets[1:]:
            self.assertGreater(bucket[0], bucket[1])
            self.assertGreaterEqual(bucket[1], 0)
            for unit in UNITS:
                digit = multiply(bucket, unit)
                self.assertEqual(table[residue(digit)], (bucket, unit))
            n = 0
            a, b = multiply(bucket, (3, 1))  # conjugate of 2 - omega
            while not (a % 7 or b % 7):
                n += 1
                a, b = multiply((a // 7, b // 7), (3, 1))
            counts[n] += 1
        self.assertEqual(counts, {0: 2401, 1: 343, 2: 49, 3: 7, 4: 1})

    def test_bn254_hexagonal_reconstruction_and_zero_tail(self):
        self.assertEqual(norm(KERNEL_GENERATOR), R)
        self.assertEqual(evaluate(KERNEL_GENERATOR), 0)
        self.assertEqual((PHI_EIGENVALUE**2 + PHI_EIGENVALUE + 1) % R, 0)
        self.assertEqual(RADIX, multiply(multiply((2, -1), (3, -5)), (3, -5)))
        self.assertLess(8100 * R, RADIX_NORM**HEX_WINDOWS)
        self.assertGreater(RADIX_NORM, 128**2)
        self.assertLess(5**2, 3 * 3**2)
        self.assertLess(5 * 127 + 90 * 3 * 128, 90 * 5 * 127)

        rng = random.Random(1902)
        edges = (0, 1, -1, R // 2, R, R - 1, 2**254 - 1)
        for scalar in (*edges, *(rng.randrange(R) for _ in range(512))):
            digits, tail = recode_hex(scalar)
            self.assertEqual(tail, ZERO)
            reconstructed = tail
            for bucket, unit in reversed(digits):
                a, b = multiply(reconstructed, RADIX)
                x, y = multiply(bucket, unit)
                reconstructed = a + x, b + y
            self.assertEqual(reconstructed, lift(scalar))
            self.assertEqual(evaluate(reconstructed), scalar % R)
            self.assertLessEqual(4 * norm(reconstructed), 3 * R)

    def test_endomorphism_action_matches_direct_group_multiplication(self):
        for multiple in (0, 1, -1, 23):
            point = scalar_mul(multiple, GENERATOR)
            self.assertEqual(point_neg(psi_squared(point)), scalar_mul(PHI_EIGENVALUE, point))
        self.assertEqual(multiply(RADIX, conjugate(RADIX)), (RADIX_NORM, 0))

    def test_hex_digits_and_shifted_bases_match_direct_msm(self):
        def act(coefficient, point):
            a, b = coefficient
            phi = point_neg(psi_squared(point))
            return point_add(scalar_mul(a, point), scalar_mul(b, phi))

        expected, actual = None, None
        for scalar, multiple in ((R // 2, 5), (R - 1, 5), (2**253 + 43, 19), (1, 0)):
            point = scalar_mul(multiple, GENERATOR)
            expected = point_add(expected, scalar_mul(scalar, point))
            digits, tail = recode_hex(scalar)
            self.assertEqual(tail, ZERO)
            for bucket, unit in digits:
                actual = point_add(actual, act(bucket, act(unit, point)))
                point = act(RADIX, point)
        self.assertEqual(actual, expected)
