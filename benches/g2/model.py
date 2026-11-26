#!/usr/bin/env python3
"""Exact-integer oracles and sizing estimates for the BN254 G2 experiments."""

from fractions import Fraction


FQ = int("30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47", 16)
FR = int("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001", 16)
RADIX = 1 << 256


def montgomery_reduce(value):
    if not 0 <= value < FQ * RADIX:
        raise ValueError("Montgomery value is outside the single-subtraction bound")
    low = (-value * pow(FQ, -1, RADIX)) % RADIX
    numerator = value + low * FQ
    assert numerator % RADIX == 0
    quotient = numerator // RADIX
    assert quotient < 2 * FQ
    return quotient - FQ if quotient >= FQ else quotient


def max_fused_products():
    return (FQ * RADIX - 1) // ((FQ - 1) ** 2)


def fq2_mul(left, right):
    a, b = left
    c, d = right
    return (a * c - b * d) % FQ, (a * d + b * c) % FQ


def fq2_square(value):
    a, b = value
    return ((a + b) * (a - b)) % FQ, (2 * a * b) % FQ


def fq2_inverse(value):
    a, b = value
    denominator = pow((a * a + b * b) % FQ, -1, FQ)
    return a * denominator % FQ, -b * denominator % FQ


def endpoint_batch_inverse(values):
    """One inversion and precisely 3(n−1) multiplications for n>0, excluding field normalization."""
    if not values:
        return [], 0
    prefixes = [values[0]]
    for elem in values[1:]:
        prefixes.append(fq2_mul(prefixes[-1], elem))
    inverse = fq2_inverse(prefixes[-1])
    outputs = [None] * len(values)
    for i in range(len(values) - 1, 0, -1):
        outputs[i] = fq2_mul(inverse, prefixes[i - 1])
        inverse = fq2_mul(inverse, values[i])
    outputs[0] = inverse
    return outputs, 3 * (len(values) - 1)


def signed_digits(value, width):
    if value < 0 or not 2 <= width <= 16:
        raise ValueError("expected a nonnegative scalar and a width from 2 to 16")
    base = 1 << width
    digits = []
    while value:
        value, digit = divmod(value, base)
        if digit >= base // 2:
            digit -= base
            value += 1
        digits.append(digit)
    return digits


def window_cost(bits, width, terms):
    if bits <= 0 or terms < 0 or not 2 <= width <= 16:
        raise ValueError("invalid bit, width, or term budget")
    windows = (bits + width) // width
    buckets = 1 << (width - 1)
    return {
        "windows_upper_bound": windows,
        "signed_buckets_per_worker": buckets,
        "insertions_upper_bound": terms * windows,
        "bucket_reduction_additions_upper_bound": 2 * buckets * windows,
        "window_doublings_upper_bound": (windows - 1) * width,
        "g2_affine_coordinate_payload_bytes": buckets * 128,
        "g2_projective_coordinate_payload_bytes": buckets * 192,
    }


def break_even(setup_ns, savings_ns):
    if setup_ns < 0 or savings_ns <= 0:
        raise ValueError(
            "setup must be nonnegative and recurring savings must be positive"
        )
    return (setup_ns + savings_ns - 1) // savings_ns


def end_to_end_bound(serial_fraction, local_speedup):
    """Fixed-work Amdahl prediction from a wall-clock fraction, not a sampled stack fraction."""
    p, s = Fraction(serial_fraction), Fraction(local_speedup)
    if not 0 <= p <= 1 or s < 1:
        raise ValueError("invalid serialized fraction or speedup")
    return 1 / (1 - p + p / s)
