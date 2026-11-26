"""Exact public-input reference for two fixed-point MSM digit alphabets.

Integer buckets follow Fan, Kuchta, Sica and Xu, ePrint 2024/750 §3.
The six-unit Eisenstein construction follows Le and Sica, ePrint 2026/1902
Theorem 1, with a directly enumerated hexagonal fundamental region.
"""

from functools import cache, reduce
from itertools import groupby, pairwise
from math import isqrt
from typing import Mapping

from bn254_twist_frobenius import (
    LAMBDA, OMEGA, P, R, U, Point, nearest, point_add, point_neg,
)

Eisenstein = tuple[int, int]
ZERO = (0, 0)
ONE = (1, 0)
UNITS = (ONE, (0, 1), (-1, -1), (-1, 0), (0, -1), (1, 1))
PHI_EIGENVALUE = -LAMBDA**2 % R
KERNEL_GENERATOR = (6 * U**2 + 4 * U + 1, 2 * U + 1)
RADIX = (-87, -149)  # (2 - omega)**5
RADIX_NORM = 7**5
HEX_WINDOWS = 19
INT_RADIX = 2**11
INT_WINDOWS = 24
OMEGA_SQUARED = OMEGA**2 % P


def valuation(value: int, prime: int) -> int:
    """Return the prime valuation of a positive integer."""
    count = 0
    while value % prime == 0:
        count += 1
        value //= prime
    return count


def integer_buckets() -> tuple[int, ...]:
    base = {
        b for b in range(1, INT_RADIX // 2 + 1)
        if valuation(b, 3) % 2 == 0
    }
    removed_twos = {b for b in base if valuation(b, 2) % 2 == 1}
    removed_threes = {
        INT_RADIX - 3 * b for b in base if b % 2 and b < INT_RADIX // 4
    }
    return (0, *sorted(base - removed_twos - removed_threes))


@cache
def integer_lookup() -> dict[int, tuple[int, int]]:
    table = {0: (0, 1)}
    for bucket in integer_buckets()[1:]:
        for multiplier in (1, -1, 2, -2, 3, -3):
            product = bucket * multiplier
            residue = product % INT_RADIX
            current = table.get(residue)
            if current is None or abs(product) < abs(current[0] * current[1]):
                table[residue] = (bucket, multiplier)
    return table


def recode_integer(scalar: int) -> tuple[tuple[tuple[int, int], ...], int]:
    residual = scalar % R
    table = integer_lookup()
    digits = []
    for _ in range(INT_WINDOWS):
        bucket, multiplier = table[residual % INT_RADIX]
        digits.append((bucket, multiplier))
        residual = (residual - bucket * multiplier) // INT_RADIX
    return tuple(digits), residual


def multiply(x: Eisenstein, y: Eisenstein) -> Eisenstein:
    a, b = x
    c, d = y
    return a * c - b * d, a * d + b * c - b * d


def norm(x: Eisenstein) -> int:
    a, b = x
    return a * a - a * b + b * b


def conjugate(x: Eisenstein) -> Eisenstein:
    a, b = x
    return a - b, -b


def evaluate(x: Eisenstein) -> int:
    return (x[0] + x[1] * PHI_EIGENVALUE) % R


def lift(scalar: int) -> Eisenstein:
    """Reduce the integer scalar modulo the principal subgroup kernel."""
    scalar %= R
    c, d = conjugate(KERNEL_GENERATOR)
    quotient = nearest(scalar * c, R), nearest(scalar * d, R)
    a, b = multiply(KERNEL_GENERATOR, quotient)
    return scalar - a, -b


def residue(x: Eisenstein) -> int:
    """Label a class modulo RADIX by the first inverse-coordinate numerator."""
    return (62 * x[0] - 149 * x[1]) % RADIX_NORM


def hex_buckets() -> tuple[Eisenstein, ...]:
    """Choose one closed-hexagon representative in each six-unit orbit."""
    # Each coordinate squared is at most 4/3 times the Eisenstein norm.
    # The circumradius of the scaled Voronoi hexagon is |RADIX| / sqrt(3).
    limit = isqrt(4 * RADIX_NORM // 9)
    inverse_numerator = conjugate(RADIX)
    buckets = {}
    for a in range(1, limit + 1):
        for b in range(a):  # half-open sector with angle in [0, pi/3)
            point = (a, b)
            x, y = multiply(point, inverse_numerator)
            if max(abs(2 * x - y), abs(2 * y - x), abs(x + y)) <= RADIX_NORM:
                orbit = min(residue(multiply(point, unit)) for unit in UNITS)
                buckets.setdefault(orbit, point)
    return (ZERO, *sorted(buckets.values()))


@cache
def hex_lookup() -> dict[int, tuple[Eisenstein, Eisenstein]]:
    table = {0: (ZERO, ONE)}
    for bucket in hex_buckets()[1:]:
        for unit in UNITS:
            key = residue(multiply(bucket, unit))
            if key in table:
                raise ValueError("duplicate Eisenstein residue")
            table[key] = bucket, unit
    return table


def recode_hex(scalar: int) -> tuple[tuple[tuple[Eisenstein, Eisenstein], ...], Eisenstein]:
    """Return each bucket and unit together with the exact top residual."""
    residual = lift(scalar)
    table = hex_lookup()
    inverse_numerator = conjugate(RADIX)
    digits = []
    for _ in range(HEX_WINDOWS):
        bucket, unit = table[residue(residual)]
        x, y = multiply(bucket, unit)
        a, b = multiply((residual[0] - x, residual[1] - y), inverse_numerator)
        if a % RADIX_NORM or b % RADIX_NORM:
            raise ArithmeticError("non-integral Eisenstein quotient")
        residual = a // RADIX_NORM, b // RADIX_NORM
        digits.append((bucket, unit))
    return tuple(digits), residual


@cache
def hex_reduction_path() -> tuple[Eisenstein, ...]:
    """Traverse consecutive a-b rows, alternating the direction inside each."""
    def row_index(z: Eisenstein) -> int:
        return z[0] - z[1]

    ordered = sorted(hex_buckets(), key=row_index)
    path = []
    for index, entries in groupby(ordered, key=row_index):
        row = tuple(entries)
        path.extend(row if index % 2 else reversed(row))
    return tuple(path)


def scale_point_x(point: Point, factor: int) -> Point:
    if point is None:
        return None
    (x0, x1), y = point
    return (x0 * factor % P, x1 * factor % P), y


def reduce_hex_buckets(buckets: Mapping[Eisenstein, Point]) -> Point:
    """Compute sum [b]S[b] via the deterministic c=5 path on subgroup points."""
    path = hex_reduction_path()
    if not buckets.keys() <= set(path[1:]):
        raise ValueError("unexpected nonzero Eisenstein bucket")
    suffix = None
    differences = {}
    for previous, bucket in reversed(tuple(pairwise(path))):
        suffix = point_add(suffix, buckets.get(bucket))
        step = bucket[0] - previous[0], bucket[1] - previous[1]
        differences[step] = point_add(differences.get(step), suffix)

    # Fuse the opposite steps ±omega². The only nonunit step is omega² - omega.
    opposite = point_add(differences[(-1, -1)], point_neg(differences[(1, 1)]))
    nonunit = differences[(-1, -2)]
    weighted_nonunit = point_add(
        scale_point_x(nonunit, OMEGA_SQUARED), point_neg(scale_point_x(nonunit, OMEGA)),
    )
    return reduce(
        point_add,
        (
            differences[(1, 0)],
            point_neg(scale_point_x(differences[(0, -1)], OMEGA)),
            scale_point_x(opposite, OMEGA_SQUARED),
            weighted_nonunit,
        ),
    )
