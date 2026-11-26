"""Exact, variable-time reference for BN254 G2 Frobenius on public test points.

The D-twist y² = x³ + 3/ξ has ξ = 9 + i and i² = -1. If w⁶ = ξ,
the untwist ι maps (x, y) to (x*w², y*w³). Transporting p-power Frobenius
via ι⁻¹ ∘ π ∘ ι gives ψ(x, y) = (conj(x)*ξ^((p-1)/3), conj(y)*ξ^((p-1)/2)).
On the prime-order G2 subgroup its eigenvalue is p mod r = 6*u².
The trace is t = p + 1 - r, so T² - t*T + p factors as (T-1)(T-p) modulo r.
After untwisting, G2 is the p-eigenspace. The 1-eigenspace gives G1.
The scalar identity must not be assumed for arbitrary on-twist points.

Parameter and generator reference, ark-bn254 0.6.0 (bffa52711f225e888c1a91e1ec9fc59f2d9d5c94):
https://github.com/arkworks-rs/algebra/blob/bffa52711f225e888c1a91e1ec9fc59f2d9d5c94/curves/bn254/src/curves/g2.rs
"""

U = 4965661367192848881
P = 36 * U**4 + 36 * U**3 + 24 * U**2 + 6 * U + 1
R = 36 * U**4 + 36 * U**3 + 18 * U**2 + 6 * U + 1
LAMBDA = P % R

Fq2 = tuple[int, int]
Point = tuple[Fq2, Fq2] | None
Vector = tuple[int, int]

GENERATOR: Point = (
    (
        10857046999023057135944570762232829481370756359578518086990519993285655852781,
        11559732032986387107991004021392285783925812861821192530917403151452391805634,
    ),
    (
        8495653923123431417604973247489272438418190587263600148770280649306958101930,
        4082367875863433681332203403145435568316851327593401208105741076214120093531,
    ),
)


def fq2_add(a: Fq2, b: Fq2) -> Fq2:
    return ((a[0] + b[0]) % P, (a[1] + b[1]) % P)


def fq2_neg(a: Fq2) -> Fq2:
    return (-a[0] % P, -a[1] % P)


def fq2_mul(a: Fq2, b: Fq2) -> Fq2:
    a0, a1 = a
    b0, b1 = b
    return ((a0 * b0 - a1 * b1) % P, (a0 * b1 + a1 * b0) % P)


def fq2_conj(a: Fq2) -> Fq2:
    return (a[0], -a[1] % P)


def fq2_inv(a: Fq2) -> Fq2:
    a0, a1 = a
    inverse_norm = pow((a0 * a0 + a1 * a1) % P, -1, P)
    return (a0 * inverse_norm % P, -a1 * inverse_norm % P)


def fq2_pow(a: Fq2, exponent: int) -> Fq2:
    if exponent < 0:
        raise ValueError("expected a nonnegative exponent")
    result = (1, 0)
    while exponent:
        if exponent & 1:
            result = fq2_mul(result, a)
        a = fq2_mul(a, a)
        exponent >>= 1
    return result


XI = (9, 1)
TWIST_B = fq2_mul((3, 0), fq2_inv(XI))
PSI_X = fq2_pow(XI, (P - 1) // 3)
PSI_Y = fq2_pow(XI, (P - 1) // 2)


def on_twist(point: Point) -> bool:
    if point is None:
        return True
    x, y = point
    return fq2_mul(y, y) == fq2_add(fq2_mul(fq2_mul(x, x), x), TWIST_B)


def point_neg(point: Point) -> Point:
    return None if point is None else (point[0], fq2_neg(point[1]))


def point_add(a: Point, b: Point) -> Point:
    if a is None:
        return b
    if b is None:
        return a
    x0, y0 = a
    x1, y1 = b
    if x0 == x1:
        if y0 == fq2_neg(y1):
            return None
        numerator = fq2_mul((3, 0), fq2_mul(x0, x0))
        denominator = fq2_add(y0, y0)
    else:
        numerator = fq2_add(y1, fq2_neg(y0))
        denominator = fq2_add(x1, fq2_neg(x0))
    slope = fq2_mul(numerator, fq2_inv(denominator))
    x2 = fq2_add(fq2_mul(slope, slope), fq2_neg(fq2_add(x0, x1)))
    y2 = fq2_add(fq2_mul(slope, fq2_add(x0, fq2_neg(x2))), fq2_neg(y0))
    return x2, y2


def scalar_mul(scalar: int, point: Point) -> Point:
    """Independent affine double-and-add. Do not reduce modulo r."""
    if scalar < 0:
        point = point_neg(point)
        scalar = -scalar
    result = None
    while scalar:
        if scalar & 1:
            result = point_add(result, point)
        point = point_add(point, point)
        scalar >>= 1
    return result


def psi(point: Point) -> Point:
    if point is None:
        return None
    x, y = point
    return fq2_mul(fq2_conj(x), PSI_X), fq2_mul(fq2_conj(y), PSI_Y)


def nearest(numerator: int, denominator: int) -> int:
    """Nearest integer with ties toward positive infinity."""
    return (2 * numerator + denominator) // (2 * denominator)


def dot(a: Vector, b: Vector) -> int:
    return a[0] * b[0] + a[1] * b[1]


def kernel_basis() -> tuple[Vector, Vector]:
    """Lagrange-reduce the kernel of (a,b) → a + λb modulo r."""
    a, b = (R, 0), (-LAMBDA, 1)
    while True:
        if dot(b, b) < dot(a, a):
            a, b = b, a
        norm, product = dot(a, a), dot(a, b)
        if 2 * abs(product) <= norm:
            if a[0] * b[1] - a[1] * b[0] < 0:
                b = (-b[0], -b[1])
            return a, b
        multiple = nearest(product, norm)
        b = (b[0] - multiple * a[0], b[1] - multiple * a[1])


BASIS = kernel_basis()
# Each rounding error is at most 1/2. Bound each resulting integer coordinate.
BOUNDS = (
    (abs(BASIS[0][0]) + abs(BASIS[1][0])) // 2,
    (abs(BASIS[0][1]) + abs(BASIS[1][1])) // 2,
)


def decompose(scalar: int) -> Vector:
    """Return a signed pair (a,b) with a + λb = scalar modulo r."""
    a, b = BASIS
    scalar %= R
    # BASIS columns have determinant +r, so these are the coordinates of (s,0).
    m = nearest(scalar * b[1], R)
    n = nearest(-scalar * a[1], R)
    return scalar - m * a[0] - n * b[0], -m * a[1] - n * b[1]


# Reduce λ² = 36*u⁴ and λ³ modulo r as polynomials in u. The four rows below
# dot these reduced powers to (0, -2r, r, 2r), and their determinant equals r.
# Hence the rows span the entire kernel of a₀+a₁λ+a₂λ²+a₃λ³ modulo r.
GLS_POWERS = (
    1,
    6 * U**2,
    -36 * U**3 - 18 * U**2 - 6 * U - 1,
    -36 * U**3 - 24 * U**2 - 12 * U - 3,
)
GLS_BASIS = (
    (2 * U, U + 1, -U, U),
    (2 * U + 1, 0, 2 * U, 1),
    (U + 1, U, U, -2 * U),
    (2 * U + 1, -U, -U - 1, -U),
)


def det3(a: tuple[int, ...], b: tuple[int, ...], c: tuple[int, ...]) -> int:
    return (
        a[0] * (b[1] * c[2] - b[2] * c[1])
        - a[1] * (b[0] * c[2] - b[2] * c[0])
        + a[2] * (b[0] * c[1] - b[1] * c[0])
    )


GLS_COFACTORS = tuple(
    (-1) ** i * det3(*(row[1:] for j, row in enumerate(GLS_BASIS) if j != i))
    for i in range(4)
)
GLS_BOUNDS = tuple(sum(abs(component) for component in col) // 2 for col in zip(*GLS_BASIS))


def decompose_gls(scalar: int) -> tuple[int, ...]:
    """Split a scalar into four signed components for the powers of ψ on G2."""
    scalar %= R
    # First column cofactors give the exact row-basis coordinates of (s,0,0,0).
    rounded = [nearest(scalar * cofactor, R) for cofactor in GLS_COFACTORS]
    return tuple(
        (scalar if j == 0 else 0) - sum(m * b for m, b in zip(rounded, col))
        for j, col in enumerate(zip(*GLS_BASIS))
    )


# ψ² multiplies x by this base-field root of unity and negates y.
OMEGA = fq2_mul(fq2_conj(PSI_X), PSI_X)[0]


def psi_squared(point: Point) -> Point:
    if point is None:
        return None
    (x0, x1), y = point
    return (x0 * OMEGA % P, x1 * OMEGA % P), fq2_neg(y)


def gls_bases(point: Point) -> tuple[Point, Point, Point, Point]:
    image = psi(point)
    return point, image, psi_squared(point), psi_squared(image)


SHIFT_128_PARTS = decompose_gls(1 << 128)
SHIFT_128_MASKS = tuple(
    sum(((abs(part) >> bit) & 1) << i for i, part in enumerate(SHIFT_128_PARTS))
    for bit in reversed(range(max(abs(part).bit_length() for part in SHIFT_128_PARTS)))
)


def shifted_point_gls(point: Point) -> Point:
    """Calculate [2^128]P on G2 with the four masks used by this fixed scalar."""
    p0, p1, p2, p3 = gls_bases(point)
    # The second and fourth signed components are negative.
    mask_12 = point_add(p2, point_neg(p3))
    mask_14 = point_add(point_neg(p1), mask_12)
    masks = {1: p0, 12: mask_12, 14: mask_14, 15: point_add(p0, mask_14)}
    highest, *remaining = SHIFT_128_MASKS
    result = masks[highest]
    for mask in remaining:
        result = point_add(result, result)
        if mask:
            result = point_add(result, masks[mask])
    return result
