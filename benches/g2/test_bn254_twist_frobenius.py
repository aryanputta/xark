"""Check exact public BN254 Frobenius and decomposition identities."""

import random
import unittest

from bn254_twist_frobenius import (
    BASIS,
    BOUNDS,
    GENERATOR,
    LAMBDA,
    P,
    PSI_X,
    PSI_Y,
    R,
    U,
    decompose,
    fq2_conj,
    fq2_mul,
    fq2_neg,
    fq2_pow,
    on_twist,
    point_add,
    psi,
    scalar_mul,
)


class BN254TwistFrobeniusTests(unittest.TestCase):
    def test_derived_parameters_match_pinned_arkworks(self):
        self.assertEqual(P % 6, 1)
        self.assertEqual(P % 4, 3)
        self.assertEqual(P - R, 6 * U**2)
        self.assertEqual(LAMBDA, 147946756881789318990833708069417712966)
        self.assertEqual(pow(P, 6, R), R - 1)
        self.assertEqual(pow(P, 12, R), 1)
        self.assertEqual(
            PSI_X,
            (
                21575463638280843010398324269430826099269044274347216827212613867836435027261,
                10307601595873709700152284273816112264069230130616436755625194854815875713954,
            ),
        )
        self.assertEqual(
            PSI_Y,
            (
                2821565182194536844548159561693502659359617185244120367078079554186484126554,
                3505843767911556378687030309984248845540243509899259641013678093033130930403,
            ),
        )
        self.assertEqual(fq2_pow((12345, 67890), P), fq2_conj((12345, 67890)))

    def test_psi_matches_independent_g2_multiplication(self):
        self.assertTrue(on_twist(GENERATOR))
        self.assertIsNone(scalar_mul(R, GENERATOR))
        for scalar in (0, 1, -1, 2, 43, 2**127 + 1, 2**200 + 43, R - 1):
            with self.subTest(scalar=scalar):
                point = scalar_mul(scalar, GENERATOR)
                image = psi(point)
                self.assertTrue(on_twist(image))
                self.assertEqual(image, scalar_mul(LAMBDA, point))

    def test_psi_squared_is_negative_sparse_cubic_map(self):
        omega = (
            21888242871839275220042445260109153167277707414472061641714758635765020556616,
            0,
        )
        scalar = 4407920970296243842393367215006156084916469457145843978461
        self.assertEqual(fq2_mul(fq2_conj(PSI_X), PSI_X), omega)
        self.assertEqual(fq2_mul(fq2_conj(PSI_Y), PSI_Y), (P - 1, 0))
        self.assertEqual(-LAMBDA**2 % R, scalar)
        self.assertIsNotNone(GENERATOR)
        x, y = GENERATOR
        self.assertEqual(psi(psi(GENERATOR)), (fq2_mul(omega, x), fq2_neg(y)))
        self.assertEqual(scalar_mul(scalar, GENERATOR), (fq2_mul(omega, x), y))

    def test_eigenvalue_is_not_valid_for_every_twist_point(self):
        # A square root of 1 + 3/(9+i) supplies a public on-twist point.
        outside = (
            (1, 0),
            (
                18278151005453108793778860132295291098363647455926340152056652516292830556603,
                5912654199736721486680175016176231956195085055698687135131307249486702594212,
            ),
        )
        self.assertTrue(on_twist(outside))
        self.assertTrue(on_twist(psi(outside)))
        self.assertIsNotNone(scalar_mul(R, outside))
        self.assertNotEqual(psi(outside), scalar_mul(LAMBDA, outside))

    def test_decomposition_congruence_and_proven_bounds(self):
        a, b = BASIS
        self.assertEqual(a[0] * b[1] - a[1] * b[0], R)
        for x, y in BASIS:
            self.assertEqual((x + LAMBDA * y) % R, 0)
        self.assertEqual(tuple(bound.bit_length() for bound in BOUNDS), (126, 126))
        rng = random.Random(254)
        edges = (0, 1, -1, R // 2, R - 1, R, R + 1, -R - 1)
        for scalar in (*edges, *(rng.randrange(R) for _ in range(4096))):
            short_x, short_y = decompose(scalar)
            self.assertLessEqual(abs(short_x), BOUNDS[0])
            self.assertLessEqual(abs(short_y), BOUNDS[1])
            self.assertEqual((short_x + LAMBDA * short_y) % R, scalar % R)

    def test_decomposition_recombines_on_generator_multiples(self):
        for multiple in (1, 7, 43):
            point = scalar_mul(multiple, GENERATOR)
            image = psi(point)
            for scalar in (0, 1, R // 2, 2**253 + 54321, R - 1):
                with self.subTest(multiple=multiple, scalar=scalar):
                    a, b = decompose(scalar)
                    self.assertEqual(
                        point_add(scalar_mul(a, point), scalar_mul(b, image)),
                        scalar_mul(scalar, point),
                    )
