//! Fixed scalar multiplication on the BN254 G2 subgroup for B2 setup.

use ark_bn254::{Config, G2Affine, G2Projective};
use ark_ec::bn::BnConfig;
use ark_ff::{AdditiveGroup, Field};
use rayon::prelude::*;

const COEFFICIENTS: [i64; 4] = [
    6_994_998_879_106_512_636,
    -1_489_860_392_368_150_449,
    1_489_860_392_368_150_451,
    -1_489_860_392_368_150_451,
];
const DOUBLES: usize = 62;

// Recode the magnitudes by bit column. The only nonzero masks are 1, 12,
// 14 and 15. Mask 1 at the top initializes the accumulator without an add.
const MASKS: [u8; DOUBLES + 1] = {
    let mut masks = [0; DOUBLES + 1];
    let mut bit = 0;
    while bit <= DOUBLES {
        let mut image = 0;
        while image < COEFFICIENTS.len() {
            masks[bit] |= (((COEFFICIENTS[image].unsigned_abs() >> bit) & 1) as u8) << image;
            image += 1;
        }
        bit += 1;
    }
    masks
};

// The untwist-Frobenius-twist map, using the public Arkworks BN254 twist
// constants. The zero encoding (0, 0) maps to itself.
fn psi(point: &G2Affine) -> G2Affine {
    let mut x = point.x;
    let mut y = point.y;
    x.frobenius_map_in_place(1);
    y.frobenius_map_in_place(1);
    G2Affine::new_unchecked(x * Config::TWIST_MUL_BY_Q_X, y * Config::TWIST_MUL_BY_Q_Y)
}

// This identity uses psi(P) = [q]P in the prime-order subgroup, and
// sum(COEFFICIENTS[i] * q^i) = 2^128 (mod r).
pub(super) fn shift_subgroup_point(point: &G2Affine) -> G2Projective {
    let image1 = psi(point);
    let image2 = psi(&image1);
    let image3 = psi(&image2);
    let sum12 = G2Projective::from(image2) - image3;
    let sum14 = sum12 - image1;
    let sum15 = sum14 + point;

    let mut result = G2Projective::from(*point);
    for &mask in MASKS[..DOUBLES].iter().rev() {
        result.double_in_place();
        match mask {
            0 => (),
            1 => result += point,
            12 => result += sum12,
            14 => result += sum14,
            15 => result += sum15,
            _ => unreachable!("unexpected fixed Frobenius mask"),
        }
    }
    result
}

/// The fixture decoder omits subgroup checks on trusted setup material. Verify
/// B2 bases once outside the timing loop before applying the subgroup identity.
pub(super) fn check_subgroup(bases: &[G2Affine]) -> Result<(), usize> {
    match bases
        .par_iter()
        .position_any(|p| !p.is_on_curve() || !p.is_in_correct_subgroup_assuming_on_curve())
    {
        Some(index) => Err(index),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::{Fq, Fq2, Fr};
    use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
    use ark_ff::{BigInteger, PrimeField};

    use super::*;

    #[test]
    fn split_reconstructs_128_bit_shift_and_has_fixed_operation_counts() {
        let q = Fr::from_le_bytes_mod_order(&Fq::MODULUS.to_bytes_le());
        let scalar: Fr = COEFFICIENTS
            .iter()
            .enumerate()
            .map(|(i, &k)| {
                let term = Fr::from(k.unsigned_abs()) * q.pow([i as u64]);
                if k < 0 { -term } else { term }
            })
            .sum();
        assert_eq!(scalar, Fr::from(2u64).pow([128]));
        assert_eq!(DOUBLES, 62);
        assert_eq!(MASKS[DOUBLES], 1);
        assert!(
            MASKS
                .iter()
                .all(|mask| matches!(mask, 0 | 1 | 12 | 14 | 15))
        );
        assert_eq!(
            MASKS[..DOUBLES].iter().filter(|&&mask| mask != 0).count() + 3,
            48
        );
        let p = G2Affine::generator();
        assert_eq!(G2Projective::from(psi(&p)), p.mul_bigint(q.into_bigint()));
    }

    #[test]
    fn frobenius_shift_matches_doubling_on_subgroup_points() {
        let scalar = [0, 0, 1];
        let generator = G2Projective::generator();
        let mut cases = vec![G2Affine::default(), (-generator).into_affine()];
        cases.extend((1..=64).map(|k| generator.mul_bigint([k]).into_affine()));
        assert_eq!(check_subgroup(&cases), Ok(()));
        for point in cases {
            let shifted = shift_subgroup_point(&point);
            assert_eq!(shifted, super::super::double_shift(&point));
            assert_eq!(shifted, point.mul_bigint(scalar));
        }
    }

    #[test]
    fn subgroup_gate_rejects_off_curve_and_non_subgroup_input() {
        let off_curve = G2Affine::new_unchecked(Fq2::ONE, Fq2::ONE);
        assert!(!off_curve.is_on_curve());
        assert_eq!(check_subgroup(&[G2Affine::generator(), off_curve]), Err(1));
        let other = (0..64)
            .filter_map(|k: u64| {
                G2Affine::get_point_from_x_unchecked(Fq2::new(Fq::from(k), Fq::ONE), false)
            })
            .find(|p| !p.is_in_correct_subgroup_assuming_on_curve())
            .expect("known on-curve non-subgroup point");
        assert!(other.is_on_curve());
        assert_eq!(check_subgroup(&[G2Affine::generator(), other]), Err(1));
    }
}
