//! Benchmark-only, immutable shifted points tied to one resident key query.

use std::mem::size_of;

use ark_bn254::{G2Affine, G2Projective};
use ark_ec::CurveGroup;
use ark_ff::{AdditiveGroup, BigInt};
use rayon::prelude::*;
use zeroize::Zeroizing;

use super::Scalar;

const CHUNK_BITS: usize = 128;
const TABLE_CAP_BYTES: usize = 3 * 1024 * 1024;

/// An experiment-only table derived from one borrowed resident G2 query.
#[doc(hidden)]
pub struct ShiftedBases<'a> {
    source: &'a [G2Affine],
    points: Vec<G2Affine>,
}

impl<'a> ShiftedBases<'a> {
    fn point_count(terms: usize) -> Result<usize, &'static str> {
        if terms > TABLE_CAP_BYTES / size_of::<G2Affine>() / 2 {
            return Err("shifted B2 table would exceed the 3 MiB affine payload cap");
        }
        Ok(2 * terms)
    }

    pub fn new(bases: &'a [G2Affine]) -> Result<Self, &'static str> {
        let count = Self::point_count(bases.len())?;
        let shifted: Vec<_> = bases
            .par_iter()
            .with_min_len(32)
            .map(|&base| {
                let mut point = G2Projective::from(base);
                for _ in 0..CHUNK_BITS {
                    point.double_in_place();
                }
                point
            })
            .collect();
        let mut points = Vec::with_capacity(count);
        points.extend_from_slice(bases);
        points.extend(G2Projective::normalize_batch(&shifted));
        Ok(Self {
            source: bases,
            points,
        })
    }

    pub fn msm(&self, scalars: &[Scalar]) -> G2Projective {
        assert_eq!(scalars.len(), self.source.len(), "shifted B2 scalar count");
        // Both halves encode private request scalars. Guard the allocation before
        // writing either half so it is wiped on return and during unwinding.
        let mut split = Zeroizing::new(Vec::with_capacity(self.points.len()));
        split.extend(scalars.iter().map(|s| BigInt([s.0[0], s.0[1], 0, 0])));
        split.extend(scalars.iter().map(|s| BigInt([s.0[2], s.0[3], 0, 0])));
        super::msm::<G2Projective>(&self.points, &split)
    }

    pub(crate) fn matches(&self, bases: &[G2Affine]) -> bool {
        std::ptr::eq(self.source, bases)
    }

    pub fn payload_bytes(&self) -> usize {
        self.points.len() * size_of::<G2Affine>()
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use ark_ec::{PrimeGroup, VariableBaseMSM};
    use ark_ff::{BigInteger, PrimeField};

    use super::*;

    fn canonical(scalar: &Scalar) -> Scalar {
        Fr::from_le_bytes_mod_order(&scalar.to_bytes_le()).into_bigint()
    }

    #[test]
    fn shifted_matches_arkworks_at_chunk_and_field_boundaries() {
        let modulus = Fr::MODULUS;
        let mut last = modulus;
        last.sub_with_borrow(&BigInt([1, 0, 0, 0]));
        let values = [
            BigInt([0, 0, 0, 0]),
            BigInt([1, 0, 0, 0]),
            BigInt([u64::MAX, u64::MAX, 0, 0]),
            BigInt([0, 0, 1, 0]),
            BigInt([1, 0, 1, 0]),
            BigInt([0, 0, 0, 1 << 61]),
            last,
            modulus,
            BigInt([u64::MAX; 4]),
        ];
        let generator = G2Projective::generator().into_affine();
        let input = [generator];
        let distinct = [generator];
        let table = ShiftedBases::new(&input).unwrap();
        assert!(table.matches(&input));
        assert!(!table.matches(&distinct));
        for scalar in values {
            let expected = G2Projective::msm_bigint(&[generator], &[canonical(&scalar)]);
            assert!(super::super::same_point(&table.msm(&[scalar]), &expected));
        }

        let mut point = G2Projective::generator();
        let bases: Vec<_> = (0..513)
            .map(|index| {
                if index % 7 == 0 {
                    G2Affine::default()
                } else {
                    point += generator;
                    point.into_affine()
                }
            })
            .collect();
        let scalars: Vec<_> = (0..bases.len()).map(|i| values[i % values.len()]).collect();
        let table = ShiftedBases::new(&bases).unwrap();
        let canonical_scalars: Vec<_> = scalars.iter().map(canonical).collect();
        let expected = G2Projective::msm_bigint(&bases, &canonical_scalars);
        assert!(super::super::same_point(&table.msm(&scalars), &expected));
    }

    #[test]
    fn table_cap_and_empty_input() {
        let max = TABLE_CAP_BYTES / size_of::<G2Affine>() / 2;
        assert_eq!(ShiftedBases::point_count(max), Ok(2 * max));
        assert!(ShiftedBases::point_count(max + 1).is_err());
        assert!(ShiftedBases::point_count(usize::MAX).is_err());
        let empty = ShiftedBases::new(&[]).unwrap();
        assert_eq!(empty.payload_bytes(), 0);
        assert_eq!(empty.msm(&[]), G2Projective::ZERO);
    }
}
