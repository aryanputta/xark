//! Benchmark-only two-chunk B2 MSM with one key-dependent table.

use std::mem::size_of;
use std::path::Path;
use std::sync::atomic::Ordering::Relaxed;

use ark_bn254::{G2Affine, G2Projective};
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::{AdditiveGroup, BigInt};
use rayon::prelude::*;
use xark_groth16::msm::{self, Scalar};

const CHUNK_BITS: usize = 128;
const TABLE_CAP_BYTES: usize = 3 * 1024 * 1024;

struct ShiftedBases {
    terms: usize,
    points: Vec<G2Affine>,
}

impl ShiftedBases {
    fn point_count(terms: usize) -> Result<usize, &'static str> {
        if terms > TABLE_CAP_BYTES / size_of::<G2Affine>() / 2 {
            return Err("shifted B2 table would exceed the 3 MiB affine payload cap");
        }
        Ok(2 * terms)
    }

    fn new(bases: &[G2Affine]) -> Result<Self, &'static str> {
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
            terms: bases.len(),
            points,
        })
    }

    fn msm(&self, scalars: &[Scalar]) -> G2Projective {
        assert_eq!(scalars.len(), self.terms, "shifted B2 scalar count");
        let mut split = Vec::with_capacity(self.points.len());
        split.extend(scalars.iter().map(|s| BigInt([s.0[0], s.0[1], 0, 0])));
        split.extend(scalars.iter().map(|s| BigInt([s.0[2], s.0[3], 0, 0])));
        msm::msm::<G2Projective>(&self.points, &split)
    }

    fn payload_bytes(&self) -> usize {
        self.points.len() * size_of::<G2Affine>()
    }
}

pub(crate) fn run(args: &[String]) {
    let [xbc_path, pk_path, directory, options @ ..] = args else {
        panic!(
            "usage: bench_prove query-msm-b2-shifted <circuit.xbc> <reduced pk.bin> <statement-dir> [samples] [warmups]"
        );
    };
    let (samples, warmups) = super::counts(options).unwrap_or_else(|reason| panic!("{reason}"));
    assert!(
        !super::super::tracking(),
        "set BENCH_TIME=1 to time query MSMs"
    );
    let (pk, scalars) = super::load(xbc_path, pk_path, Path::new(directory));
    let bases = &pk.b_g2_query;
    let (table, prepare) = super::timed(|| ShiftedBases::new(bases));
    let table = table.unwrap_or_else(|reason| panic!("{reason}"));
    let expected = G2Projective::msm_bigint(bases, &scalars);
    let baseline = || super::timed(|| msm::msm::<G2Projective>(bases, &scalars));
    let shifted = || super::timed(|| table.msm(&scalars));
    let mut timings = Vec::with_capacity(samples);
    for iteration in 0..(warmups + samples) {
        let baseline_first = iteration % 2 == 0;
        let ((control, baseline_time), (candidate, shifted_time)) = if baseline_first {
            (baseline(), shifted())
        } else {
            let candidate = shifted();
            (baseline(), candidate)
        };
        for (arm, point) in [("baseline", control), ("shifted", candidate)] {
            assert!(
                msm::same_point(&point, &expected),
                "{arm} B2 query iteration {} disagrees with Arkworks",
                iteration + 1
            );
        }
        if iteration >= warmups {
            timings.push((baseline_first, baseline_time, shifted_time));
        }
    }
    println!(
        "query msm B2 shifted verified: terms={} threads={} samples={samples} warmups={warmups} xark_glv={} xark_batch_affine={} table_payload_bytes={} table_cap_bytes={TABLE_CAP_BYTES} prepare_ns={}",
        scalars.len(),
        rayon::current_num_threads(),
        msm::GLV.load(Relaxed),
        msm::BATCH_AFFINE.load(Relaxed),
        table.payload_bytes(),
        prepare.as_nanos(),
    );
    for (index, (baseline_first, baseline, shifted)) in timings.into_iter().enumerate() {
        let first = if baseline_first {
            "baseline"
        } else {
            "shifted"
        };
        println!(
            "query msm B2 shifted: sample={} first={first} baseline_ns={} shifted_ns={}",
            index + 1,
            baseline.as_nanos(),
            shifted.as_nanos(),
        );
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use ark_ec::PrimeGroup;
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
        let table = ShiftedBases::new(&[generator]).unwrap();
        for scalar in values {
            let expected = G2Projective::msm_bigint(&[generator], &[canonical(&scalar)]);
            assert!(msm::same_point(&table.msm(&[scalar]), &expected));
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
        assert!(msm::same_point(&table.msm(&scalars), &expected));
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
