//! Benchmark-only cached four-dimensional GLS on BN254 G2.

use std::mem::size_of;
use std::path::Path;
use std::sync::atomic::Ordering::Relaxed;
use std::time::{Duration, Instant};

use ark_bn254::{Config, Fr, G2Affine, G2Projective, g2};
use ark_ec::{AffineRepr, VariableBaseMSM, bn::BnConfig, scalar_mul::glv::GLVConfig};
use ark_ff::{BigInt as ArkBigInt, BigInteger, Field, PrimeField};
use num_bigint::{BigInt, Sign};
use rayon::prelude::*;
use xark_groth16::msm::{self, Scalar};

const IMAGES: usize = 4;
const TABLE_CAP_BYTES: usize = 4 * 1024 * 1024;
const U: i128 = 4_965_661_367_192_848_881;

// The kernel rows and first-column cofactors from the exact 7d99bba reference.
// The row determinant is r. The cofactors of this column are all positive.
const BASIS: [[i128; IMAGES]; IMAGES] = [
    [2 * U, U + 1, -U, U],
    [2 * U + 1, 0, 2 * U, 1],
    [U + 1, U, U, -2 * U],
    [2 * U + 1, -U, -U - 1, -U],
];
const COFACTORS: [&str; IMAGES] = [
    "734653495049373973658254490726798021314063399421879442165",
    "734653495049373973806201247608587340319794091592875701774",
    "9931322734385697763",
    "734653495049373973806201247608587340314828430225682852893",
];

struct Recoder {
    modulus: BigInt,
    half_modulus: BigInt,
    cofactors: [BigInt; IMAGES],
}

impl Recoder {
    fn new() -> Self {
        let modulus = BigInt::from_bytes_le(Sign::Plus, &Fr::MODULUS.to_bytes_le());
        let half_modulus = &modulus >> 1;
        Self {
            modulus,
            half_modulus,
            cofactors: COFACTORS.map(|c| c.parse().expect("nonnegative GLS cofactor")),
        }
    }

    // Nearest row-basis coordinates of (scalar,0,0,0); no tie is possible since
    // r is odd. The signed residual magnitudes all fit in one u64.
    fn decompose(&self, scalar: &Scalar) -> [BigInt; IMAGES] {
        let n = BigInt::from_bytes_le(Sign::Plus, &scalar.to_bytes_le());
        let mut parts = std::array::from_fn(|i| if i == 0 { n.clone() } else { BigInt::ZERO });
        for (row, cofactor) in BASIS.iter().zip(&self.cofactors) {
            let nearest = (&n * cofactor + &self.half_modulus) / &self.modulus;
            for (part, &coordinate) in parts.iter_mut().zip(row) {
                *part -= &nearest * coordinate;
            }
        }
        parts
    }

    fn encode(&self, scalar: &Scalar) -> [Scalar; IMAGES] {
        if !requires_split(scalar) {
            return [
                *scalar,
                Scalar::default(),
                Scalar::default(),
                Scalar::default(),
            ];
        }
        self.decompose(scalar).map(|part| {
            let mut limbs = part.iter_u64_digits();
            let magnitude = ArkBigInt([limbs.next().unwrap_or(0), 0, 0, 0]);
            assert!(limbs.next().is_none(), "GLS split exceeded u64 magnitude");
            if part.sign() == Sign::Minus {
                // Give Xark's existing signed magnitude classes canonical r-k.
                let mut encoded = Fr::MODULUS;
                encoded.sub_with_borrow(&magnitude);
                encoded
            } else {
                magnitude
            }
        })
    }
}

fn requires_split(scalar: &Scalar) -> bool {
    // The witness loader supplies canonical Fr values. Keep the same full-width
    // class as the existing starting Xark MSM, including short negatives.
    if scalar.num_bits() <= 128 {
        return false;
    }
    let mut negative = Fr::MODULUS;
    negative.sub_with_borrow(scalar);
    negative.num_bits() > 128
}

fn images(point: &G2Affine) -> [G2Affine; IMAGES] {
    let mut x = point.x;
    let mut y = point.y;
    x.frobenius_map_in_place(1);
    y.frobenius_map_in_place(1);
    let psi = G2Affine::new_unchecked(x * Config::TWIST_MUL_BY_Q_X, y * Config::TWIST_MUL_BY_Q_Y);
    // On the prime-order subgroup, psi^2 = -phi. Both maps preserve infinity.
    [
        *point,
        psi,
        -g2::Config::endomorphism_affine(point),
        -g2::Config::endomorphism_affine(&psi),
    ]
}

fn check_subgroup(bases: &[G2Affine]) -> Result<(), usize> {
    match bases
        .par_iter()
        .position_any(|p| !p.is_on_curve() || !p.is_in_correct_subgroup_assuming_on_curve())
    {
        Some(index) => Err(index),
        None => Ok(()),
    }
}

struct CachedImages {
    points: Vec<G2Affine>,
}

impl CachedImages {
    fn new(bases: &[G2Affine]) -> Result<Self, &'static str> {
        if bases.len() > TABLE_CAP_BYTES / size_of::<G2Affine>() / IMAGES {
            return Err("cached GLS B2 table would exceed the 4 MiB affine payload cap");
        }
        let points: Vec<_> = bases.par_iter().with_min_len(128).map(images).collect();
        Ok(Self {
            points: points.into_flattened(),
        })
    }

    fn recode(&self, recoder: &Recoder, scalars: &[Scalar]) -> Vec<Scalar> {
        assert_eq!(self.points.len() / IMAGES, scalars.len());
        let parts: Vec<_> = self
            .points
            .par_chunks_exact(IMAGES)
            .zip(scalars.par_iter())
            .with_min_len(128)
            .map(|(images, scalar)| {
                if images[0].is_zero() {
                    [Scalar::default(); IMAGES]
                } else {
                    recoder.encode(scalar)
                }
            })
            .collect();
        parts.into_flattened()
    }
}

struct CandidateTiming {
    total: Duration,
    recode: Duration,
    msm: Duration,
}

pub(crate) fn run(args: &[String]) {
    let [xbc_path, pk_path, directory, options @ ..] = args else {
        panic!(
            "usage: bench_prove query-msm-b2-cached-gls <circuit.xbc> <reduced pk.bin> <statement-dir> [samples] [warmups]"
        );
    };
    let (samples, warmups) = super::counts(options).unwrap_or_else(|reason| panic!("{reason}"));
    assert!(!super::super::tracking(), "set BENCH_TIME=1 to time GLS");
    let (pk, scalars) = super::load(xbc_path, pk_path, Path::new(directory));
    let bases = &pk.b_g2_query;
    // The normal trusted proving-key decoder deliberately skips this check.
    if let Err(index) = check_subgroup(bases) {
        panic!("B2 base {index} is outside the BN254 G2 subgroup");
    }
    let split_terms = bases
        .iter()
        .zip(&scalars)
        .filter(|(point, s)| !point.is_zero() && requires_split(s))
        .count();
    let (recoder, recoder_setup) = super::timed(Recoder::new);
    let (cache, prepare) =
        super::timed(|| CachedImages::new(bases).expect("prepare signed GLS bases"));
    let expected = G2Projective::msm_bigint(bases, &scalars);
    let baseline = || super::timed(|| msm::msm::<G2Projective>(bases, &scalars));
    let candidate = || {
        let start = Instant::now();
        let (recoded, recode) = super::timed(|| cache.recode(&recoder, &scalars));
        let (point, msm) = super::timed(|| msm::msm::<G2Projective>(&cache.points, &recoded));
        drop(recoded);
        let total = start.elapsed();
        (point, CandidateTiming { total, recode, msm })
    };
    let mut timings = Vec::with_capacity(samples);
    for iteration in 0..(warmups + samples) {
        let baseline_first = iteration % 2 == 0;
        let ((reference, baseline_time), (gls, gls_time)) = if baseline_first {
            (baseline(), candidate())
        } else {
            let gls = candidate();
            (baseline(), gls)
        };
        for (arm, point) in [("baseline", reference), ("cached GLS", gls)] {
            assert!(
                msm::same_point(&point, &expected),
                "{arm} B2 query iteration {} disagrees with Arkworks",
                iteration + 1
            );
        }
        if iteration >= warmups {
            timings.push((baseline_first, baseline_time, gls_time));
        }
    }
    println!(
        "query msm B2 cached GLS verified: terms={} threads={} samples={samples} warmups={warmups} subgroup_points={} split_terms={split_terms} xark_glv={} xark_batch_affine={} table_payload_bytes={} table_cap_bytes={TABLE_CAP_BYTES} scalar_scratch_bytes={} recoder_setup_ns={} prepare_ns={}",
        bases.len(),
        rayon::current_num_threads(),
        bases.len(),
        msm::GLV.load(Relaxed),
        msm::BATCH_AFFINE.load(Relaxed),
        cache.points.len() * size_of::<G2Affine>(),
        cache.points.len() * size_of::<Scalar>(),
        recoder_setup.as_nanos(),
        prepare.as_nanos(),
    );
    for (index, (baseline_first, baseline, candidate)) in timings.into_iter().enumerate() {
        let first = if baseline_first {
            "baseline"
        } else {
            "cached-gls"
        };
        println!(
            "query msm B2 cached GLS: sample={} first={first} baseline_ns={} gls_total_ns={} gls_recode_ns={} gls_msm_ns={}",
            index + 1,
            baseline.as_nanos(),
            candidate.total.as_nanos(),
            candidate.recode.as_nanos(),
            candidate.msm.as_nanos(),
        );
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::{Fq, Fq2};
    use ark_ec::{CurveGroup, PrimeGroup};
    use ark_ff::UniformRand;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;

    #[test]
    fn exact_split_matches_reference_and_reconstructs_canonical_scalars() {
        let r = Recoder::new();
        let q = Fr::from_le_bytes_mod_order(&Fq::MODULUS.to_bytes_le());
        let half = Fr::from_le_bytes_mod_order(&r.half_modulus.to_bytes_le().1).into_bigint();
        assert_eq!(
            r.decompose(&half),
            [
                12_414_153_417_982_122_203i128,
                2_482_830_683_596_424_441,
                -2_482_830_683_596_424_441,
                -4_965_661_367_192_848_881,
            ]
            .map(BigInt::from)
        );
        assert_eq!(
            r.decompose(&ArkBigInt([54_321, 0, 0, 1 << 61])),
            [
                682_483_550_152_688_312i128,
                1_107_664_535_193_208_529,
                -482_353_279_730_965_775,
                2_164_377_927_436_131_267,
            ]
            .map(BigInt::from)
        );
        let mut rng = ChaCha20Rng::seed_from_u64(25404);
        let mut minus_one = Fr::MODULUS;
        minus_one.sub_with_borrow(&ArkBigInt([1, 0, 0, 0]));
        for scalar in [Scalar::default(), ArkBigInt([1, 0, 0, 0]), half, minus_one]
            .into_iter()
            .chain((0..1024).map(|_| Fr::rand(&mut rng).into_bigint()))
        {
            let split = r.encode(&scalar);
            let recombined: Fr = split
                .into_iter()
                .enumerate()
                .map(|(i, part)| Fr::from_bigint(part).unwrap() * q.pow([i as u64]))
                .sum();
            assert_eq!(recombined.into_bigint(), scalar);
        }
    }

    #[test]
    fn short_positive_and_negative_inputs_keep_the_original_image() {
        let r = Recoder::new();
        let short = ArkBigInt([u64::MAX, u64::MAX, 0, 0]);
        let mut negative = Fr::MODULUS;
        negative.sub_with_borrow(&short);
        for coefficient in [Scalar::default(), short, negative] {
            assert_eq!(
                r.encode(&coefficient),
                [
                    coefficient,
                    Scalar::default(),
                    Scalar::default(),
                    Scalar::default()
                ]
            );
        }
        let wide = ArkBigInt([0, 0, 1, 0]);
        let mut negative_wide = Fr::MODULUS;
        negative_wide.sub_with_borrow(&wide);
        assert!(requires_split(&wide) && requires_split(&negative_wide));
    }

    #[test]
    fn cached_images_and_msm_agree_with_arkworks() {
        let generator = G2Projective::generator();
        let q = Fr::from_le_bytes_mod_order(&Fq::MODULUS.to_bytes_le());
        let mut rng = ChaCha20Rng::seed_from_u64(254);
        let bases = (0..65)
            .map(|i| generator.mul_bigint([i]).into_affine())
            .collect::<Vec<_>>();
        assert_eq!(check_subgroup(&bases), Ok(()));
        for base in &bases {
            for (i, image) in images(base).into_iter().enumerate() {
                assert_eq!(
                    G2Projective::from(image),
                    base.mul_bigint(q.pow([i as u64]).into_bigint())
                );
            }
        }
        let scalars: Vec<_> = (0..bases.len())
            .map(|_| Fr::rand(&mut rng).into_bigint())
            .collect();
        let cache = CachedImages::new(&bases).unwrap();
        let encoded = cache.recode(&Recoder::new(), &scalars);
        let expected = G2Projective::msm_bigint(&bases, &scalars);
        assert_eq!(msm::msm::<G2Projective>(&cache.points, &encoded), expected);
    }

    #[test]
    fn cached_payload_limit_is_checked_before_building_images() {
        let max = TABLE_CAP_BYTES / size_of::<G2Affine>() / IMAGES;
        let oversized = vec![G2Affine::default(); max + 1];
        assert!(CachedImages::new(&oversized).is_err());
        assert!(CachedImages::new(&[]).unwrap().points.is_empty());
    }

    #[test]
    fn subgroup_gate_rejects_on_curve_non_subgroup_points() {
        let point = (0..64)
            .filter_map(|k: u64| {
                G2Affine::get_point_from_x_unchecked(Fq2::new(Fq::from(k), Fq::ONE), false)
            })
            .find(|p| !p.is_in_correct_subgroup_assuming_on_curve())
            .unwrap();
        assert_eq!(check_subgroup(&[G2Affine::generator(), point]), Err(1));
    }
}
