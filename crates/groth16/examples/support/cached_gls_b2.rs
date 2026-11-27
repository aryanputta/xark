//! Benchmark-only cached four-dimensional GLS on BN254 G2.

use std::mem::size_of;
use std::path::Path;
use std::sync::atomic::Ordering::Relaxed;
use std::time::{Duration, Instant};

use ark_bn254::{Config, Fr, G2Affine, G2Projective, g2};
use ark_ec::{AffineRepr, VariableBaseMSM, bn::BnConfig, scalar_mul::glv::GLVConfig};
use ark_ff::{AdditiveGroup, BigInt as ArkBigInt, BigInteger, Field, PrimeField, Zero};
use num_bigint::{BigInt, Sign};
use rayon::prelude::*;
use xark_groth16::msm::{self, Scalar};
use zeroize::Zeroizing;

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

// Exact fixed-limb rounding parameters from 39896f2.
const RECIPROCALS: [[u64; 7]; IMAGES] = [
    [
        0x7f9c553cc028af1,
        0xdf7a82efc16af4a4,
        0x500bb9ebe34b87b5,
        0x7d1fff2e5ce18e26,
        0x46f4bda995d51bb1,
        0x8e5da66fc7184ae,
        0x9e80318ab0d92b93,
    ],
    [
        0x139c9c6a3f3db20a,
        0xe7358073326c5b71,
        0xc638c5d5d685c43e,
        0x353ccca0e558c73b,
        0x2dff291532e42728,
        0x55b4ca7ba3e5577f,
        0x9e80318ab0d92b95,
    ],
    [
        0x96ce4aece61f0339,
        0x2e3ff027efccd68a,
        0x8fa7d32d2fafba64,
        0x6eb9c714773a6ef2,
        0xd91d232ec7e0b3d7,
        0x2,
        0x0,
    ],
    [
        0xd86d9429bd1d799a,
        0x5a39b15f89c9f59e,
        0xd69f2f027ee767b0,
        0x23038c29bb8bb4ff,
        0xc170977dcef3cd3f,
        0x55b4ca7ba3e5577d,
        0x9e80318ab0d92b95,
    ],
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

    fn encode<const FIXED: bool>(&self, scalar: &Scalar) -> [Scalar; IMAGES] {
        if !requires_split(scalar) {
            return [
                *scalar,
                Scalar::default(),
                Scalar::default(),
                Scalar::default(),
            ];
        }
        if FIXED {
            return decompose_fixed(scalar.0).map(|part| {
                let magnitude = u64::try_from(part.unsigned_abs()).expect("bounded GLS component");
                encode_signed(magnitude, part < 0)
            });
        }
        self.decompose(scalar).map(|part| {
            let mut limbs = part.iter_u64_digits();
            let magnitude = limbs.next().unwrap_or(0);
            assert!(limbs.next().is_none(), "GLS split exceeded u64 magnitude");
            encode_signed(magnitude, part.sign() == Sign::Minus)
        })
    }
}

fn encode_signed(magnitude: u64, negative: bool) -> Scalar {
    let magnitude = ArkBigInt([magnitude, 0, 0, 0]);
    if negative {
        // Give Xark's existing signed magnitude classes canonical r-k.
        let mut encoded = Fr::MODULUS;
        encoded.sub_with_borrow(&magnitude);
        encoded
    } else {
        magnitude
    }
}

// Each product column needs at most (2^64−1)^2 + 2(2^64−1) = 2^128−1.
// The input is in [0,r), and each reciprocal is <2^448.
fn round_reciprocal(scalar: [u64; 4], factor: [u64; 7]) -> [u64; 3] {
    let mut product = [0u64; 11];
    for (i, a) in scalar.into_iter().enumerate() {
        let mut carry = 0;
        for (j, b) in factor.into_iter().enumerate() {
            let column = u128::from(a) * u128::from(b) + u128::from(product[i + j]) + carry;
            product[i + j] = column as u64;
            carry = column >> 64;
        }
        product[i + factor.len()] = carry as u64;
    }
    let (low, carry) = product[8].overflowing_add(product[7] >> 63);
    let (mid, carry) = product[9].overflowing_add(u64::from(carry));
    [low, mid, product[10] + u64::from(carry)]
}

// The exact centered residual fits in one signed i128. Its low 128 bits
// uniquely encode it, so higher coordinate words are not needed here.
fn decompose_fixed(scalar: [u64; 4]) -> [i128; IMAGES] {
    fn low128(lo: u64, hi: u64) -> u128 {
        u128::from(lo) | (u128::from(hi) << 64)
    }
    let coordinates = RECIPROCALS.map(|factor| round_reciprocal(scalar, factor));
    let mut residual = [low128(scalar[0], scalar[1]), 0, 0, 0];
    for (row, [lo, hi, _]) in BASIS.into_iter().zip(coordinates) {
        let coefficient = low128(lo, hi);
        for (out, entry) in residual.iter_mut().zip(row) {
            *out = out.wrapping_sub(coefficient.wrapping_mul(entry as u128));
        }
    }
    residual.map(|part| part as i128)
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

fn frobenius(point: &G2Affine) -> G2Affine {
    if point.is_zero() {
        return *point;
    }
    let mut x = point.x;
    let mut y = point.y;
    x.frobenius_map_in_place(1);
    y.frobenius_map_in_place(1);
    G2Affine::new_unchecked(x * Config::TWIST_MUL_BY_Q_X, y * Config::TWIST_MUL_BY_Q_Y)
}

fn images(point: &G2Affine) -> [G2Affine; IMAGES] {
    let psi = frobenius(point);
    // On the prime-order subgroup, psi^2 = -phi. Both maps preserve infinity.
    [
        *point,
        psi,
        -g2::Config::endomorphism_affine(point),
        -g2::Config::endomorphism_affine(&psi),
    ]
}

const SIX_U_SQUARED: u128 = 6 * (U as u128) * (U as u128);

const fn signed_check_digits() -> [i8; 128] {
    let mut digits = [0; 128];
    let mut scalar = SIX_U_SQUARED;
    let mut i = 0;
    while scalar != 0 {
        if scalar & 1 != 0 {
            if scalar & 3 == 1 {
                digits[i] = 1;
                scalar -= 1;
            } else {
                digits[i] = -1;
                scalar += 1;
            }
        }
        scalar >>= 1;
        i += 1;
    }
    digits
}

const CHECK_DIGITS: [i8; 128] = signed_check_digits();
const _: () = assert!(CHECK_DIGITS[127] == 1);

// The integer multiplication is valid on the full twist, even for points
// outside the target subgroup. No scalar reduction or GLV identity is used.
fn multiply_check_scalar(point: &G2Affine) -> G2Projective {
    let mut value = G2Projective::from(*point);
    let negated = -*point;
    for digit in CHECK_DIGITS[..127].iter().rev() {
        value.double_in_place();
        match digit {
            1 => value += *point,
            -1 => value += negated,
            _ => (),
        }
    }
    value
}

fn signed_subgroup(point: &G2Affine) -> bool {
    point.is_zero() || multiply_check_scalar(point).eq(&frobenius(point))
}

fn check_subgroup(bases: &[G2Affine], signed: bool) -> Result<(), usize> {
    let check = if signed {
        signed_subgroup
    } else {
        G2Affine::is_in_correct_subgroup_assuming_on_curve
    };
    match bases
        .par_iter()
        .position_any(|p| !p.is_on_curve() || !check(p))
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

    fn recode<const FIXED: bool>(
        &self,
        recoder: &Recoder,
        scalars: &[Scalar],
    ) -> Zeroizing<Box<[Scalar]>> {
        assert_eq!(self.points.len() / IMAGES, scalars.len());
        // Put the backing allocation under the wipe guard before copying any
        // witness-derived values into it, including during Rayon unwinding.
        let mut parts =
            Zeroizing::new(vec![Scalar::default(); self.points.len()].into_boxed_slice());
        parts
            .par_chunks_exact_mut(IMAGES)
            .zip(self.points.par_chunks_exact(IMAGES))
            .zip(scalars)
            .with_min_len(128)
            .for_each(|((out, images), scalar)| {
                if !images[0].is_zero() {
                    out.copy_from_slice(&recoder.encode::<FIXED>(scalar));
                }
            });
        parts
    }
}

/// The complete-proof comparison keeps validated public inputs resident.
#[cfg(feature = "msm-g2-shifted-bench")]
pub(crate) struct ResidentCachedGls<'a> {
    bases: &'a [G2Affine],
    cache: CachedImages,
    recoder: Recoder,
}

#[cfg(feature = "msm-g2-shifted-bench")]
impl<'a> ResidentCachedGls<'a> {
    pub(crate) fn new(bases: &'a [G2Affine], signed: bool) -> Result<Self, String> {
        check_subgroup(bases, signed)
            .map_err(|index| format!("B2 base {index} is outside the BN254 G2 subgroup"))?;
        let cache = CachedImages::new(bases).map_err(str::to_owned)?;
        Ok(Self {
            bases,
            cache,
            recoder: Recoder::new(),
        })
    }

    pub(crate) fn payload_bytes(&self) -> usize {
        self.cache.points.len() * size_of::<G2Affine>()
    }

    pub(crate) fn msm(&self, bases: &[G2Affine], scalars: &[Scalar]) -> G2Projective {
        assert!(
            std::ptr::eq(self.bases, bases),
            "cached GLS B2 key mismatch"
        );
        let recoded = self.cache.recode::<true>(&self.recoder, scalars);
        msm::msm::<G2Projective>(&self.cache.points, &recoded)
    }
}

pub(crate) fn run_subgroup_pairs(args: &[String]) {
    let [key, pairs] = args else {
        panic!("usage: bench_prove check-g2-subgroup PROVING_KEY PAIRS");
    };
    let pairs: usize = pairs.parse().expect("number of pairs");
    assert!(pairs > 0);
    let key = xark_backend::Groth16Keys::read_proving_key(Path::new(key)).expect("load key");
    let bases = &key.b_g2_query;
    assert!(!bases.is_empty(), "empty B2 key");
    assert!(
        bases
            .par_iter()
            .all(|p| p.is_on_curve() && p.mul_bigint(Fr::MODULUS).is_zero()),
        "independent full-order reference rejected the B2 key"
    );
    println!("G2 full-order reference verified points={}", bases.len());
    println!(
        "G2 validation points={} threads={}",
        bases.len(),
        rayon::current_num_threads()
    );
    for pair in 0..=pairs {
        let signed_first = pair % 2 == 0;
        let timed_check = |signed| {
            let start = Instant::now();
            let checked = check_subgroup(bases, signed);
            let elapsed = start.elapsed();
            assert_eq!(checked, Ok(()));
            elapsed.as_nanos()
        };
        let (binary, signed) = if signed_first {
            let signed = timed_check(true);
            (timed_check(false), signed)
        } else {
            (timed_check(false), timed_check(true))
        };
        if pair > 0 {
            println!(
                "G2 validation verified pair={pair} signed_first={signed_first} binary_ns={binary} signed_ns={signed}"
            );
        }
    }
}

struct CandidateTiming {
    total: Duration,
    recode: Duration,
    msm: Duration,
}

pub(crate) fn run<const FIXED: bool>(args: &[String]) {
    let mode = if FIXED {
        "query-msm-b2-cached-gls-reciprocal"
    } else {
        "query-msm-b2-cached-gls"
    };
    let [xbc_path, pk_path, directory, options @ ..] = args else {
        panic!(
            "usage: bench_prove {mode} <circuit.xbc> <reduced pk.bin> <statement-dir> [samples] [warmups]"
        );
    };
    let (samples, warmups) = super::counts(options).unwrap_or_else(|reason| panic!("{reason}"));
    assert!(!super::super::tracking(), "set BENCH_TIME=1 to time GLS");
    let ((pk, scalars), fixture_load) =
        super::timed(|| super::load(xbc_path, pk_path, Path::new(directory)));
    let bases = &pk.b_g2_query;
    // The normal trusted proving-key decoder deliberately skips this check.
    let (subgroup, subgroup_check) = super::timed(|| check_subgroup(bases, false));
    if let Err(index) = subgroup {
        panic!("B2 base {index} is outside the BN254 G2 subgroup");
    }
    let (recoder, recoder_setup) = super::timed(Recoder::new);
    let (cache, prepare) =
        super::timed(|| CachedImages::new(bases).expect("prepare signed GLS bases"));
    if FIXED {
        assert!(
            cache.recode::<false>(&recoder, &scalars)[..]
                == cache.recode::<true>(&recoder, &scalars)[..],
            "fixed-width and division recodings differ on the fixture"
        );
    }
    let (expected, oracle) = super::timed(|| G2Projective::msm_bigint(bases, &scalars));
    let baseline = || super::timed(|| msm::msm::<G2Projective>(bases, &scalars));
    let candidate = || {
        let start = Instant::now();
        let (recoded, recode) = super::timed(|| cache.recode::<FIXED>(&recoder, &scalars));
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
    let rounding = if FIXED { "fixed-limb" } else { "division" };
    println!(
        "query msm B2 cached GLS verified: terms={} threads={} samples={samples} warmups={warmups} subgroup_points={} xark_glv={} xark_batch_affine={} table_payload_bytes={} table_cap_bytes={TABLE_CAP_BYTES} scalar_scratch_bytes={} recoder_setup_ns={} prepare_ns={} rounding={rounding} fixture_load_ns={} subgroup_check_ns={} oracle_ns={}",
        bases.len(),
        rayon::current_num_threads(),
        bases.len(),
        msm::GLV.load(Relaxed),
        msm::BATCH_AFFINE.load(Relaxed),
        cache.points.len() * size_of::<G2Affine>(),
        cache.points.len() * size_of::<Scalar>(),
        recoder_setup.as_nanos(),
        prepare.as_nanos(),
        fixture_load.as_nanos(),
        subgroup_check.as_nanos(),
        oracle.as_nanos(),
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
            let split = r.encode::<false>(&scalar);
            assert_eq!(split, r.encode::<true>(&scalar));
            assert_eq!(
                r.decompose(&scalar),
                decompose_fixed(scalar.0).map(BigInt::from)
            );
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
                r.encode::<true>(&coefficient),
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
        assert_eq!(check_subgroup(&bases, false), Ok(()));
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
        let encoded = cache.recode::<true>(&Recoder::new(), &scalars);
        let expected = G2Projective::msm_bigint(&bases, &scalars);
        assert_eq!(msm::msm::<G2Projective>(&cache.points, &encoded), expected);
        #[cfg(feature = "msm-g2-shifted-bench")]
        assert_eq!(
            ResidentCachedGls::new(&bases, true)
                .unwrap()
                .msm(&bases, &scalars),
            expected
        );
    }

    // This is an operation-shape model for deterministic synthetic scalars,
    // not a memory trace or a constant-time test. It follows msm.rs's class,
    // GLV and window rules so the reported bucket updates are comparable.
    #[test]
    fn synthetic_cached_gls_bucket_shape_matches_both_group_results() {
        const CLASS_BITS: [usize; 6] = [1, 16, 32, 64, 128, 256];

        fn bits_at(s: &Scalar, pos: usize, len: usize) -> u64 {
            let (q, r) = (pos / 64, pos % 64);
            if q >= 4 {
                return 0;
            }
            let mut value = s.0[q] >> r;
            if r + len > 64 && q + 1 < 4 {
                value |= s.0[q + 1] << (64 - r);
            }
            value & ((1u64 << len) - 1)
        }

        fn digit(s: &Scalar, window: usize, width: usize) -> i64 {
            let pos = window * width;
            let value = bits_at(s, pos, width) as i64;
            let carry = if pos == 0 {
                0
            } else {
                bits_at(s, pos - 1, 1) as i64
            };
            value + carry - (((value >> (width - 1)) & 1) << width)
        }

        fn width(n: usize, bits: usize) -> usize {
            let cost = |c: usize| {
                let buckets = 1usize << (c - 1);
                let add = if buckets >= 64 && n >= 4 * buckets {
                    let turned_away = if buckets >= 256 {
                        0.1 * (512.0 / buckets as f64).min(1.0)
                    } else {
                        0.0
                    };
                    0.6 + 10.0 / buckets.min(512) as f64 + turned_away
                } else {
                    1.0
                };
                (bits + 1).div_ceil(c) as f64 * (n as f64 * add + 0.8 * (1u64 << c) as f64)
            };
            (2..=15)
                .min_by(|&a, &b| cost(a).total_cmp(&cost(b)))
                .unwrap()
        }

        #[derive(Debug, Default)]
        struct Shape {
            classes: [usize; 6],
            glv_terms: usize,
            unit_additions: usize,
            bucket_updates: usize,
            window_rows: usize,
        }

        fn shape(scalars: &[Scalar]) -> Shape {
            let mut groups: [Vec<Scalar>; 6] = std::array::from_fn(|_| Vec::new());
            for &scalar in scalars {
                if scalar.is_zero() {
                    continue;
                }
                let positive_bits = scalar.num_bits() as usize;
                let mut magnitude = scalar;
                if positive_bits > 128 {
                    let mut negative = Fr::MODULUS;
                    negative.sub_with_borrow(&scalar);
                    if (negative.num_bits() as usize) < positive_bits {
                        magnitude = negative;
                    }
                }
                if magnitude.is_zero() {
                    continue;
                }
                let class = CLASS_BITS
                    .iter()
                    .position(|&bits| magnitude.num_bits() as usize <= bits)
                    .unwrap();
                groups[class].push(if class == 5 { scalar } else { magnitude });
            }
            let mut out = Shape {
                classes: groups.each_ref().map(Vec::len),
                unit_additions: groups[0].len(),
                ..Shape::default()
            };
            for (class, values) in groups.into_iter().enumerate().skip(1) {
                if values.is_empty() {
                    continue;
                }
                let (values, bits) = if class == 5
                    && values.len() * rayon::current_num_threads() <= 1 << 16
                {
                    let mut parts = Vec::with_capacity(2 * values.len());
                    for scalar in values {
                        let ((_, left), (_, right)) = xark_groth16::glv::g2().decompose(&scalar);
                        parts.extend([left, right]);
                    }
                    out.glv_terms += parts.len();
                    (parts, 128)
                } else {
                    (values, CLASS_BITS[class])
                };
                let c = width(values.len(), bits);
                let windows = (bits + 1).div_ceil(c);
                out.window_rows += windows;
                out.bucket_updates += values
                    .iter()
                    .flat_map(|scalar| (0..windows).map(move |w| digit(scalar, w, c)))
                    .filter(|&d| d != 0)
                    .count();
            }
            out
        }

        for n in [256, 5_406, 7_606] {
            let generator = G2Projective::generator();
            let bases: Vec<_> = (1..=n)
                .map(|i| generator.mul_bigint([i as u64]).into_affine())
                .collect();
            let cache = CachedImages::new(&bases).unwrap();
            let recoder = Recoder::new();
            let mut rng = ChaCha20Rng::seed_from_u64(0xacc355);
            let random: Vec<_> = (0..n).map(|_| Fr::rand(&mut rng).into_bigint()).collect();
            let small: Vec<_> = (0..n)
                .map(|i| Fr::from((i % 17 + 1) as u64).into_bigint())
                .collect();
            let near_modulus: Vec<_> = small
                .iter()
                .map(|scalar| {
                    let mut negative = Fr::MODULUS;
                    negative.sub_with_borrow(scalar);
                    negative
                })
                .collect();
            let sparse: Vec<_> = (0..n)
                .map(|i| {
                    let bit = [0, 63, 127, 128, 190, 252][i % 6];
                    let mut limbs = [0u64; 4];
                    limbs[bit / 64] = 1u64 << (bit % 64);
                    ArkBigInt(limbs)
                })
                .collect();

            for (name, scalars) in [
                ("zero", vec![Scalar::default(); n]),
                ("small", small),
                ("near-modulus", near_modulus),
                ("sparse", sparse),
                ("random", random),
            ] {
                let recoded = cache.recode::<true>(&recoder, &scalars);
                let oracle = G2Projective::msm_bigint(&bases, &scalars);
                #[cfg(feature = "msm-access-audit")]
                let _ = msm::access_audit::take();
                assert_eq!(msm::msm::<G2Projective>(&bases, &scalars), oracle);
                #[cfg(feature = "msm-access-audit")]
                let ordinary_access = msm::access_audit::take();
                assert_eq!(msm::msm::<G2Projective>(&cache.points, &recoded), oracle);
                #[cfg(feature = "msm-access-audit")]
                let cached_access = msm::access_audit::take();
                let ordinary = shape(&scalars);
                let cached = shape(&recoded);
                eprintln!("synthetic n={n} {name}: ordinary={ordinary:?} cached_gls={cached:?}");
                #[cfg(feature = "msm-access-audit")]
                {
                    assert_eq!(
                        ordinary_access.window_base_reads as usize,
                        ordinary.bucket_updates
                    );
                    assert_eq!(
                        cached_access.window_base_reads as usize,
                        cached.bucket_updates
                    );
                    assert_eq!(
                        ordinary_access.affine_adds + ordinary_access.projective_updates,
                        ordinary_access.window_base_reads
                    );
                    assert_eq!(
                        cached_access.affine_adds + cached_access.projective_updates,
                        cached_access.window_base_reads
                    );
                    eprintln!(
                        "executed synthetic n={n} {name}: ordinary={ordinary_access:?} cached_gls={cached_access:?}"
                    );
                }
                assert_eq!(ordinary.unit_additions, cached.unit_additions);
                if name == "random" {
                    assert!(ordinary.glv_terms > 0);
                    assert_eq!(cached.glv_terms, 0);
                    assert!(cached.classes[4] == 0 && cached.classes[5] == 0);
                    assert!(cached.window_rows < ordinary.window_rows);
                }
            }
        }

        // Explicit local-only extension. The fixture is synthetic and the test
        // target is never part of a production prover binary. The caller must
        // verify its manifest before setting this environment variable.
        if let Ok(root) = std::env::var("XARK_SYNTHETIC_FIXTURE_ROOT") {
            let root = Path::new(&root);
            for circuit in ["escrow", "withdrawal"] {
                let reference = root.join("reference").join(circuit);
                let requests = root.join("requests").join(circuit).join("1");
                let request: Vec<_> = std::fs::read_dir(requests)
                    .unwrap()
                    .map(|entry| entry.unwrap().path())
                    .collect();
                assert_eq!(request.len(), 1, "one pinned synthetic request");
                let (key, scalars) = super::super::load(
                    reference.join("circuit.xbc").to_str().unwrap(),
                    reference.join("test-key.bin").to_str().unwrap(),
                    &request[0],
                );
                let scalars = Zeroizing::new(scalars);
                let bases = &key.b_g2_query;
                let cache = CachedImages::new(bases).unwrap();
                let recoded = cache.recode::<true>(&Recoder::new(), &scalars);
                let expected = G2Projective::msm_bigint(bases, &scalars);
                #[cfg(feature = "msm-access-audit")]
                let _ = msm::access_audit::take();
                assert_eq!(msm::msm::<G2Projective>(bases, &scalars), expected);
                #[cfg(feature = "msm-access-audit")]
                let ordinary_access = msm::access_audit::take();
                assert_eq!(msm::msm::<G2Projective>(&cache.points, &recoded), expected);
                #[cfg(feature = "msm-access-audit")]
                let cached_access = msm::access_audit::take();
                let visible = Zeroizing::new(
                    bases
                        .iter()
                        .zip(scalars.iter())
                        .map(|(point, scalar)| {
                            if point.is_zero() {
                                Scalar::default()
                            } else {
                                *scalar
                            }
                        })
                        .collect::<Vec<_>>(),
                );
                eprintln!(
                    "pinned synthetic fixture {circuit}: ordinary={:?} cached_gls={:?}",
                    shape(&visible),
                    shape(&recoded)
                );
                #[cfg(feature = "msm-access-audit")]
                {
                    assert_eq!(
                        ordinary_access.window_base_reads as usize,
                        shape(&visible).bucket_updates
                    );
                    assert_eq!(
                        cached_access.window_base_reads as usize,
                        shape(&recoded).bucket_updates
                    );
                    eprintln!(
                        "executed pinned synthetic fixture {circuit}: ordinary={ordinary_access:?} cached_gls={cached_access:?}"
                    );
                }
            }
        }
    }

    #[cfg(all(feature = "msm-access-audit", feature = "msm-window-audit"))]
    #[test]
    fn cached_gls_public_window_sweep_matches_arkworks() {
        struct ResetWindow;
        impl Drop for ResetWindow {
            fn drop(&mut self) {
                msm::set_audit_g2_window_delta(0);
            }
        }
        let _reset = ResetWindow;

        fn sweep(label: &str, bases: &[G2Affine], scalars: &[Scalar]) {
            let cache = CachedImages::new(bases).unwrap();
            let recoded = cache.recode::<true>(&Recoder::new(), scalars);
            let expected = G2Projective::msm_bigint(bases, scalars);
            for delta in [-1, 0, 1] {
                msm::set_audit_g2_window_delta(delta);
                let _ = msm::access_audit::take();
                let actual = msm::msm::<G2Projective>(&cache.points, &recoded);
                let counts = msm::access_audit::take();
                assert_eq!(actual, expected, "{label} delta={delta}");
                assert_eq!(
                    counts.affine_adds + counts.projective_updates,
                    counts.window_base_reads,
                    "{label} delta={delta}"
                );
                eprintln!(
                    "window-audit {label} delta={delta} gather={} window_reads={} affine_adds={} attempts={} conflicts={} spills={} flushes={} projective={} reduction_slots={}",
                    counts.gather_reads,
                    counts.window_base_reads,
                    counts.affine_adds,
                    counts.place_attempts,
                    counts.place_conflicts,
                    counts.spill_adds,
                    counts.nonempty_flushes,
                    counts.projective_updates,
                    counts.reduction_slots
                );
            }
        }

        let generator = G2Projective::generator();
        let bases: Vec<_> = (1..=256u64)
            .map(|i| generator.mul_bigint([i]).into_affine())
            .collect();
        let mut rng = ChaCha20Rng::seed_from_u64(0xacc355);
        let scalars: Vec<_> = (0..bases.len())
            .map(|_| Fr::rand(&mut rng).into_bigint())
            .collect();
        sweep("synthetic-256", &bases, &scalars);

        if let Ok(root) = std::env::var("XARK_SYNTHETIC_FIXTURE_ROOT") {
            let root = Path::new(&root);
            for circuit in ["escrow", "withdrawal"] {
                let reference = root.join("reference").join(circuit);
                let requests = root.join("requests").join(circuit).join("1");
                let request: Vec<_> = std::fs::read_dir(requests)
                    .unwrap()
                    .map(|entry| entry.unwrap().path())
                    .collect();
                assert_eq!(request.len(), 1, "one pinned synthetic request");
                let (key, scalars) = super::super::load(
                    reference.join("circuit.xbc").to_str().unwrap(),
                    reference.join("test-key.bin").to_str().unwrap(),
                    &request[0],
                );
                let scalars = Zeroizing::new(scalars);
                sweep(circuit, &key.b_g2_query, &scalars);
            }
        }
    }

    #[cfg(feature = "msm-g2-shifted-bench")]
    #[test]
    #[should_panic(expected = "cached GLS B2 key mismatch")]
    fn resident_gls_rejects_another_key_buffer() {
        let bases = vec![G2Affine::generator()];
        let other = bases.clone();
        let table = ResidentCachedGls::new(&bases, false).unwrap();
        let _ = table.msm(&other, &[Scalar::default()]);
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
        for signed in [false, true] {
            assert_eq!(
                check_subgroup(&[G2Affine::generator(), point], signed),
                Err(1)
            );
        }
        #[cfg(feature = "msm-g2-shifted-bench")]
        assert!(ResidentCachedGls::new(&[G2Affine::generator(), point], true).is_err());
    }

    #[test]
    fn signed_public_scalar_and_predicate_match_independent_group_checks() {
        let reconstructed = CHECK_DIGITS.iter().rev().fold(0u128, |n, &digit| {
            (2 * n).checked_add_signed(i128::from(digit)).unwrap()
        });
        assert_eq!(reconstructed, SIX_U_SQUARED);
        assert_eq!(CHECK_DIGITS.iter().filter(|&&d| d != 0).count(), 40);
        assert!(CHECK_DIGITS.windows(2).all(|w| w[0] == 0 || w[1] == 0));
        let scalar = [SIX_U_SQUARED as u64, (SIX_U_SQUARED >> 64) as u64];

        let curve_points = (0..48u64).filter_map(|x| {
            G2Affine::get_point_from_x_unchecked(Fq2::new(Fq::from(x), Fq::ONE), false)
        });
        let subgroup_points = (1..=16).map(|n| G2Affine::generator().mul_bigint([n]).into_affine());
        let mut outsiders = 0;
        for p in curve_points
            .chain(subgroup_points)
            .chain([G2Affine::identity()])
        {
            assert!(p.is_on_curve());
            let full_order_check = p.mul_bigint(Fr::MODULUS).is_zero();
            outsiders += usize::from(!full_order_check);
            assert_eq!(multiply_check_scalar(&p), p.mul_bigint(scalar));
            assert_eq!(signed_subgroup(&p), full_order_check);
            assert_eq!(
                p.is_in_correct_subgroup_assuming_on_curve(),
                full_order_check
            );
        }
        assert!(outsiders > 0);
        let off_curve = G2Affine::new_unchecked(Fq2::ZERO, Fq2::ONE);
        assert!(!off_curve.is_on_curve());
        assert_eq!(check_subgroup(&[off_curve], true), Err(0));
    }
}
