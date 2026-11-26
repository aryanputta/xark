//! Isolate four exact GLS lattice roundings on the pinned test-query shapes.

use std::hint::black_box;
use std::path::Path;
use std::time::Instant;

use num_bigint::{BigInt, BigUint};

const MODULUS: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";
const COFACTORS: [&str; 4] = [
    "734653495049373973658254490726798021314063399421879442165",
    "734653495049373973806201247608587340319794091592875701774",
    "9931322734385697763",
    "734653495049373973806201247608587340314828430225682852893",
];
const RECIPROCALS: [[u64; 7]; 4] = [
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

const U: i128 = 4_965_661_367_192_848_881;
const BASIS: [[i128; 4]; 4] = [
    [2 * U, U + 1, -U, U],
    [2 * U + 1, 0, 2 * U, 1],
    [U + 1, U, U, -2 * U],
    [2 * U + 1, -U, -U - 1, -U],
];

#[derive(Clone)]
struct Scalar {
    value: BigUint,
    words: [u64; 4],
}

impl Scalar {
    fn new(value: BigUint) -> Self {
        let words = words(&value);
        Self { value, words }
    }
}

fn words<const N: usize>(value: &BigUint) -> [u64; N] {
    let mut result = [0; N];
    for (i, limb) in value.iter_u64_digits().enumerate() {
        result[i] = limb;
    }
    result
}

struct ExactDivision {
    modulus: BigUint,
    half: BigUint,
    cofactors: [BigUint; 4],
}

impl ExactDivision {
    fn new() -> Self {
        let modulus: BigUint = MODULUS.parse().expect("BN254 scalar modulus");
        let half = &modulus >> 1;
        let cofactors = COFACTORS.map(|c| c.parse().expect("lattice cofactor"));
        Self {
            modulus,
            half,
            cofactors,
        }
    }

    fn coordinates(&self, scalar: &Scalar) -> [BigUint; 4] {
        self.cofactors
            .each_ref()
            .map(|c| (&scalar.value * c + &self.half) / &self.modulus)
    }

    fn round(&self, scalar: &Scalar) -> [[u64; 3]; 4] {
        self.coordinates(scalar).each_ref().map(words)
    }

    fn decompose(&self, scalar: &Scalar) -> [i128; 4] {
        let mut residual = [
            BigInt::from(scalar.value.clone()),
            BigInt::ZERO,
            BigInt::ZERO,
            BigInt::ZERO,
        ];
        for (row, coefficient) in BASIS.into_iter().zip(self.coordinates(scalar)) {
            let coefficient = BigInt::from(coefficient);
            for (out, entry) in residual.iter_mut().zip(row) {
                *out -= &coefficient * entry;
            }
        }
        residual.map(|part| i128::try_from(part).expect("bounded GLS component"))
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

fn reciprocal(scalar: &Scalar) -> [[u64; 3]; 4] {
    RECIPROCALS.map(|factor| round_reciprocal(scalar.words, factor))
}

// Every true signed residual is below 2^64 in magnitude. Calculating it modulo
// 2^128 and reinterpreting it as signed therefore reconstructs it uniquely.
fn decompose_fixed(scalar: &Scalar) -> [i128; 4] {
    fn low128(lo: u64, hi: u64) -> u128 {
        u128::from(lo) | (u128::from(hi) << 64)
    }
    let mut residual = [low128(scalar.words[0], scalar.words[1]), 0, 0, 0];
    for (row, [lo, hi, _]) in BASIS.into_iter().zip(reciprocal(scalar)) {
        let coefficient = low128(lo, hi);
        for (out, entry) in residual.iter_mut().zip(row) {
            *out = out.wrapping_sub(coefficient.wrapping_mul(entry as u128));
        }
    }
    residual.map(|part| part as i128)
}

fn load(path: &Path, exact: &ExactDivision) -> Vec<Scalar> {
    let input = std::fs::read(path).expect("read test query export");
    assert_eq!(&input[..8], b"XKQMSM01");
    let count = u32::from_le_bytes(input[8..12].try_into().unwrap()) as usize;
    assert!([5_406, 7_606].contains(&count), "unexpected test query");
    let data_end = 12 + count * 224;
    assert_eq!(input.len(), data_end + 192);
    input[12..data_end]
        .chunks_exact(224)
        .filter(|row| row[96..].iter().any(|x| *x != 0))
        .filter_map(|row| {
            let value = BigUint::from_bytes_be(&row[..32]);
            assert!(value < exact.modulus, "noncanonical test scalar");
            let negative = &exact.modulus - &value;
            (value.bits().min(negative.bits()) > 128).then(|| Scalar::new(value))
        })
        .collect()
}

fn time<T>(scalars: &[Scalar], round: impl Fn(&Scalar) -> T) -> u128 {
    let start = Instant::now();
    for _ in 0..10 {
        for scalar in scalars {
            black_box(round(black_box(scalar)));
        }
    }
    start.elapsed().as_nanos()
}

fn main() {
    let mut args = std::env::args_os().skip(1);
    let path = args
        .next()
        .expect("provide a pinned synthetic B2 query export");
    let full = match args.next().as_deref() {
        None => false,
        Some(flag) if flag == "--full" => true,
        Some(_) => panic!("expected --full"),
    };
    assert!(args.next().is_none());
    let exact = ExactDivision::new();
    let scalars = load(Path::new(&path), &exact);
    assert!(
        [4_282, 5_892].contains(&scalars.len()),
        "unexpected wide scalar count"
    );
    for scalar in &scalars {
        assert!(
            exact.round(scalar) == reciprocal(scalar),
            "roundings differ"
        );
        assert!(
            exact.decompose(scalar) == decompose_fixed(scalar),
            "decompositions differ"
        );
    }
    let division = || {
        if full {
            time(&scalars, |scalar| exact.decompose(scalar))
        } else {
            time(&scalars, |scalar| exact.round(scalar))
        }
    };
    let fixed = || {
        if full {
            time(&scalars, decompose_fixed)
        } else {
            time(&scalars, reciprocal)
        }
    };
    black_box((division(), fixed()));
    eprintln!(
        "verified {} wide fixture scalars with exact division",
        scalars.len()
    );
    println!("pair,division_first,division_ns,reciprocal_ns");
    for i in 0..12 {
        let division_first = i % 2 == 0;
        let (old, new) = if division_first {
            (division(), fixed())
        } else {
            let new = fixed();
            (division(), new)
        };
        println!("{},{division_first},{old},{new}", i + 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_reciprocal_rounding_at_scalar_and_carry_boundaries() {
        let exact = ExactDivision::new();
        for (cofactor, factor) in exact.cofactors.iter().zip(RECIPROCALS) {
            let mut bytes = [0; 56];
            for (offset, limb) in factor.into_iter().enumerate() {
                bytes[8 * offset..8 * (offset + 1)].copy_from_slice(&limb.to_le_bytes());
            }
            let k = BigUint::from_bytes_le(&bytes);
            let numerator = cofactor << 512;
            assert!(k.clone() * &exact.modulus <= numerator);
            assert!((k + 1u8) * &exact.modulus > numerator);
        }
        let edge = [
            BigUint::from(0u8),
            BigUint::from(1u8),
            &exact.modulus >> 1,
            &exact.modulus - 1u8,
            BigUint::from(1u8) << 128,
        ];
        let mut state: u64 = 731;
        for value in edge.into_iter().chain((0..4096).map(|_| {
            let mut bytes = [0; 32];
            for limb in bytes.chunks_exact_mut(8) {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                limb.copy_from_slice(&state.to_le_bytes());
            }
            BigUint::from_bytes_le(&bytes) % &exact.modulus
        })) {
            let scalar = Scalar::new(value);
            assert!(reciprocal(&scalar) == exact.round(&scalar));
            assert!(decompose_fixed(&scalar) == exact.decompose(&scalar));
        }
    }
}
