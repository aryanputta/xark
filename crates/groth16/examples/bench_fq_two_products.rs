//! Compare an interleaved portable two-product prototype with Arkworks Fq sum_of_products.
//! The prototype is benchmark-only and is not called by the prover.

use std::hint::black_box;
use std::time::Instant;

use ark_bn254::Fq;
use ark_ff::{BigInt, BigInteger, Field, PrimeField, UniformRand};
use num_bigint::BigUint;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

const LIMBS: usize = 4;
const MODULUS: [u64; LIMBS] = Fq::MODULUS.0;

const fn negative_inverse(word: u64) -> u64 {
    let mut inverse = 1u64;
    let mut bits = 1;
    while bits < 64 {
        inverse = inverse.wrapping_mul(2u64.wrapping_sub(word.wrapping_mul(inverse)));
        bits *= 2;
    }
    inverse.wrapping_neg()
}

const INV: u64 = negative_inverse(MODULUS[0]);

fn accumulate_row(t: &mut [u64; 9], offset: usize, a: u64, b: &[u64; LIMBS]) {
    let mut carry = 0;
    for (slot, limb) in t[offset..offset + LIMBS].iter_mut().zip(b) {
        // (2^64 - 1)^2 + two 64-bit words fits exactly in a u128.
        let sum = u128::from(a) * u128::from(*limb) + u128::from(*slot) + u128::from(carry);
        *slot = sum as u64;
        carry = (sum >> 64) as u64;
    }
    for slot in &mut t[offset + LIMBS..] {
        let (sum, overflow) = slot.overflowing_add(carry);
        *slot = sum;
        carry = u64::from(overflow);
    }
    debug_assert_eq!(carry, 0);
}

fn two_products(values: &[Fq; 4]) -> Fq {
    let mut t = [0u64; 9];
    let [a, b, c, d] = values;
    // Higher operand rows start at i+1 or later, so they cannot affect the
    // low word used to choose this Montgomery factor. Retiring it here
    // preserves the same REDC operation as accumulating both full products.
    for i in 0..LIMBS {
        accumulate_row(&mut t, i, a.0.0[i], &b.0.0);
        accumulate_row(&mut t, i, c.0.0[i], &d.0.0);
        let factor = t[i].wrapping_mul(INV);
        accumulate_row(&mut t, i, factor, &MODULUS);
        debug_assert_eq!(t[i], 0);
    }
    debug_assert_eq!(t[8], 0);
    let mut limbs = [0; LIMBS];
    limbs.copy_from_slice(&t[LIMBS..LIMBS * 2]);
    let mut difference = [0; LIMBS];
    let mut borrow = false;
    for ((out, word), modulus) in difference.iter_mut().zip(limbs).zip(MODULUS) {
        let (d, first) = word.overflowing_sub(modulus);
        let (d, second) = d.overflowing_sub(u64::from(borrow));
        *out = d;
        borrow = first | second;
    }
    let use_original = 0u64.wrapping_sub(u64::from(borrow));
    for (word, reduced) in limbs.iter_mut().zip(difference) {
        *word = (*word & use_original) | (reduced & !use_original);
    }
    Fq::new_unchecked(BigInt(limbs))
}

fn baseline([a, b, c, d]: &[Fq; 4]) -> Fq {
    Fq::sum_of_products(&[*a, *c], &[*b, *d])
}

fn reference([a, b, c, d]: &[Fq; 4]) -> BigUint {
    let integer = |f: &Fq| BigUint::from_bytes_le(&f.into_bigint().to_bytes_le());
    let modulus = BigUint::from_bytes_le(&Fq::MODULUS.to_bytes_le());
    (integer(a) * integer(b) + integer(c) * integer(d)) % modulus
}

fn checked(values: &[Fq; 4]) {
    let proposed = two_products(values);
    assert_eq!(proposed, baseline(values));
    assert_eq!(
        BigUint::from_bytes_le(&proposed.into_bigint().to_bytes_le()),
        reference(values)
    );
}

fn inputs(count: usize) -> Vec<[Fq; 4]> {
    let mut rng = ChaCha20Rng::seed_from_u64(947);
    (0..count)
        .map(|_| std::array::from_fn(|_| Fq::rand(&mut rng)))
        .collect()
}

// POSIX clock() counts process CPU time, independent of time descheduled.
#[cfg(unix)]
fn cpu_ticks() -> Option<i64> {
    unsafe extern "C" {
        fn clock() -> std::ffi::c_long;
    }
    // SAFETY: clock needs no arguments and does not access Rust-owned data.
    let ticks = unsafe { clock() } as i64;
    (ticks >= 0).then_some(ticks)
}

#[cfg(not(unix))]
fn cpu_ticks() -> Option<i64> {
    None
}

fn measure(inputs: &[[Fq; 4]], operation: impl Fn(&[Fq; 4]) -> Fq) -> (u128, Option<i64>) {
    let cpu_started = cpu_ticks();
    let started = Instant::now();
    for values in inputs {
        black_box(operation(black_box(values)));
    }
    let elapsed = started.elapsed().as_nanos();
    let cpu_elapsed = cpu_ticks().zip(cpu_started).map(|(end, start)| end - start);
    (elapsed, cpu_elapsed)
}

fn main() {
    let count = std::env::args().nth(1).map_or(65_536, |n| {
        n.parse::<usize>().expect("supply a positive operand count")
    });
    assert!(count >= 1024);
    let values = inputs(count);
    for item in &values {
        checked(item);
    }
    black_box(measure(&values, baseline));
    black_box(measure(&values, two_products));
    println!(
        "round,operations,candidate_first,arkworks_ns,prototype_ns,arkworks_cpu_ticks,prototype_cpu_ticks"
    );
    for round in 0..12 {
        let candidate_first = round % 2 == 1;
        let (arkworks, prototype) = if candidate_first {
            let prototype = measure(&values, two_products);
            (measure(&values, baseline), prototype)
        } else {
            let arkworks = measure(&values, baseline);
            (arkworks, measure(&values, two_products))
        };
        let field =
            |measurement: Option<i64>| measurement.map_or(String::new(), |ticks| ticks.to_string());
        println!(
            "{},{count},{candidate_first},{},{},{},{}",
            round + 1,
            arkworks.0,
            prototype.0,
            field(arkworks.1),
            field(prototype.1)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edge_products_match_both_oracles() {
        assert_eq!(MODULUS[0].wrapping_mul(INV), u64::MAX);
        let edges = [
            Fq::from(0),
            Fq::from(1),
            Fq::from(u64::MAX),
            -Fq::from(1),
            -Fq::from(2),
        ];
        for a in edges {
            for b in edges {
                for c in edges {
                    for d in edges {
                        checked(&[a, b, c, d]);
                    }
                }
            }
        }
    }

    #[test]
    fn seeded_products_match_both_oracles() {
        for item in inputs(4096) {
            checked(&item);
        }
    }
}
