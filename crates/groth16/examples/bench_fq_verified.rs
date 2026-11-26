//! Isolate BN254 base-field operations on seeded and boundary inputs.
//! Run `cargo run --release -p xark-groth16 --example bench_fq_verified`.

use std::hint::black_box;
use std::time::Instant;

use ark_bn254::Fq;
use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField, UniformRand};
use num_bigint::BigUint;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

const CASES: usize = 2048;
const REPEATS: usize = 64;
const SAMPLES: usize = 15;

fn measure(
    label: &str,
    inputs: &[[Fq; 4]],
    expected: impl Fn(&[BigUint; 4]) -> BigUint,
    operation: impl Fn([Fq; 4]) -> Fq,
) {
    let modulus = BigUint::from_bytes_be(&Fq::MODULUS.to_bytes_be());
    let reference: Vec<_> = inputs
        .iter()
        .map(|row| {
            let integers = row.map(|x| BigUint::from_bytes_be(&x.into_bigint().to_bytes_be()));
            expected(&integers) % &modulus
        })
        .collect();
    let mut output = vec![Fq::ZERO; inputs.len()];
    let mut samples = Vec::with_capacity(SAMPLES);
    for sample in 0..=SAMPLES {
        let start = Instant::now();
        for _ in 0..REPEATS {
            for (value, &row) in output.iter_mut().zip(black_box(inputs)) {
                *value = operation(row);
            }
            black_box(&mut output);
        }
        let elapsed = start.elapsed().as_nanos();
        for (result, reference) in output.iter().zip(&reference) {
            assert_eq!(
                &BigUint::from_bytes_be(&result.into_bigint().to_bytes_be()),
                reference
            );
        }
        if sample > 0 {
            samples.push(elapsed);
        }
    }
    for (i, elapsed) in samples.into_iter().enumerate() {
        println!("{label},{},{},{elapsed}", i + 1, inputs.len() * REPEATS);
    }
}

fn main() {
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    let mut inputs: Vec<_> = (0..CASES)
        .map(|_| std::array::from_fn(|_| Fq::rand(&mut rng)))
        .collect();
    let edges = [Fq::ZERO, Fq::ONE, -Fq::ONE];
    for a in edges {
        for b in edges {
            inputs.push([a, b, -a, -b]);
        }
    }
    let modulus = BigUint::from_bytes_be(&Fq::MODULUS.to_bytes_be());
    println!("operation,sample,operations,elapsed_ns");
    measure("add", &inputs, |[a, b, ..]| a + b, |[a, b, ..]| a + b);
    measure(
        "sub",
        &inputs,
        |[a, b, ..]| &modulus + a - b,
        |[a, b, ..]| a - b,
    );
    measure("mul", &inputs, |[a, b, ..]| a * b, |[a, b, ..]| a * b);
    measure("square", &inputs, |[a, ..]| a * a, |[a, ..]| a.square());
    measure(
        "two_product_sum",
        &inputs,
        |[a, b, c, d]| a * b + c * d,
        |[a, b, c, d]| Fq::sum_of_products(&[a, c], &[b, d]),
    );
}
