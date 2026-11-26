//! Query-matched B1 screen: existing GLV versus public 128-bit shifted bases.
//! Accepts only synthetic query exports from `bench_prove query-msm-export`.
//! This is a diagnostic benchmark, not a production prover or security boundary.

use std::hint::black_box;
use std::mem::size_of;
use std::time::Instant;

use ark_bn254::{Fq, Fr, G1Affine, G1Projective};
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::{AdditiveGroup, BigInt, BigInteger, PrimeField};
use rayon::prelude::*;
use xark_groth16::msm::{Scalar, msm};

const HEADER: usize = 12;
const RECORD: usize = 224;
const TRAILER: usize = 192;

fn canonical<F: PrimeField>(encoded: &[u8]) -> F {
    let value = F::from_be_bytes_mod_order(encoded);
    assert_eq!(value.into_bigint().to_bytes_be(), encoded);
    value
}

fn g1(bytes: &[u8]) -> G1Affine {
    if bytes.iter().all(|byte| *byte == 0) {
        return G1Affine::identity();
    }
    let point =
        G1Affine::new_unchecked(canonical::<Fq>(&bytes[..32]), canonical::<Fq>(&bytes[32..]));
    assert!(point.is_on_curve() && point.is_in_correct_subgroup_assuming_on_curve());
    point
}

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let [path, samples, warmups] = args.as_slice() else {
        panic!("usage: bench_b1_shifted <query-export> <samples> <warmups>");
    };
    let samples: usize = samples.parse().unwrap();
    let warmups: usize = warmups.parse().unwrap();
    assert!(samples > 0);
    let bytes = std::fs::read(path).unwrap();
    assert!(bytes.len() >= HEADER && &bytes[..8] == b"XKQMSM01");
    let terms = u32::from_le_bytes(bytes[8..HEADER].try_into().unwrap()) as usize;
    assert_eq!(bytes.len(), HEADER + RECORD * terms + TRAILER);
    let trailer = HEADER + RECORD * terms;
    let mut bases = Vec::with_capacity(terms);
    let mut scalars: Vec<Scalar> = Vec::with_capacity(terms);
    for row in bytes[HEADER..trailer].chunks_exact(RECORD) {
        scalars.push(canonical::<Fr>(&row[..32]).into_bigint());
        bases.push(g1(&row[32..96]));
    }
    let reference = G1Projective::from(g1(&bytes[trailer..trailer + 64]));
    assert_eq!(G1Projective::msm_bigint(&bases, &scalars), reference);
    drop(bytes);

    let start = Instant::now();
    let shifted: Vec<_> = bases
        .par_iter()
        .map(|&base| {
            let mut point = G1Projective::from(base);
            for _ in 0..128 {
                point.double_in_place();
            }
            point
        })
        .collect();
    let mut points = Vec::with_capacity(2 * terms);
    points.extend_from_slice(&bases);
    points.extend(G1Projective::normalize_batch(&shifted));
    let setup_ns = start.elapsed().as_nanos();

    let measure = |shifted: bool| {
        let start = Instant::now();
        let result = if shifted {
            let mut split = Vec::with_capacity(2 * terms);
            split.extend(scalars.iter().map(|s| BigInt([s.0[0], s.0[1], 0, 0])));
            split.extend(scalars.iter().map(|s| BigInt([s.0[2], s.0[3], 0, 0])));
            msm::<G1Projective>(black_box(&points), black_box(&split))
        } else {
            msm::<G1Projective>(black_box(&bases), black_box(&scalars))
        };
        let elapsed = start.elapsed().as_nanos();
        assert_eq!(result, reference);
        elapsed
    };

    println!(
        "terms={terms} workers={} table_bytes={} setup_ns={setup_ns}",
        rayon::current_num_threads(),
        points.len() * size_of::<G1Affine>()
    );
    println!("round,shifted_first,baseline_ns,shifted_ns");
    for round in 0..samples + warmups {
        let shifted_first = round % 2 == 1;
        let first = measure(shifted_first);
        let second = measure(!shifted_first);
        if round >= warmups {
            let (baseline, shifted) = if shifted_first {
                (second, first)
            } else {
                (first, second)
            };
            println!(
                "{},{shifted_first},{baseline},{shifted}",
                round + 1 - warmups
            );
        }
    }
}
