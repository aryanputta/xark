//! Compare B2 on an exact test-only `bench_prove query-msm-export` fixture.
//! Use `RAYON_NUM_THREADS=2 bench_b2_prepared query.bin 100 3`.

use std::hint::black_box;
use std::io::{self, ErrorKind};
use std::time::Instant;

use ark_bn254::{Fq, Fq2, Fr, G2Affine, G2Projective};
use ark_ec::VariableBaseMSM;
use ark_ff::{BigInteger, PrimeField};
use xark_groth16::msm::{PreparedG2, Scalar, msm};

const HEADER: usize = 12;
const RECORD: usize = 224;
const TRAILER: usize = 192;
const MAX_TERMS: usize = 8192;

fn field<F: PrimeField>(encoded: &[u8]) -> io::Result<F> {
    let value = F::from_be_bytes_mod_order(encoded);
    if value.into_bigint().to_bytes_be() != encoded {
        return Err(io::Error::new(ErrorKind::InvalidData, "noncanonical field"));
    }
    Ok(value)
}

fn g2(bytes: &[u8]) -> io::Result<G2Affine> {
    let x = Fq2::new(field::<Fq>(&bytes[32..64])?, field::<Fq>(&bytes[..32])?);
    let y = Fq2::new(field::<Fq>(&bytes[96..128])?, field::<Fq>(&bytes[64..96])?);
    let point = G2Affine::new_unchecked(x, y);
    if !point.is_on_curve() || !point.is_in_correct_subgroup_assuming_on_curve() {
        return Err(io::Error::new(ErrorKind::InvalidData, "invalid G2 point"));
    }
    Ok(point)
}

fn main() -> io::Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let [path, samples, warmups] = args.as_slice() else {
        panic!("usage: bench_b2_prepared <test-query-file> <samples> <warmups>");
    };
    let samples: usize = samples.parse().expect("sample count");
    let warmups: usize = warmups.parse().expect("warmup count");
    assert!(samples > 0);
    let rounds = samples.checked_add(warmups).expect("total round count");
    let bytes = std::fs::read(path)?;
    assert!(bytes.len() >= HEADER && &bytes[..8] == b"XKQMSM01");
    let terms = u32::from_le_bytes(bytes[8..HEADER].try_into().unwrap()) as usize;
    assert!((1..=MAX_TERMS).contains(&terms));
    assert_eq!(bytes.len(), HEADER + terms * RECORD + TRAILER);
    let trailer = HEADER + terms * RECORD;
    let mut bases = Vec::with_capacity(terms);
    let mut scalars: Vec<Scalar> = Vec::with_capacity(terms);
    for row in bytes[HEADER..trailer].chunks_exact(RECORD) {
        scalars.push(field::<Fr>(&row[..32])?.into_bigint());
        bases.push(g2(&row[96..])?);
    }
    let reference: G2Projective = g2(&bytes[trailer + 64..])?.into();
    assert_eq!(G2Projective::msm_bigint(&bases, &scalars), reference);
    drop(bytes);

    let start = Instant::now();
    let prepared = PreparedG2::new(&bases).expect("B2 payload budget");
    let preparation_ns = start.elapsed().as_nanos();
    let measure = |use_cache| {
        let start = Instant::now();
        let result = if use_cache {
            prepared.msm(black_box(&scalars))
        } else {
            msm::<G2Projective>(black_box(&bases), black_box(&scalars))
        };
        let elapsed = start.elapsed().as_nanos();
        assert_eq!(result, reference);
        elapsed
    };
    let mut timings = Vec::with_capacity(samples);
    for i in 0..rounds {
        let cache_first = i % 2 == 1;
        let first = measure(cache_first);
        let second = measure(!cache_first);
        if i >= warmups {
            let (baseline, cached) = if cache_first {
                (second, first)
            } else {
                (first, second)
            };
            timings.push((cache_first, baseline, cached));
        }
    }
    println!(
        "terms={terms} workers={} prepared_payload_bytes={} preparation_ns={preparation_ns}",
        rayon::current_num_threads(),
        prepared.payload_bytes()
    );
    println!("round,cache_first,baseline_ns,cached_ns");
    for (i, (cache_first, baseline, cached)) in timings.into_iter().enumerate() {
        println!("{},{cache_first},{baseline},{cached}", i + 1);
    }
    Ok(())
}
