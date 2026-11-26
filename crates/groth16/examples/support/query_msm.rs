use std::fs::OpenOptions;
use std::hint::black_box;
use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::sync::atomic::Ordering::Relaxed;
use std::time::{Duration, Instant};

use ark_bn254::{Bn254, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{BigInteger, PrimeField};
use xark_groth16::msm::{self, Scalar, SwCurve};
use xark_groth16::{BytecodeSource, ConstraintSource, ProvingKey};

const MAGIC: &[u8; 8] = b"XKQMSM01";

#[path = "shifted_b2.rs"]
pub(super) mod shifted_b2;

fn counts(args: &[String]) -> Result<(usize, usize), &'static str> {
    let (samples, warmups): (usize, usize) = match args {
        [] => (30, 3),
        [samples] => (samples.parse().map_err(|_| "invalid sample count")?, 3),
        [samples, warmups] => (
            samples.parse().map_err(|_| "invalid sample count")?,
            warmups.parse().map_err(|_| "invalid warmup count")?,
        ),
        _ => return Err("expected at most a sample count and a warmup count"),
    };
    if samples == 0 || samples.checked_add(warmups).is_none() {
        return Err("sample count must be positive and total iterations must fit in usize");
    }
    Ok((samples, warmups))
}

fn query_shape(query: &str, points: usize, scalars: usize) -> Result<(), String> {
    if points == scalars && scalars != 0 {
        Ok(())
    } else {
        Err(format!(
            "{query} query has {points} points and the ordered witness has {scalars} scalars, expected equal nonzero lengths"
        ))
    }
}

fn timed<T>(calculate: impl FnOnce() -> T) -> (T, Duration) {
    let start = Instant::now();
    let result = black_box(calculate());
    (result, start.elapsed())
}

fn measure<G: SwCurve>(
    query: &str,
    bases: &[G::Affine],
    scalars: &[Scalar],
    samples: usize,
    warmups: usize,
) -> Vec<(bool, Duration, Duration)> {
    let xark = || timed(|| msm::msm::<G>(bases, scalars));
    let arkworks = || timed(|| <G as ark_ec::VariableBaseMSM>::msm_bigint(bases, scalars));
    let mut timings = Vec::with_capacity(samples);
    for iteration in 0..(warmups + samples) {
        let xark_first = iteration % 2 == 0;
        let ((ours, xark_time), (theirs, arkworks_time)) = if xark_first {
            (xark(), arkworks())
        } else {
            let arkworks = arkworks();
            (xark(), arkworks)
        };
        assert!(
            msm::same_point(&ours, &theirs),
            "{query} query iteration {} disagrees with Arkworks",
            iteration + 1
        );
        if iteration >= warmups {
            timings.push((xark_first, xark_time, arkworks_time));
        }
    }
    timings
}

fn load(xbc_path: &str, pk_path: &str, directory: &Path) -> (ProvingKey<Bn254>, Vec<Scalar>) {
    let xbc = std::fs::read(xbc_path).expect("read the reduced circuit");
    let inputs = directory.join("inputs.json");
    let assign = super::solve(&xbc, inputs.to_str().expect("UTF-8 input file path"));
    let src = BytecodeSource::new(&xbc).expect("read the reduced circuit source");
    let witness = src.layout().assignment_from_map(&assign);
    super::check_statements(directory, &witness[1..src.layout().num_instance()]);
    assert!(
        xark_groth16::r1cs::first_unsatisfied(&src, &witness).is_none(),
        "the fixture witness fails a reduced constraint"
    );

    let pk = xark_backend::Groth16Keys::read_proving_key(Path::new(pk_path))
        .expect("decode the reduced proving key");
    assert_eq!(
        pk.vk.gamma_abc_g1.len(),
        src.layout().num_instance(),
        "verifying key and circuit have different instance counts"
    );
    for (query, points) in [("b1", pk.b_g1_query.len()), ("b2", pk.b_g2_query.len())] {
        query_shape(query, points, witness.len()).unwrap_or_else(|reason| panic!("{reason}"));
    }
    let scalars: Vec<Scalar> = witness.iter().map(|s| s.into_bigint()).collect();
    (pk, scalars)
}

pub(super) fn run(args: &[String], xark_only: bool) {
    let [xbc_path, pk_path, directory, options @ ..] = args else {
        let mode = if xark_only {
            "query-msm-xark"
        } else {
            "query-msm"
        };
        panic!(
            "usage: bench_prove {mode} <circuit.xbc> <reduced pk.bin> <statement-dir> [samples] [warmups]"
        );
    };
    let (samples, warmups) = counts(options).unwrap_or_else(|reason| panic!("{reason}"));
    assert!(!super::tracking(), "set BENCH_TIME=1 to time query MSMs");
    if std::env::var("NO_GLV").is_ok() {
        msm::GLV.store(false, Relaxed);
    }

    let (pk, scalars) = load(xbc_path, pk_path, Path::new(directory));
    if xark_only {
        run_xark(&pk, &scalars, samples, warmups);
        return;
    }
    let b1 = measure::<G1Projective>("b1", &pk.b_g1_query, &scalars, samples, warmups);
    let b2 = measure::<G2Projective>("b2", &pk.b_g2_query, &scalars, samples, warmups);

    println!(
        "query msm verified: terms={} threads={} samples={samples} warmups={warmups} xark_glv={} xark_batch_affine={}",
        scalars.len(),
        rayon::current_num_threads(),
        msm::GLV.load(Relaxed),
        msm::BATCH_AFFINE.load(Relaxed),
    );
    for (query, timings) in [("b1", b1), ("b2", b2)] {
        for (index, (xark_first, xark, arkworks)) in timings.into_iter().enumerate() {
            let first = if xark_first { "xark" } else { "arkworks" };
            println!(
                "query msm: query={query} sample={} first={first} xark_ns={} arkworks_ns={}",
                index + 1,
                xark.as_nanos(),
                arkworks.as_nanos(),
            );
        }
    }
}

fn measure_xark<G: SwCurve>(
    query: &str,
    bases: &[G::Affine],
    scalars: &[Scalar],
    expected: &G,
    samples: usize,
    warmups: usize,
) -> Vec<Duration> {
    let mut timings = Vec::with_capacity(samples);
    for iteration in 0..(warmups + samples) {
        let (result, elapsed) = timed(|| msm::msm::<G>(bases, scalars));
        assert!(
            msm::same_point(&result, expected),
            "{query} query iteration {} disagrees with Arkworks",
            iteration + 1
        );
        if iteration >= warmups {
            timings.push(elapsed);
        }
    }
    timings
}

fn run_xark(pk: &ProvingKey<Bn254>, scalars: &[Scalar], samples: usize, warmups: usize) {
    let expected_b1 = G1Projective::msm_bigint(&pk.b_g1_query, scalars);
    let expected_b2 = G2Projective::msm_bigint(&pk.b_g2_query, scalars);
    let b1 = measure_xark(
        "b1",
        &pk.b_g1_query,
        scalars,
        &expected_b1,
        samples,
        warmups,
    );
    let b2 = measure_xark(
        "b2",
        &pk.b_g2_query,
        scalars,
        &expected_b2,
        samples,
        warmups,
    );
    println!(
        "query msm xark verified: terms={} threads={} samples={samples} warmups={warmups} xark_glv={} xark_batch_affine={}",
        scalars.len(),
        rayon::current_num_threads(),
        msm::GLV.load(Relaxed),
        msm::BATCH_AFFINE.load(Relaxed),
    );
    for (query, timings) in [("b1", b1), ("b2", b2)] {
        for (index, elapsed) in timings.into_iter().enumerate() {
            println!(
                "query msm xark: query={query} sample={} xark_ns={}",
                index + 1,
                elapsed.as_nanos(),
            );
        }
    }
}

fn write_g1(out: &mut impl Write, point: &G1Affine) -> io::Result<()> {
    let Some((x, y)) = point.xy() else {
        return out.write_all(&[0; 64]);
    };
    out.write_all(&x.into_bigint().to_bytes_be())?;
    out.write_all(&y.into_bigint().to_bytes_be())
}

fn write_g2(out: &mut impl Write, point: &G2Affine) -> io::Result<()> {
    let Some((x, y)) = point.xy() else {
        return out.write_all(&[0; 128]);
    };
    // gnark-crypto's uncompressed order writes the imaginary component first.
    for coordinate in [x.c1, x.c0, y.c1, y.c0] {
        out.write_all(&coordinate.into_bigint().to_bytes_be())?;
    }
    Ok(())
}

/// The ordered witness and both key queries are validated before opening the file.
fn write_vectors(
    out: &mut impl Write,
    scalars: &[Scalar],
    b1: &[G1Affine],
    b2: &[G2Affine],
) -> io::Result<()> {
    let count = u32::try_from(scalars.len()).expect("too many query terms for export");
    let reference_b1 = G1Projective::msm_bigint(b1, scalars).into_affine();
    let reference_b2 = G2Projective::msm_bigint(b2, scalars).into_affine();
    out.write_all(MAGIC)?;
    out.write_all(&count.to_le_bytes())?;
    for ((scalar, g1), g2) in scalars.iter().zip(b1).zip(b2) {
        out.write_all(&scalar.to_bytes_be())?;
        write_g1(out, g1)?;
        write_g2(out, g2)?;
    }
    write_g1(out, &reference_b1)?;
    write_g2(out, &reference_b2)
}

pub(super) fn export(args: &[String]) {
    let [xbc_path, pk_path, directory, output] = args else {
        panic!(
            "usage: bench_prove query-msm-export <circuit.xbc> <reduced pk.bin> <statement-dir> <new-output-file>"
        );
    };
    let (pk, scalars) = load(xbc_path, pk_path, Path::new(directory));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut out = BufWriter::new(options.open(output).expect("create the new query export"));
    write_vectors(&mut out, &scalars, &pk.b_g1_query, &pk.b_g2_query)
        .expect("write the query export");
    out.flush().expect("flush the query export");
    println!("exported query MSM fixture: terms={}", scalars.len());
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Fq, Fr};

    #[test]
    fn counts_check_the_number_of_measured_iterations() {
        let parse =
            |options: &[&str]| counts(&options.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert_eq!(parse(&[]), Ok((30, 3)));
        assert_eq!(parse(&["5"]), Ok((5, 3)));
        assert_eq!(parse(&["5", "0"]), Ok((5, 0)));
        for options in [&["0"][..], &["-1"], &["5", "junk"], &["5", "0", "extra"]] {
            assert!(parse(options).is_err());
        }
        assert!(counts(&[usize::MAX.to_string(), "1".into()]).is_err());
    }

    #[test]
    fn query_shape_rejects_truncated_or_empty_inputs() {
        assert!(query_shape("b1", 5, 5).is_ok());
        assert!(query_shape("b1", 4, 5).is_err());
        assert!(query_shape("b2", 6, 5).is_err());
        assert!(query_shape("b2", 0, 0).is_err());
    }

    #[test]
    #[should_panic(expected = "b1 query iteration 1 disagrees with Arkworks")]
    fn xark_only_rejects_a_wrong_reference() {
        let base = G1Affine::generator();
        let scalar = Fr::from(1u64).into_bigint();
        let wrong = G1Projective::from(G1Affine::identity());
        measure_xark("b1", &[base], &[scalar], &wrong, 1, 0);
    }

    #[test]
    fn fixture_has_canonical_coordinates_and_reference_sums() {
        let scalars = [Fr::from(1u64).into_bigint(), Fr::from(513u64).into_bigint()];
        let g1 = G1Affine::generator();
        let g2 = G2Affine::generator();
        let mut bytes = Vec::new();
        write_vectors(
            &mut bytes,
            &scalars,
            &[g1, G1Affine::identity()],
            &[g2, G2Affine::identity()],
        )
        .unwrap();

        assert_eq!(bytes.len(), 12 + 2 * 224 + 64 + 128);
        assert_eq!(&bytes[..12], b"XKQMSM01\x02\x00\x00\x00");
        let records = &bytes[12..12 + 2 * 224];
        assert_eq!(Fr::from_be_bytes_mod_order(&records[..32]), Fr::from(1u64));
        let fields = [g1.x, g1.y, g2.x.c1, g2.x.c0, g2.y.c1, g2.y.c0];
        for (encoded, expected) in records[32..224].chunks_exact(32).zip(fields) {
            assert_eq!(Fq::from_be_bytes_mod_order(encoded), expected);
        }
        assert_eq!(&records[224 + 30..224 + 32], &[2, 1]);
        assert!(records[224 + 32..].iter().all(|byte| *byte == 0));
        assert_eq!(&bytes[12 + 2 * 224..], &records[32..224]);
    }
}
