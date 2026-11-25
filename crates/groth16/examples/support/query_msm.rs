use std::hint::black_box;
use std::path::Path;
use std::sync::atomic::Ordering::Relaxed;
use std::time::{Duration, Instant};

use ark_bn254::{G1Projective, G2Projective};
use ark_ff::PrimeField;
use xark_groth16::msm::{self, Scalar, SwCurve};
use xark_groth16::{BytecodeSource, ConstraintSource};

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

pub(super) fn run(args: &[String]) {
    let [xbc_path, pk_path, directory, options @ ..] = args else {
        panic!(
            "usage: bench_prove query-msm <circuit.xbc> <reduced pk.bin> <statement-dir> [samples] [warmups]"
        );
    };
    let (samples, warmups) = counts(options).unwrap_or_else(|reason| panic!("{reason}"));
    assert!(!super::tracking(), "set BENCH_TIME=1 to time query MSMs");
    if std::env::var("NO_GLV").is_ok() {
        msm::GLV.store(false, Relaxed);
    }

    let directory = Path::new(directory);
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

#[cfg(test)]
mod tests {
    use super::{counts, query_shape};

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
}
