use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use ark_serialize::Valid;
use rayon::prelude::*;
use zeroize::{Zeroize, Zeroizing};

use super::{
    Bn254, BytecodeSource, CUR, ConstraintSource, Cpu, Fr, Groth16, Instant, PEAK, ProfiledCpu,
    ProverConfig, Relaxed, SNARK, checked_arkworks_encoding, prove_with_rng, public_hash,
    query_msm, solve_with_prepared, tracking,
};

struct Fixture {
    inputs: PathBuf,
    expected: Fr,
    altered: Fr,
}

impl Fixture {
    fn open(directory: &Path) -> Self {
        let expected = public_hash(&directory.join("public.json"));
        let altered = public_hash(&directory.join("public-changed.json"));
        assert!(expected != altered, "altered statement must differ");
        Self {
            inputs: directory.join("inputs.json"),
            expected,
            altered,
        }
    }
}

#[cfg(feature = "msm-b-shared-bench")]
fn shared_b_mode(value: Result<String, std::env::VarError>, use_gls: bool) -> bool {
    match value {
        Err(std::env::VarError::NotPresent) => use_gls,
        Ok(value) if value == "0" => false,
        Ok(value) if value == "1" => true,
        _ => panic!("BENCH_SHARED_B_SCALARS must be 0 or 1"),
    }
}

pub(super) fn run(args: &[String]) {
    let [xbc, key, mode, concurrency, requests, directories @ ..] = args else {
        panic!("usage: warm-requests XBC KEY cpu|gls CONCURRENCY REQUESTS FIXTURE...");
    };
    let memory_trace = std::env::var("BENCH_MEMORY").as_deref() == Ok("1");
    let profile = std::env::var("BENCH_REQUEST_PROFILE").as_deref() == Ok("1");
    assert!(
        !tracking() || memory_trace,
        "use BENCH_TIME=1 for request timing or BENCH_MEMORY=1 for heap tracing"
    );
    assert!(
        !memory_trace || tracking(),
        "BENCH_MEMORY=1 requires allocation tracking; omit BENCH_TIME"
    );
    assert!(
        !profile || !tracking(),
        "BENCH_REQUEST_PROFILE=1 requires BENCH_TIME=1"
    );
    let use_gls = match mode.as_str() {
        "cpu" => false,
        "gls" => true,
        _ => panic!("expected cpu or gls"),
    };
    #[cfg(feature = "msm-b-shared-bench")]
    let share_b_scalars = shared_b_mode(std::env::var("BENCH_SHARED_B_SCALARS"), use_gls);
    let concurrency: usize = concurrency.parse().expect("request concurrency");
    let requests: usize = requests.parse().expect("number of requests");
    assert!((1..=64).contains(&concurrency) && requests >= concurrency);
    assert!(directories.len() >= 2, "provide distinct requests");
    assert!(
        requests >= directories.len(),
        "exercise every request fixture"
    );

    let start = Instant::now();
    let fixtures: Vec<_> = directories
        .iter()
        .map(|directory| Fixture::open(Path::new(directory)))
        .collect();
    assert_eq!(
        fixtures
            .iter()
            .map(|fixture| fixture.expected)
            .collect::<BTreeSet<_>>()
            .len(),
        fixtures.len(),
        "fixture public statements must be distinct"
    );
    let xbc = std::fs::read(xbc).expect("load circuit");
    let source = BytecodeSource::new(&xbc).expect("build compiled constraint source");
    let prepare_solver = match std::env::var("BENCH_PREPARED_SOLVER").as_deref() {
        Err(std::env::VarError::NotPresent) | Ok("0") => false,
        Ok("1") => true,
        _ => panic!("BENCH_PREPARED_SOLVER must be 0 or 1"),
    };
    let solver = prepare_solver.then(|| {
        xark_ir::function_decode::PreparedStreamSolver::new(&xbc)
            .expect("prepare immutable witness and row programs")
    });
    let key = xark_backend::Groth16Keys::read_proving_key(Path::new(key)).expect("load key");
    let key_validation_start = Instant::now();
    key.check().expect("validate proving-key points");
    eprintln!(
        "proving key validation: complete duration_ns={}",
        key_validation_start.elapsed().as_nanos()
    );
    assert_eq!(key.vk.gamma_abc_g1.len(), 2, "expected one public input");
    assert_eq!(
        source.layout().num_instance(),
        2,
        "expected one public input"
    );
    let ark_vk: ark_groth16::VerifyingKey<Bn254> = checked_arkworks_encoding(&key.vk);
    let ark_vk = Groth16::<Bn254>::process_vk(&ark_vk).expect("prepare reference key");
    let cfg = ProverConfig {
        merge_below: 0,
        ..ProverConfig::default()
    };
    let cached = use_gls.then(|| {
        assert!(
            cfg.msm_chunk >= key.b_g2_query.len(),
            "GLS requires unchunked B2"
        );
        query_msm::cached_gls_b2::ResidentCachedGls::new(&key.b_g2_query, true)
            .expect("validate and prepare resident G2 points")
    });
    let cached_msm = cached.as_ref().map(|table| {
        move |bases: &[ark_bn254::G2Affine], scalars: &[xark_groth16::msm::Scalar]| {
            table.msm(bases, scalars)
        }
    });
    let setup = start.elapsed();

    let prove = |index: usize| {
        let began = Instant::now();
        let fixture = &fixtures[index % fixtures.len()];
        let mut assignment = solve_with_prepared(
            &xbc,
            fixture.inputs.to_str().expect("UTF-8 path"),
            solver.as_ref(),
        );
        let solve_elapsed = began.elapsed();
        let witness = Zeroizing::new(source.layout().assignment_from_map(&assignment));
        for value in assignment.values_mut() {
            value.zeroize();
        }
        drop(assignment);
        assert!(witness[1] == fixture.expected, "witness statement mismatch");
        assert!(
            xark_groth16::r1cs::first_unsatisfied(&source, &witness).is_none(),
            "request witness is unsatisfied"
        );
        let cpu = Cpu::new(xark_groth16::InMemoryPk::new(&key), cfg.clone());
        let mut profiles = Vec::new();
        let mut prover = ProfiledCpu {
            cpu,
            profiles: profile.then_some(&mut profiles),
            shifted: None,
            cached_gls: cached_msm
                .as_ref()
                .map(|msm| msm as &xark_groth16::prover::BenchResidentB2<'_>),
            #[cfg(feature = "msm-b-shared-bench")]
            share_b_scalars,
        };
        let proof = prove_with_rng(&mut prover, &source, &witness, &mut rand::thread_rng())
            .expect("generate request proof");
        drop(prover);
        drop(witness);
        (proof, began.elapsed(), solve_elapsed, profiles)
    };

    let verify = |index: usize, proof: &xark_groth16::Proof<Bn254>| {
        let fixture = &fixtures[index % fixtures.len()];
        let other = &fixtures[(index + 1) % fixtures.len()];
        let ark_proof: ark_groth16::Proof<Bn254> = checked_arkworks_encoding(proof);
        for (statement, expected) in [
            (fixture.expected, true),
            (fixture.altered, false),
            (other.expected, false),
        ] {
            assert_eq!(
                xark_groth16::verify(&key.vk, &[statement], proof).unwrap(),
                expected
            );
            assert_eq!(
                Groth16::<Bn254>::verify_with_processed_vk(&ark_vk, &[statement], &ark_proof)
                    .unwrap(),
                expected
            );
        }
    };

    // Warm the shared execution pool and verify one separate request before timing.
    verify(0, &prove(0).0);
    for first in (0..requests).step_by(concurrency) {
        let start = Instant::now();
        let last = first.saturating_add(concurrency).min(requests);
        let proofs: Vec<_> = (first..last).into_par_iter().map(prove).collect();
        let elapsed = start.elapsed();
        for (index, (proof, _, _, _)) in (first..last).zip(&proofs) {
            verify(index, proof);
        }
        println!(
            "request wave first={first} count={} active_ns={}",
            last - first,
            elapsed.as_nanos()
        );
        for (index, (_, elapsed, solve_elapsed, spans)) in (first..last).zip(&proofs) {
            println!(
                "request verified index={index} fixture={} service_ns={}",
                index % fixtures.len(),
                elapsed.as_nanos()
            );
            eprintln!(
                "request solver index={index} solve_ns={}",
                solve_elapsed.as_nanos()
            );
            if profile {
                assert_eq!(spans.len(), 1, "expected one profiled proof per request");
                for span in &spans[0] {
                    eprintln!(
                        "request task index={index} phase={} offset_ns={} elapsed_ns={}",
                        span.phase,
                        span.offset.as_nanos(),
                        span.elapsed.as_nanos()
                    );
                }
            }
        }
        if memory_trace {
            drop(proofs);
            eprintln!(
                "request memory completed={last} live_heap_bytes={} peak_heap_bytes={}",
                CUR.load(Relaxed),
                PEAK.load(Relaxed)
            );
        }
    }
    eprintln!("prepared stream solver: {}", u8::from(prepare_solver));
    #[cfg(feature = "msm-b-shared-bench")]
    eprintln!("shared B scalars: {}", u8::from(share_b_scalars));
    println!(
        "requests verified mode={mode} concurrency={concurrency} threads={} count={requests} setup_ns={} altered=rejected cross_request=rejected",
        rayon::current_num_threads(),
        setup.as_nanos()
    );
}

#[cfg(all(test, feature = "msm-b-shared-bench"))]
mod tests {
    use super::shared_b_mode;

    #[test]
    fn shared_b_selector_supports_cpu_and_gls_ablation() {
        assert!(!shared_b_mode(Err(std::env::VarError::NotPresent), false));
        assert!(shared_b_mode(Err(std::env::VarError::NotPresent), true));
        for use_gls in [false, true] {
            assert!(!shared_b_mode(Ok("0".into()), use_gls));
            assert!(shared_b_mode(Ok("1".into()), use_gls));
        }
    }

    #[test]
    #[should_panic(expected = "BENCH_SHARED_B_SCALARS must be 0 or 1")]
    fn shared_b_selector_rejects_invalid_value() {
        shared_b_mode(Ok("maybe".into()), false);
    }
}
