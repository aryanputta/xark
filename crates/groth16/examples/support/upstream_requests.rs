//! Resident request timing with the benchmark's checked fixture protocol.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Instant;

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, prepare_verifying_key};
use rayon::prelude::*;
use xark_groth16::{BytecodeSource, ConstraintSource, Cpu, InMemoryPk, Proof, ProverConfig};
use zeroize::{Zeroize, Zeroizing};

use super::{arkworks_encoding, first_unsatisfied_compiled, statement};

struct Fixture {
    inputs: PathBuf,
    expected: Fr,
    altered: Fr,
}

impl Fixture {
    fn open(directory: &Path) -> Self {
        let expected = statement(directory, "public.json");
        let altered = statement(directory, "public-changed.json");
        assert!(expected != altered, "altered statement must differ");
        Self {
            inputs: directory.join("inputs.json"),
            expected,
            altered,
        }
    }
}

fn solve(xbc: &[u8], inputs: &Path) -> BTreeMap<u32, Fr> {
    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(inputs).unwrap()).unwrap();
    let names: BTreeMap<String, String> = json
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
        .collect();
    let vars = xark_ir::function_decode::decode_input_vars(xbc).unwrap();
    let ids = xark_prover::resolve_input_ids(&vars, &names).unwrap();
    drop(vars);
    let (computed, _) = xark_ir::function_decode::stream_solve_verify(xbc, &ids).unwrap();
    xark_prover::lower_witness(&computed)
}

pub(super) fn run(args: &[OsString]) {
    let [xbc, key, mode, concurrency, requests, directories @ ..] = args else {
        panic!("usage: warm-requests XBC KEY cpu CONCURRENCY REQUESTS FIXTURE...");
    };
    assert_eq!(
        mode, "cpu",
        "the upstream control uses the ordinary CPU prover"
    );
    assert!(std::env::var_os("BENCH_PREPARED_SOLVER").is_none());
    let concurrency: usize = concurrency
        .to_str()
        .unwrap()
        .parse()
        .expect("request concurrency");
    let requests: usize = requests
        .to_str()
        .unwrap()
        .parse()
        .expect("number of requests");
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
    let key = xark_backend::Groth16Keys::read_proving_key(Path::new(key)).expect("load key");
    assert_eq!(key.vk.gamma_abc_g1.len(), 2, "expected one public input");
    assert_eq!(
        source.layout().num_instance(),
        2,
        "expected one public input"
    );
    let ark_vk: ark_groth16::VerifyingKey<Bn254> = arkworks_encoding(&key.vk);
    let ark_vk = prepare_verifying_key(&ark_vk);
    let cfg = ProverConfig::default();
    // Both pinned fixtures naturally use the same split schedule as the candidate.
    assert!(
        key.a_query.len() >= cfg.merge_below,
        "expected the upstream default split path"
    );
    let setup = start.elapsed();

    let prove = |index: usize| {
        let began = Instant::now();
        let fixture = &fixtures[index % fixtures.len()];
        let mut assignment = solve(&xbc, &fixture.inputs);
        let solve_elapsed = began.elapsed();
        let convert_start = Instant::now();
        let witness = Zeroizing::new(source.layout().assignment_from_map(&assignment));
        for value in assignment.values_mut() {
            value.zeroize();
        }
        drop(assignment);
        let convert_elapsed = convert_start.elapsed();
        let check_start = Instant::now();
        assert!(witness[1] == fixture.expected, "witness statement mismatch");
        assert!(
            first_unsatisfied_compiled(&source, &witness).is_none(),
            "request witness is unsatisfied"
        );
        let check_elapsed = check_start.elapsed();
        let construct_start = Instant::now();
        let mut prover = Cpu::new(InMemoryPk::new(&key), cfg.clone());
        let construct_elapsed = construct_start.elapsed();
        let prove_start = Instant::now();
        let proof =
            xark_groth16::prove_with_rng(&mut prover, &source, &witness, &mut rand::thread_rng())
                .expect("generate request proof");
        drop(witness);
        let prove_elapsed = prove_start.elapsed();
        (
            proof,
            began.elapsed(),
            solve_elapsed,
            [
                convert_elapsed,
                check_elapsed,
                construct_elapsed,
                prove_elapsed,
            ],
        )
    };

    let verify = |index: usize, proof: &Proof<Bn254>| {
        let fixture = &fixtures[index % fixtures.len()];
        let other = &fixtures[(index + 1) % fixtures.len()];
        let ark_proof: ark_groth16::Proof<Bn254> = arkworks_encoding(proof);
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
                Groth16::<Bn254>::verify_proof(&ark_vk, &ark_proof, &[statement]).unwrap(),
                expected
            );
        }
    };

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
        for (index, (_, elapsed, solve_elapsed, phases)) in (first..last).zip(&proofs) {
            println!(
                "request verified index={index} fixture={} service_ns={}",
                index % fixtures.len(),
                elapsed.as_nanos()
            );
            eprintln!(
                "request solver index={index} solve_ns={}",
                solve_elapsed.as_nanos()
            );
            eprintln!(
                "request phases index={index} convert_ns={} check_ns={} construct_ns={} prove_ns={}",
                phases[0].as_nanos(),
                phases[1].as_nanos(),
                phases[2].as_nanos(),
                phases[3].as_nanos()
            );
        }
    }
    eprintln!("upstream verified request wrapper: 1");
    println!(
        "requests verified mode=cpu concurrency={concurrency} threads={} count={requests} setup_ns={} altered=rejected cross_request=rejected",
        rayon::current_num_threads(),
        setup.as_nanos()
    );
}
