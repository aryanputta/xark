//! Verified resident proof timings using the unchanged upstream CPU prover.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Instant;

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, prepare_verifying_key};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use xark_groth16::{BytecodeSource, ConstraintSource, Cpu, InMemoryPk, ProverConfig};

fn statement(directory: &Path, file: &str) -> Fr {
    let file = std::fs::File::open(directory.join(file)).expect("open statement");
    let fields: BTreeMap<String, String> = serde_json::from_reader(file).expect("read statement");
    assert_eq!(fields.len(), 1, "expected one public input");
    fields["public_hash"].parse().expect("parse public hash")
}

fn arkworks_encoding<A: CanonicalSerialize, B: CanonicalDeserialize>(value: &A) -> B {
    let mut bytes = Vec::new();
    value
        .serialize_compressed(&mut bytes)
        .expect("encode public artifact");
    B::deserialize_compressed(bytes.as_slice()).expect("validate Arkworks encoding")
}

// Match the compiled check in the candidate's timed warm loop. The 0.5
// diagnostic first_unsatisfied helper expands rows instead.
fn first_unsatisfied_compiled(src: &BytecodeSource, z: &[Fr]) -> Option<usize> {
    let layout = src.layout();
    let value = |id| z[layout.position(id).expect("unallocated row variable")];
    for window in src.windows(1 << 14) {
        let mut row = window.rows.start;
        let mut first = None;
        src.stream()
            .eval_items(window.handle, &value, [true; 3], &mut |[a, b, c]| {
                if first.is_none() && a * b != c {
                    first = Some(row);
                }
                row += 1;
            });
        debug_assert_eq!(row, window.rows.end);
        if first.is_some() {
            return first;
        }
    }
    None
}

fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let [mode, circuit, key, inputs, samples, warmups] = args.as_slice() else {
        panic!("usage: bench_verified_warm warm CIRCUIT KEY INPUTS SAMPLES WARMUPS");
    };
    assert_eq!(mode, "warm", "unknown benchmark mode");
    let samples: usize = samples
        .to_str()
        .expect("sample count")
        .parse()
        .expect("sample count");
    let warmups: usize = warmups
        .to_str()
        .expect("warmup count")
        .parse()
        .expect("warmup count");
    assert!(samples > 0);
    let proof_count = samples.checked_add(warmups).expect("proof count");
    let statements =
        std::env::var_os("BENCH_PUBLIC_STATEMENTS").expect("fixture statement directory");
    let check_rows = std::env::var_os("BENCH_CHECK_ROWS").is_some_and(|value| {
        assert_eq!(value, "1", "only compiled row checks are supported");
        true
    });

    let setup = Instant::now();
    let xbc = std::fs::read(circuit).expect("read circuit");
    let assignment = {
        let names: BTreeMap<String, String> =
            serde_json::from_reader(std::fs::File::open(inputs).expect("open fixture inputs"))
                .expect("read fixture inputs");
        let vars = xark_ir::function_decode::decode_input_vars(&xbc).expect("read input layout");
        let ids = xark_prover::resolve_input_ids(&vars, &names).expect("resolve fixture inputs");
        let (computed, _) =
            xark_ir::function_decode::stream_solve_verify(&xbc, &ids).expect("solve fixture");
        xark_prover::lower_witness(&computed)
    };
    let src = BytecodeSource::new(&xbc).expect("open compiled rows");
    let z = src.layout().assignment_from_map(&assignment);
    assert!(z.len() == src.layout().num_vars() && z[0] == Fr::from(1u64));
    let public = &z[1..src.layout().num_instance()];
    let valid = statement(Path::new(&statements), "public.json");
    let changed = statement(Path::new(&statements), "public-changed.json");
    assert!(
        public == [valid] && valid != changed,
        "invalid fixture statements"
    );
    let pk =
        xark_backend::Groth16Keys::read_proving_key(Path::new(key)).expect("load resident key");
    let vk: ark_groth16::VerifyingKey<Bn254> = arkworks_encoding(&pk.vk);
    let prepared_vk = prepare_verifying_key(&vk);
    let mut cfg = ProverConfig::default();
    if let Ok(threshold) = std::env::var("BENCH_MERGE_BELOW") {
        cfg.merge_below = threshold.parse().expect("merge threshold");
    }
    eprintln!(
        "resident CPU: a_query_len={} merge_below={} merged={}",
        pk.a_query.len(),
        cfg.merge_below,
        pk.a_query.len() < cfg.merge_below
    );
    let mut prover = Cpu::new(InMemoryPk::new(&pk), cfg);
    let mut rng = rand::thread_rng();
    let setup_elapsed = setup.elapsed();

    let runs: Vec<_> = (0..proof_count)
        .map(|_| {
            let t = Instant::now();
            if check_rows {
                assert!(
                    first_unsatisfied_compiled(&src, &z).is_none(),
                    "constraint check failed"
                );
            }
            let proof = xark_groth16::prove_with_rng(&mut prover, &src, &z, &mut rng)
                .expect("resident proof");
            (t.elapsed(), proof)
        })
        .collect();

    for (_, proof) in &runs {
        let ark: ark_groth16::Proof<Bn254> = arkworks_encoding(proof);
        assert!(
            Groth16::<Bn254>::verify_proof(&prepared_vk, &ark, public).expect("Arkworks verify")
        );
        assert!(xark_groth16::verify(&pk.vk, public, proof).expect("Xark verify"));
        assert!(
            !Groth16::<Bn254>::verify_proof(&prepared_vk, &ark, &[changed])
                .expect("Arkworks altered verify")
        );
        assert!(!xark_groth16::verify(&pk.vk, &[changed], proof).expect("Xark altered verify"));
    }
    println!(
        "verified upstream setup_ns={} first_proof_ns={}",
        setup_elapsed.as_nanos(),
        runs[0].0.as_nanos()
    );
    println!("resident includes row checks: {check_rows}");
    if check_rows {
        println!("witness row checker: compiled");
    }
    println!(
        "warm proofs verified by Arkworks and Xark: xark-groth16 warmups={warmups} measured={samples}"
    );
    println!("changed statement rejected by Arkworks and Xark for each backend");
    for (elapsed, _) in &runs[warmups..] {
        println!("warm prove: xark-groth16 {:.6}s", elapsed.as_secs_f64());
    }
}
