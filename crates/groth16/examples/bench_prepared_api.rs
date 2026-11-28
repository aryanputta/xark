//! Benchmark-only caller of the final public PreparedCpuProver API.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::time::Instant;

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, prepare_verifying_key};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use xark_groth16::Proof;
use xark_prover::{CircuitProof, PreparedCpuProver, ProveInputs};

struct Request(BTreeMap<String, String>);

impl Request {
    fn read(path: &Path) -> Self {
        Self(serde_json::from_slice(&fs::read(path).expect("read request")).expect("parse request"))
    }
}

impl ProveInputs for Request {
    fn into_inputs(self) -> Vec<(String, Fr)> {
        self.0
            .into_iter()
            .map(|(name, decimal)| (name, decimal.parse().expect("field element")))
            .collect()
    }
}

fn statement(directory: &Path, file: &str) -> Fr {
    let mut map = Request::read(&directory.join(file)).0;
    assert_eq!(map.len(), 1);
    map.remove("public_hash").unwrap().parse().unwrap()
}

fn decode(result: &CircuitProof) -> (Proof<Bn254>, Vec<Fr>) {
    (
        Proof::<Bn254>::deserialize_compressed(result.proof.as_slice()).unwrap(),
        Vec::<Fr>::deserialize_compressed(result.public_inputs.as_slice()).unwrap(),
    )
}

fn main() {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let [mode, xbc, key, concurrency, requests, directories @ ..] = args.as_slice() else {
        panic!("usage: bench_prepared_api warm-requests XBC KEY 1 REQUESTS FIXTURE...");
    };
    assert_eq!(mode, "warm-requests");
    assert_eq!(concurrency, "1", "this replay measures serial requests");
    assert_eq!(directories.len(), 4, "four distinct requests are required");
    let count: usize = requests.to_str().unwrap().parse().unwrap();
    assert!(count >= 4);

    let setup_start = Instant::now();
    let fixtures: Vec<_> = directories
        .iter()
        .map(|path| {
            let path = Path::new(path);
            let valid = statement(path, "public.json");
            let altered = statement(path, "public-changed.json");
            assert_ne!(valid, altered);
            (path, valid, altered)
        })
        .collect();
    assert_eq!(
        fixtures
            .iter()
            .map(|(_, valid, _)| valid)
            .collect::<BTreeSet<_>>()
            .len(),
        4
    );
    let xbc = fs::read(xbc).expect("read circuit");
    let key = xark_backend::Groth16Keys::read_proving_key(Path::new(key)).expect("read key");
    let prover = PreparedCpuProver::new(&xbc, key).expect("prepare prover");
    let mut vk_bytes = Vec::new();
    prover
        .verifying_key()
        .serialize_compressed(&mut vk_bytes)
        .unwrap();
    let ark_vk =
        ark_groth16::VerifyingKey::<Bn254>::deserialize_compressed(vk_bytes.as_slice()).unwrap();
    let ark_vk = prepare_verifying_key(&ark_vk);
    let setup_ns = setup_start.elapsed().as_nanos();

    let run = |index: usize| {
        let current = index % fixtures.len();
        let (directory, expected, altered) = fixtures[current];
        let other = fixtures[(current + 1) % fixtures.len()].1;
        let start = Instant::now();
        let request = Request::read(&directory.join("inputs.json"));
        let result = prover.prove(request).expect("prepared proof");
        let service_ns = start.elapsed().as_nanos();

        let (proof, public) = decode(&result);
        assert_eq!(public, [expected], "wrong public statement");
        let ark_proof =
            ark_groth16::Proof::<Bn254>::deserialize_compressed(result.proof.as_slice()).unwrap();
        for (statement, accepted) in [(expected, true), (altered, false), (other, false)] {
            assert_eq!(
                xark_groth16::verify(prover.verifying_key(), &[statement], &proof).unwrap(),
                accepted
            );
            assert_eq!(
                Groth16::<Bn254>::verify_proof(&ark_vk, &ark_proof, &[statement]).unwrap(),
                accepted
            );
        }
        service_ns
    };
    run(0); // An independently verified warmup, outside measured samples.
    for index in 0..count {
        println!(
            "request verified index={index} fixture={} service_ns={}",
            index % fixtures.len(),
            run(index)
        );
    }
    eprintln!("prepared final public API: 1");
    println!(
        "requests verified mode=cpu concurrency=1 threads={} count={count} setup_ns={setup_ns} altered=rejected cross_request=rejected",
        rayon::current_num_threads()
    );
}
