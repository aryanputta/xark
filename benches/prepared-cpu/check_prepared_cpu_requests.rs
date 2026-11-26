use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, prepare_verifying_key};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
    time::Instant,
};
use xark_groth16::{PkSource, Proof, SerializedPk};
use xark_prover::{CircuitProof, PreparedCpuProver, ProveError, ProveInputs};

struct Request(BTreeMap<String, String>);
impl Request {
    fn read(path: &Path) -> Self {
        Self(serde_json::from_slice(&fs::read(path).expect("read fixture")).expect("parse fixture"))
    }
}
impl ProveInputs for Request {
    fn into_inputs(self) -> Vec<(String, Fr)> {
        self.0
            .into_iter()
            .map(|(name, value)| (name, value.parse().expect("field element")))
            .collect()
    }
}
fn statement(fixture: &Path, file: &str) -> Fr {
    let mut request = Request::read(&fixture.join(file));
    assert_eq!(request.0.len(), 1);
    request.0.remove("public_hash").unwrap().parse().unwrap()
}
fn decode(result: &CircuitProof) -> (Proof<Bn254>, Vec<Fr>) {
    (
        Proof::<Bn254>::deserialize_compressed(result.proof.as_slice()).unwrap(),
        Vec::<Fr>::deserialize_compressed(result.public_inputs.as_slice()).unwrap(),
    )
}
fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let [mode, artifacts, key, batch, offset, fixtures @ ..] = args.as_slice() else {
        panic!("usage: check_prepared_cpu_requests MODE ARTIFACTS KEY BATCH OFFSET FIXTURE...");
    };
    assert_eq!(fixtures.len(), 4);
    let key = Path::new(key);
    let count = batch.to_str().unwrap().parse::<usize>().unwrap();
    let offset = offset.to_str().unwrap().parse::<usize>().unwrap();
    assert!(count >= 4 && offset < 4);
    let pk = SerializedPk::open(key).expect("open reference verifying key");
    let vk = pk.header().vk.clone();
    drop(pk);
    let mut vk_bytes = Vec::new();
    vk.serialize_compressed(&mut vk_bytes).unwrap();
    let ark_vk =
        ark_groth16::VerifyingKey::<Bn254>::deserialize_compressed(vk_bytes.as_slice()).unwrap();
    let ark_vk = prepare_verifying_key(&ark_vk);
    let fixtures: Vec<_> = fixtures.iter().map(Path::new).collect();
    let statements: Vec<_> = fixtures
        .iter()
        .map(|path| {
            (
                statement(path, "public.json"),
                statement(path, "public-changed.json"),
            )
        })
        .collect();
    assert_eq!(
        statements
            .iter()
            .map(|row| row.0)
            .collect::<BTreeSet<_>>()
            .len(),
        4
    );
    assert!(statements.iter().all(|(valid, altered)| valid != altered));

    let start = Instant::now();
    let prove: Box<dyn Fn(Request) -> Result<CircuitProof, ProveError>> =
        match mode.to_str().unwrap() {
            "ordinary" => {
                let circuit = xark_prover::circuit_at(artifacts);
                let verify_key = &vk;
                Box::new(move |request| {
                    let result = circuit.prove_with_key(key, request)?;
                    // Give the ordinary API the same positive in-request check.
                    let (proof, public) = decode(&result);
                    assert!(xark_groth16::verify(verify_key, &public, &proof).unwrap());
                    Ok(result)
                })
            }
            "prepared" => {
                let xbc = fs::read(Path::new(artifacts).join("circuit.xbc")).unwrap();
                let loaded = xark_backend::Groth16Keys::read_proving_key(key).unwrap();
                let prover = PreparedCpuProver::new(&xbc, loaded).expect("prepare resident prover");
                assert_eq!(prover.verifying_key(), &vk);
                Box::new(move |request| prover.prove(request))
            }
            _ => panic!("expected ordinary or prepared"),
        };
    let setup = start.elapsed();
    let run = |i: usize| {
        let current = (i + offset) % fixtures.len();
        let (expected, altered) = statements[current];
        let other = statements[(current + 1) % fixtures.len()].0;
        let start = Instant::now();
        let inputs = Request::read(&fixtures[current].join("inputs.json"));
        let result = prove(inputs).expect("prove");
        let service = start.elapsed();
        let (proof, public) = decode(&result);
        assert_eq!(public, [expected]);
        let ark_proof =
            ark_groth16::Proof::<Bn254>::deserialize_compressed(result.proof.as_slice()).unwrap();
        for (statement, acceptance) in [(expected, true), (altered, false), (other, false)] {
            assert_eq!(
                xark_groth16::verify(&vk, &[statement], &proof).unwrap(),
                acceptance
            );
            assert_eq!(
                Groth16::<Bn254>::verify_proof(&ark_vk, &ark_proof, &[statement]).unwrap(),
                acceptance
            );
        }
        service
    };
    run(0);
    for i in 0..count {
        println!(
            "sample proof={i} fixture={} request_ns={} verified=true",
            (i + offset) % fixtures.len(),
            run(i).as_nanos()
        );
    }
    println!(
        "typed requests mode={} measured={count} warmups=1 setup_ns={} altered=rejected cross_request=rejected",
        mode.to_str().unwrap(),
        setup.as_nanos()
    );
}
