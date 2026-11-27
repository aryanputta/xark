//! Complete typed prepared proof check on existing synthetic circuit fixtures.
//! Usage: bench_prepared_typed CIRCUIT.xbc KEY.bin INPUTS.json [INPUTS.json ...]

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Instant;

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16 as ArkGroth16, Proof};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use xark_backend::Groth16Keys;
use xark_prover::{PreparedCpuProver, ProveInputs};
use zeroize::{Zeroize, Zeroizing};

struct TypedRequest(Zeroizing<Vec<(String, Fr)>>);

struct NamedInputs(BTreeMap<String, String>);

impl Drop for NamedInputs {
    fn drop(&mut self) {
        self.0.values_mut().for_each(Zeroize::zeroize);
    }
}

impl ProveInputs for TypedRequest {
    fn into_inputs(mut self) -> Vec<(String, Fr)> {
        std::mem::take(&mut self.0)
    }
}

fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        return Err("usage: bench_prepared_typed CIRCUIT.xbc KEY.bin INPUTS.json [...]".into());
    }
    let xbc = std::fs::read(&args[1]).map_err(|err| err.to_string())?;
    let key = Groth16Keys::read_proving_key(Path::new(&args[2]))
        .map_err(|err| format!("key load: {err}"))?;
    let prepare_start = Instant::now();
    let prepared = PreparedCpuProver::new(&xbc, key).map_err(|err| err.0)?;
    let prepare_ms = prepare_start.elapsed().as_secs_f64() * 1e3;
    let mut vk_bytes = Vec::new();
    prepared
        .verifying_key()
        .serialize_compressed(&mut vk_bytes)
        .map_err(|err| err.to_string())?;
    let reference_vk =
        ark_groth16::VerifyingKey::<Bn254>::deserialize_compressed(vk_bytes.as_slice())
            .map_err(|err| err.to_string())?;
    println!("prepare_ms={prepare_ms:.3} requests={}", args.len() - 3);
    println!("request,prove_ms,arkworks_verified,altered_rejected");

    for (index, path) in args[3..].iter().enumerate() {
        let encoded = Zeroizing::new(std::fs::read(path).map_err(|err| err.to_string())?);
        let named = NamedInputs(serde_json::from_slice(&encoded).map_err(|err| err.to_string())?);
        let mut fields = Zeroizing::new(Vec::with_capacity(named.0.len()));
        for (name, value) in &named.0 {
            let field = value
                .parse::<Fr>()
                .map_err(|_| "invalid field input".to_string())?;
            fields.push((name.clone(), field));
        }
        let request = TypedRequest(fields);
        drop(named);
        drop(encoded);
        let start = Instant::now();
        let output = prepared.prove(request).map_err(|err| err.0)?;
        let prove_ms = start.elapsed().as_secs_f64() * 1e3;
        let proof = Proof::<Bn254>::deserialize_compressed(output.proof.as_slice())
            .map_err(|err| err.to_string())?;
        let mut public = Vec::<Fr>::deserialize_compressed(output.public_inputs.as_slice())
            .map_err(|err| err.to_string())?;
        let verified = ArkGroth16::<Bn254>::verify(&reference_vk, &public, &proof)
            .map_err(|err| err.to_string())?;
        if !verified || public.is_empty() {
            return Err("proof or public statement is invalid".into());
        }
        public[0] += Fr::from(1u64);
        let altered_rejected = !ArkGroth16::<Bn254>::verify(&reference_vk, &public, &proof)
            .map_err(|err| err.to_string())?;
        if !altered_rejected {
            return Err("altered public statement was accepted".into());
        }
        println!("{},{prove_ms:.3},{verified},{altered_rejected}", index + 1);
    }
    Ok(())
}
