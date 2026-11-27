use std::collections::BTreeMap;

use ark_bn254::{Bn254, Fr};
use ark_serialize::{CanonicalSerialize, Valid};
use xark_groth16::{ConstraintSource, InMemoryPk, ProverConfig, ProvingKey, VerifyingKey};
use xark_ir::function_decode::PreparedStreamSolver;
use xark_ir::primitive::VarRole;
use zeroize::{Zeroize, Zeroizing};

use crate::{CircuitProof, ProveError, ProveInputs, owned_rows_for_key};

// The solver borrows field inputs. Wipe them on return and unwinding.
#[derive(Default)]
struct RequestFields(BTreeMap<u32, Fr>);

impl RequestFields {
    fn wipe(&mut self) {
        self.0.values_mut().for_each(Zeroize::zeroize);
    }
}

impl Drop for RequestFields {
    fn drop(&mut self) {
        self.wipe();
    }
}

/// Repeated BN254 proving for one immutable circuit and resident key.
///
/// Construction validates the key's points and prepares the witness and row
/// programs. Use artifacts from the intended circuit and a trusted setup.
/// Requests can share this object. Each request owns its working state and uses
/// fresh OS randomness. The CPU prover uses variable-time arithmetic.
pub struct PreparedCpuProver {
    solver: PreparedStreamSolver,
    inputs: BTreeMap<String, u32>,
    rows: Box<dyn ConstraintSource + Send>,
    key: ProvingKey<Bn254>,
    config: ProverConfig,
}

impl PreparedCpuProver {
    /// Prepare the supplied circuit bytecode and take ownership of its key.
    /// Callers should authenticate both artifacts before constructing a prover.
    pub fn new(xbc: &[u8], key: ProvingKey<Bn254>) -> Result<Self, ProveError> {
        let solver = PreparedStreamSolver::new(xbc).map_err(ProveError)?;
        let rows = owned_rows_for_key(xbc, key.a_query.len(), None).map_err(ProveError)?;
        let config = ProverConfig {
            self_check: true,
            ..Default::default()
        };
        let layout = rows.layout();
        for (name, actual, expected) in [
            ("a_query", key.a_query.len(), layout.num_vars()),
            ("b_g1_query", key.b_g1_query.len(), layout.num_vars()),
            ("b_g2_query", key.b_g2_query.len(), layout.num_vars()),
            ("l_query", key.l_query.len(), layout.num_witness()),
            (
                "vk.gamma_abc_g1",
                key.vk.gamma_abc_g1.len(),
                layout.num_instance(),
            ),
        ] {
            if actual != expected {
                return Err(ProveError(format!(
                    "{name} has {actual} points, circuit needs {expected}"
                )));
            }
        }
        xark_groth16::qap::key_domain(&*rows, key.h_query.len(), config.fft).map_err(ProveError)?;
        key.check()
            .map_err(|err| ProveError(format!("invalid proving key: {err}")))?;
        let mut inputs = BTreeMap::new();
        for var in solver
            .input_vars()
            .iter()
            .filter(|var| matches!(var.role, VarRole::PublicInput | VarRole::PrivateInput))
        {
            if inputs.insert(var.name.clone(), var.id).is_some() {
                return Err(ProveError("duplicate circuit input name".into()));
            }
        }
        Ok(Self {
            solver,
            inputs,
            rows,
            key,
            config,
        })
    }

    /// The verifying key embedded in the prepared proving key.
    pub fn verifying_key(&self) -> &VerifyingKey<Bn254> {
        &self.key.vk
    }

    /// Solve, prove and self-check a fresh request. The proof and public inputs
    /// use the same canonical encodings as [`crate::Circuit::prove`].
    pub fn prove(&self, inputs: impl ProveInputs) -> Result<CircuitProof, ProveError> {
        let mut fields = RequestFields::default();
        let solved = (|| {
            let values = Zeroizing::new(inputs.into_inputs());
            for (name, value) in values.iter() {
                let id = self
                    .inputs
                    .get(name)
                    .ok_or_else(|| ProveError("unknown circuit input".into()))?;
                let std::collections::btree_map::Entry::Vacant(entry) = fields.0.entry(*id) else {
                    return Err(ProveError("duplicate circuit input".into()));
                };
                entry.insert(*value);
            }
            drop(values);
            if fields.0.len() != self.inputs.len() {
                return Err(ProveError("missing circuit input".into()));
            }
            self.solver
                .solve_verify_dense_fields(&fields.0)
                .map_err(ProveError)
        })();
        drop(fields);
        let (assignment, _) = solved?;
        let layout = self.rows.layout();
        let witness =
            Zeroizing::new(layout.assignment(|id| assignment.get(id as usize).copied().flatten()));
        drop(assignment);
        let proof = xark_groth16::prove(
            &*self.rows,
            &witness,
            &mut InMemoryPk::new(&self.key),
            &mut rand::rngs::OsRng,
            &self.config,
        )
        .map_err(|err| ProveError(format!("proving: {err}")))?;
        let mut result = CircuitProof {
            proof: Vec::new(),
            public_inputs: Vec::new(),
        };
        proof
            .serialize_compressed(&mut result.proof)
            .map_err(|err| ProveError(err.to_string()))?;
        witness[1..layout.num_instance()]
            .serialize_compressed(&mut result.public_inputs)
            .map_err(|err| ProveError(err.to_string()))?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;

    use super::RequestFields;

    #[test]
    fn request_field_values_are_cleared_in_place() {
        let mut values = RequestFields::default();
        values.0.insert(1, Fr::from(123456789u64));
        values.0.insert(2, Fr::from(987654321u64));
        values.wipe();
        assert_eq!(values.0.len(), 2);
        assert!(values.0.values().all(|value| *value == Fr::from(0u64)));
    }
}
