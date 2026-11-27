//! Diagnostic paired witness-solver comparison on an existing circuit fixture.
//! Usage: bench_prepared_inputs CIRCUIT.xbc INPUTS.json PAIRS

use std::collections::BTreeMap;
use std::hint::black_box;
use std::time::Instant;

use ark_bn254::Fr;
use ark_ff::PrimeField;
use num_bigint::BigUint;
use xark_ir::function_decode::PreparedStreamSolver;
use xark_ir::primitive::VarRole;
use zeroize::Zeroize;

fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    let [_, xbc_path, inputs_path, pairs] = args.as_slice() else {
        return Err("usage: bench_prepared_inputs CIRCUIT.xbc INPUTS.json PAIRS".into());
    };
    let pairs: usize = pairs.parse().map_err(|_| "PAIRS must be a number")?;
    if pairs == 0 {
        return Err("PAIRS must be positive".into());
    }
    let xbc = std::fs::read(xbc_path).map_err(|err| err.to_string())?;
    let names: BTreeMap<String, String> =
        serde_json::from_slice(&std::fs::read(inputs_path).map_err(|err| err.to_string())?)
            .map_err(|err| err.to_string())?;
    let solver = PreparedStreamSolver::new(&xbc)?;
    let input_ids: BTreeMap<_, _> = solver
        .input_vars()
        .iter()
        .filter(|var| matches!(var.role, VarRole::PublicInput | VarRole::PrivateInput))
        .map(|var| (var.name.as_str(), var.id))
        .collect();
    let mut decimals = BTreeMap::new();
    let mut fields = BTreeMap::new();
    for (name, value) in &names {
        let id = *input_ids
            .get(name.as_str())
            .ok_or_else(|| format!("unknown input name: {name}"))?;
        let positive = BigUint::parse_bytes(value.as_bytes(), 10)
            .ok_or_else(|| format!("input {name} is not an unsigned decimal"))?;
        let field = Fr::from_le_bytes_mod_order(&positive.to_bytes_le());
        decimals.insert(id, value.clone());
        fields.insert(id, field);
    }
    let decimal_result = solver.solve_verify(&decimals)?;
    let dense_result = solver.solve_verify_dense_fields(&fields)?;
    for (&id, value) in &decimal_result.0 {
        assert_eq!(
            dense_result.0[id as usize],
            value.as_bn254_fr(),
            "witness assignments differ"
        );
    }
    let report = |rows: Vec<xark_ir::solver::UnderConstrained>| {
        rows.into_iter()
            .map(|row| (row.var, row.name, row.reason))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        report(decimal_result.1),
        report(dense_result.1),
        "under-constraint reports differ"
    );
    println!(
        "verified inputs={} pairs={pairs} boundary=map-prep-solve-cleanup",
        fields.len()
    );
    println!("pair,first,decimal_map_ns,field_dense_ns");
    for pair in 0..pairs {
        let timed_decimal = || {
            let start = Instant::now();
            let mut request: BTreeMap<u32, String> = fields
                .iter()
                .map(|(&id, value)| (id, value.into_bigint().to_string()))
                .collect();
            let result = solver
                .solve_verify(black_box(&request))
                .expect("decimal solve");
            request.values_mut().for_each(Zeroize::zeroize);
            let duration = start.elapsed().as_nanos();
            black_box(result);
            duration
        };
        let timed_field = || {
            let start = Instant::now();
            let mut request = fields.clone();
            let result = solver
                .solve_verify_dense_fields(black_box(&request))
                .expect("field solve");
            request.values_mut().for_each(Zeroize::zeroize);
            let duration = start.elapsed().as_nanos();
            black_box(result);
            duration
        };
        let (first, decimal_ns, field_ns) = if pair % 2 == 0 {
            let decimal = timed_decimal();
            ("decimal", decimal, timed_field())
        } else {
            let field = timed_field();
            ("field", timed_decimal(), field)
        };
        println!("{},{first},{decimal_ns},{field_ns}", pair + 1);
    }
    Ok(())
}
