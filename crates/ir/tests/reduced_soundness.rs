//! The template-reduced R1CS (what `xark setup` keys) must stay as sound as the full
//! circuit. Regression: the per-scope minimizer used to treat a template call's
//! output as a free internal variable in the *caller*, eliminate it there and drop
//! the row tying it to a public output — leaving the output unconstrained, so a proof
//! could claim any value.
//!
//! Fixture: `examples/poseidon2_sponge`'s `circuit.xbc` (`xark build`; its rounds
//! are templated). Regenerate it after a container-format change.

use std::collections::BTreeMap;

use ark_bn254::Fr;
use xark_ir::function_decode::{
    PreparedStreamSolver, expand_function_blob, expand_function_blob_reduced, stream_solve_verify,
};
use xark_ir::solver::{check_cp, solve_cp};

const XBC: &[u8] = include_bytes!("fixtures/poseidon2_sponge.xbc");
/// `poseidon2_sponge(1, 2, 3, 4, 5)`.
const HASH: &str = "8828141863764826539393608139805007447022200187560478202710690249571019683634";

fn inputs(h: &str) -> BTreeMap<u32, String> {
    let full = expand_function_blob(XBC).unwrap();
    let id = |n: &str| full.vars.iter().find(|v| v.name == n).unwrap().id;
    [
        ("a", "1"),
        ("b", "2"),
        ("c", "3"),
        ("d", "4"),
        ("e", "5"),
        ("out", h),
    ]
    .into_iter()
    .map(|(n, v)| (id(n), v.to_string()))
    .collect()
}

fn witness(h: &str) -> BTreeMap<u32, xark_ir::solver::Fp> {
    solve_cp(&expand_function_blob(XBC).unwrap(), &inputs(h)).unwrap()
}

#[test]
fn prepared_solver_matches_full_stream_checks_after_a_rejected_request() {
    let solver = PreparedStreamSolver::new(XBC).unwrap();
    let valid = inputs(HASH);
    let invalid = inputs("12345");
    let expected = stream_solve_verify(XBC, &valid).unwrap();
    let (actual, rejected) = rayon::join(
        || solver.solve_verify(&valid),
        || solver.solve_verify(&invalid),
    );
    let actual = actual.unwrap();
    assert_eq!(
        rejected.unwrap_err(),
        stream_solve_verify(XBC, &invalid).unwrap_err()
    );
    assert_eq!(actual.0, expected.0);
    let report = |rows: Vec<xark_ir::solver::UnderConstrained>| {
        rows.into_iter()
            .map(|row| (row.var, row.name, row.reason))
            .collect::<Vec<_>>()
    };
    assert_eq!(report(actual.1), report(expected.1));
    assert_eq!(solver.solve_verify(&valid).unwrap().0, expected.0);
    assert!(PreparedStreamSolver::new(&XBC[..6]).is_err());
}

#[test]
fn typed_field_inputs_match_decimal_solver_and_reject_invalid_statements() {
    let solver = PreparedStreamSolver::new(XBC).unwrap();
    let decimal = inputs(HASH);
    let fields: BTreeMap<u32, Fr> = decimal
        .iter()
        .map(|(&id, value)| (id, value.parse().unwrap()))
        .collect();
    let expected = solver.solve_verify(&decimal).unwrap();
    let actual = solver.solve_verify_fields(&fields).unwrap();
    let dense = solver.solve_verify_dense_fields(&fields).unwrap();
    assert_eq!(actual.0, expected.0);
    for (&id, value) in &expected.0 {
        assert_eq!(dense.0[id as usize], value.as_bn254_fr());
    }
    let report = |rows: Vec<xark_ir::solver::UnderConstrained>| {
        rows.into_iter()
            .map(|row| (row.var, row.name, row.reason))
            .collect::<Vec<_>>()
    };
    let expected_report = report(expected.1);
    assert_eq!(report(actual.1), expected_report);
    assert_eq!(report(dense.1), expected_report);

    let invalid = inputs("12345");
    let invalid_fields: BTreeMap<u32, Fr> = invalid
        .iter()
        .map(|(&id, value)| (id, value.parse().unwrap()))
        .collect();
    assert_eq!(
        solver.solve_verify_fields(&invalid_fields).unwrap_err(),
        solver.solve_verify(&invalid).unwrap_err()
    );
    assert_eq!(
        solver
            .solve_verify_dense_fields(&invalid_fields)
            .unwrap_err(),
        solver.solve_verify(&invalid).unwrap_err()
    );
    let mut missing = fields;
    missing.remove(&solver.input_vars()[0].id);
    let mut missing_decimal = decimal;
    missing_decimal.remove(&solver.input_vars()[0].id);
    assert_eq!(
        solver.solve_verify_fields(&missing).unwrap_err(),
        solver.solve_verify(&missing_decimal).unwrap_err()
    );
    assert_eq!(
        solver.solve_verify_dense_fields(&missing).unwrap_err(),
        solver.solve_verify(&missing_decimal).unwrap_err()
    );
}

#[test]
fn fixture_is_templated() {
    // Otherwise the tests below check a flat circuit and prove nothing about the
    // per-template minimizer.
    assert!(xark_ir::function_decode::count_templates(XBC) > 0);
}

#[test]
fn reduced_circuit_rejects_a_wrong_public_output() {
    let full = expand_function_blob(XBC).unwrap();
    let reduced = expand_function_blob_reduced(XBC).unwrap();
    let honest = witness(HASH);
    assert!(
        check_cp(&full, &honest).is_ok(),
        "the full circuit accepts the hash"
    );
    assert!(
        check_cp(&reduced, &honest).is_ok(),
        "so does the keyed (reduced) one"
    );
    let forged = witness("12345");
    assert!(
        check_cp(&full, &forged).is_err(),
        "the full circuit rejects out = 12345"
    );
    assert!(
        check_cp(&reduced, &forged).is_err(),
        "the keyed (reduced) circuit must reject it too"
    );
}

#[test]
fn reduced_circuit_references_every_public_input() {
    let reduced = expand_function_blob_reduced(XBC).unwrap();
    for v in reduced
        .vars
        .iter()
        .filter(|v| v.role == xark_ir::primitive::VarRole::PublicInput)
    {
        assert!(
            reduced
                .constraints
                .iter()
                .flat_map(|r| [&r.a, &r.b, &r.c])
                .any(|lc| lc.terms.iter().any(|t| t.var == v.id)),
            "public input `{}` is unconstrained in the keyed circuit",
            v.name
        );
    }
}
