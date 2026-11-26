use std::path::PathBuf;
use std::time::Instant;

use super::*;

#[test]
#[ignore = "requires private synthetic Privacy Rings fixtures"]
fn privacy_rings_solver_ablations() {
    let root = PathBuf::from(std::env::var_os("XARK_SOLVER_ABLATION_FIXTURES").unwrap());
    let circuit = std::env::var("XARK_SOLVER_ABLATION_CIRCUIT").unwrap();
    assert!(matches!(circuit.as_str(), "escrow" | "withdrawal"));
    let bytes = std::fs::read(root.join("reference").join(&circuit).join("circuit.xbc")).unwrap();
    let start = Instant::now();
    let (field, vars, defs, top_c, top_w, keep_extra, num_inputs) = decode_compact(&bytes);
    let modulus = num_bigint::BigUint::parse_bytes(field.modulus_decimal.as_bytes(), 10).unwrap();
    assert!(crate::solver::is_bn254(&modulus));
    let decode = start.elapsed();
    let start = Instant::now();
    let witness = eval::WProgram::compile(&defs, &top_w);
    let witness_compile = start.elapsed();
    let start = Instant::now();
    let rows = eval::compile(&defs, &top_c);
    let row_compile = start.elapsed();
    eprintln!(
        "ablation setup circuit={circuit} threads={} decode_ns={} witness_compile_ns={} row_compile_ns={}",
        rayon::current_num_threads(),
        decode.as_nanos(),
        witness_compile.as_nanos(),
        row_compile.as_nanos()
    );

    let input_vars = &vars[..num_inputs];
    let public = input_vars
        .iter()
        .find(|v| v.name == "public_hash")
        .unwrap()
        .id;
    let inputs: Vec<_> = (1..=4)
        .map(|request| {
            let directory = root
                .join("requests")
                .join(&circuit)
                .join(request.to_string());
            let mut candidates = directory.read_dir().unwrap();
            let fixture = candidates.next().unwrap().unwrap().path();
            assert!(candidates.next().is_none());
            let read = |name| -> BTreeMap<String, String> {
                serde_json::from_slice(&std::fs::read(fixture.join(name)).unwrap()).unwrap()
            };
            let names = read("inputs.json");
            assert_eq!(names.len(), input_vars.len());
            let ids: BTreeMap<_, _> = input_vars
                .iter()
                .map(|v| (v.id, names[&v.name].clone()))
                .collect();
            let mut altered = ids.clone();
            altered.insert(public, read("public-changed.json")["public_hash"].clone());
            (ids, altered)
        })
        .collect();

    let run = |mode, inputs: &BTreeMap<u32, String>| {
        if mode == 0 {
            return stream_solve_verify(&bytes, inputs);
        }
        let compiled_witness = matches!(mode, 2 | 4).then_some(&witness);
        let assign = solve_streamed_with_program(
            input_vars,
            vars.len(),
            &defs,
            &top_w,
            &modulus,
            inputs,
            compiled_witness,
        )?;
        let compiled_rows;
        let row_program = if matches!(mode, 3 | 4) {
            &rows
        } else {
            compiled_rows = eval::compile(&defs, &top_c);
            &compiled_rows
        };
        let (valid, report) = stream_underconstrained_with_program(
            (&defs, &top_c),
            &vars,
            &keep_extra,
            &assign,
            &modulus,
            true,
            Some(row_program),
        );
        if !valid {
            return Err("a constraint is unsatisfied".into());
        }
        Ok((crate::solver::slots_into_map(assign), report))
    };

    let expected: Vec<_> = inputs
        .iter()
        .map(|(valid, altered)| {
            let rejected = run(0, altered).expect_err("original solver must reject altered input");
            for mode in 1..5 {
                assert_eq!(
                    run(mode, altered).expect_err("ablation must reject altered input"),
                    rejected
                );
            }
            run(0, valid).unwrap()
        })
        .collect();

    let modes = ["original", "decoded", "witness", "rows", "both"];
    for round in 0..24 {
        let request = round % inputs.len();
        // Rotate the initial arm so each setting sees all execution positions.
        for slot in 0..modes.len() {
            let mode = (round + slot) % modes.len();
            let started = Instant::now();
            let actual = run(mode, &inputs[request].0).unwrap();
            let elapsed = started.elapsed();
            let want = &expected[request];
            assert!(actual.0 == want.0, "solver assignment changed");
            assert!(
                actual
                    .1
                    .iter()
                    .map(|row| (row.var, &row.name, &row.reason))
                    .eq(want.1.iter().map(|row| (row.var, &row.name, &row.reason))),
                "under-constraint report changed"
            );
            if round >= 4 {
                println!(
                    "ablation sample={} request={request} position={slot} mode={} total_ns={} verified=true",
                    round - 4,
                    modes[mode],
                    elapsed.as_nanos()
                );
            }
        }
    }
    eprintln!("ablation verified circuit={circuit} measured_per_mode=20 altered_cases=4");
}
