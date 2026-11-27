//! Paired screening of the checked prepared witness's map and dense-slot API.
//! Run with a pinned synthetic Privacy Rings fixture directory. Prints raw CSV;
//! this measures witness solving and row checks, not complete proving.

use std::collections::BTreeMap;
use std::fs;
use std::hint::black_box;
use std::path::Path;
use std::time::Instant;

use xark_ir::function_decode::PreparedStreamSolver;

fn request_inputs(solver: &PreparedStreamSolver, path: &Path) -> BTreeMap<u32, String> {
    let names: BTreeMap<_, _> = solver
        .input_vars()
        .iter()
        .map(|var| (var.name.as_str(), var.id))
        .collect();
    let json: BTreeMap<String, String> =
        serde_json::from_slice(&fs::read(path).expect("request input file")).expect("input JSON");
    json.into_iter()
        .map(|(name, value)| (*names.get(name.as_str()).expect("known input"), value))
        .collect()
}

fn main() {
    let root = std::env::args().nth(1).expect("synthetic fixture root");
    let samples: usize = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "100".into())
        .parse()
        .expect("sample count");
    let root = Path::new(&root);
    println!("circuit,iteration,request,arm,nanos,assigned");
    for circuit in ["withdrawal", "escrow"] {
        let xbc = fs::read(root.join("reference").join(circuit).join("circuit.xbc"))
            .expect("circuit artifact");
        let solver = PreparedStreamSolver::new(&xbc).expect("prepared solver");
        let mut dirs: Vec<_> = fs::read_dir(root.join("requests").join(circuit))
            .expect("request fixture")
            .flat_map(|level| fs::read_dir(level.expect("level").path()).expect("request level"))
            .map(|dir| dir.expect("request").path())
            .collect();
        dirs.sort();
        assert_eq!(dirs.len(), 4, "four distinct synthetic requests");
        let inputs: Vec<_> = dirs
            .iter()
            .map(|dir| request_inputs(&solver, &dir.join("inputs.json")))
            .collect();
        for input in &inputs {
            let map = solver.solve_satisfied(input).expect("map preflight");
            let slots = solver.solve_satisfied_slots(input).expect("slot preflight");
            let from_slots = slots.into_map();
            assert_eq!(map, from_slots, "exact checked witness equivalence");
        }
        for iteration in 0..samples {
            let request = iteration % inputs.len();
            let order = if iteration % 2 == 0 {
                ["map", "slots"]
            } else {
                ["slots", "map"]
            };
            for arm in order {
                let start = Instant::now();
                let assigned = if arm == "map" {
                    black_box(
                        solver
                            .solve_satisfied(&inputs[request])
                            .expect("checked map"),
                    )
                    .len()
                } else {
                    black_box(
                        solver
                            .solve_satisfied_slots(&inputs[request])
                            .expect("checked slots"),
                    )
                    .iter()
                    .flatten()
                    .count()
                };
                let nanos = start.elapsed().as_nanos();
                println!("{circuit},{iteration},{request},{arm},{nanos},{assigned}");
            }
        }
    }
}
