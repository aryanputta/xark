//! Bench-only allocation probe for the prepared Privacy Rings witness solver.
//! Prints counts and durations, never private input values or assignments.

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use xark_ir::function_decode::{PreparedStreamSolver, decode_input_vars, stream_solve_verify};

struct CountAlloc;
static ALLOC_CALLS: AtomicU64 = AtomicU64::new(0);
static REQUESTED_BYTES: AtomicU64 = AtomicU64::new(0);

#[global_allocator]
static ALLOCATOR: CountAlloc = CountAlloc;

unsafe impl GlobalAlloc for CountAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        REQUESTED_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        REQUESTED_BYTES.fetch_add(new_size as u64, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let [circuit, directories @ ..] = args.as_slice() else {
        panic!("row_scratch_probe XBC REQUEST_DIR...");
    };
    assert_eq!(
        directories.len(),
        4,
        "four distinct request directories required"
    );
    let bytes = std::fs::read(circuit).expect("read circuit");
    let vars = decode_input_vars(&bytes).expect("decode inputs");
    let prepared = PreparedStreamSolver::new(&bytes).expect("prepare exact circuit");
    let public = vars
        .iter()
        .find(|v| v.name == "public_hash")
        .expect("fixture has public_hash")
        .id;
    let mut inputs = Vec::new();
    for directory in directories {
        let path = Path::new(directory);
        let names: BTreeMap<String, String> =
            serde_json::from_slice(&std::fs::read(path.join("inputs.json")).expect("inputs"))
                .expect("parse inputs");
        let ids = vars
            .iter()
            .map(|v| (v.id, names[&v.name].clone()))
            .collect::<BTreeMap<_, _>>();
        let changed: BTreeMap<String, String> = serde_json::from_slice(
            &std::fs::read(path.join("public-changed.json")).expect("changed public"),
        )
        .expect("parse changed public");
        let mut altered = ids.clone();
        altered.insert(public, changed["public_hash"].clone());
        assert_eq!(
            prepared
                .solve_verify(&altered)
                .expect_err("altered accepted"),
            stream_solve_verify(&bytes, &altered).expect_err("control accepted altered")
        );
        inputs.push(ids);
    }
    println!("altered_solver_requests_rejected=4");
    for i in 0..16 {
        let ids = &inputs[i % inputs.len()];
        let before = ALLOC_CALLS.load(Ordering::Relaxed);
        let before_bytes = REQUESTED_BYTES.load(Ordering::Relaxed);
        let start = Instant::now();
        let candidate = prepared.solve_verify(ids).expect("prepared solve");
        let elapsed = start.elapsed().as_nanos();
        let allocations = ALLOC_CALLS.load(Ordering::Relaxed) - before;
        let requested_bytes = REQUESTED_BYTES.load(Ordering::Relaxed) - before_bytes;
        let reference = stream_solve_verify(&bytes, ids).expect("reference solve");
        assert_eq!(candidate.0, reference.0, "assignment mismatch");
        assert!(
            candidate
                .1
                .iter()
                .map(|r| (&r.var, &r.name, &r.reason))
                .eq(reference.1.iter().map(|r| (&r.var, &r.name, &r.reason))),
            "under-constraint report mismatch"
        );
        if i >= 4 {
            println!(
                "sample={} fixture={} allocation_calls={} requested_bytes={} solve_ns={elapsed}",
                i - 4,
                i % inputs.len(),
                allocations,
                requested_bytes,
            );
        }
    }
}
