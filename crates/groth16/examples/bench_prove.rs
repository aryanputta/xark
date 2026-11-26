//! End-to-end prover benchmark: arkworks baseline vs the streaming prover, with a
//! peak-heap-tracking allocator so every phase reports its own high-water mark.
//!
//! ```text
//! bench_prove counts <circuit.xbc>                         # inspect before generating keys
//! bench_prove check-witness <circuit.xbc> <statement-dir> # check the solved public input
//! bench_prove export-iden3 <circuit.xbc> <statement-dir> <new-directory>
//! bench_prove setup-reduced <circuit.xbc> <out pk.bin>     # key the template-reduced circuit
//! bench_prove ark    <circuit.xbc> <pk.bin> <inputs.json> [--reduced]
//! bench_prove stream <circuit.xbc> <pk.bin> <inputs.json> [--source xbc|min] [--tile N] [--chunk N]
//! BENCH_TIME=1 bench_prove warm <circuit.xbc> <reduced pk.bin> <inputs.json> [proofs] [warmups]
//! BENCH_TIME=1 bench_prove warm-requests <circuit.xbc> <reduced pk.bin> <cpu|gls> <concurrency> <requests> <fixture-dir>...
//! BENCH_TIME=1 bench_prove query-msm <circuit.xbc> <reduced pk.bin> <statement-dir> [samples] [warmups]
//! BENCH_TIME=1 bench_prove query-msm-xark <circuit.xbc> <reduced pk.bin> <statement-dir> [samples] [warmups]
//! BENCH_TIME=1 bench_prove query-msm-b2-shifted <circuit.xbc> <reduced pk.bin> <statement-dir> [samples] [warmups]
//! BENCH_TIME=1 bench_prove query-msm-b2-cached-gls <circuit.xbc> <reduced pk.bin> <statement-dir> [samples] [warmups]
//! BENCH_TIME=1 bench_prove query-msm-b2-cached-gls-reciprocal <circuit.xbc> <reduced pk.bin> <statement-dir> [samples] [warmups]
//! bench_prove query-msm-export <circuit.xbc> <reduced pk.bin> <statement-dir> <new-output-file>
//! ```
//! `--reduced` / `--source xbc` prove the template-reduced circuit (key from
//! `setup-reduced`); otherwise the boundary-minimized circuit `xark setup` keys.
//! `warm` also uses a key from `setup-reduced`. It times resident prover adapter
//! calls with witness solving and independent verification outside the samples.
//! For a controlled CPU comparison, set `BENCH_MERGE_BELOW=0` to disable merging.
//! Set `BENCH_WARM_BACKEND=cpu` to time Xark alone while still checking each
//! proof with Arkworks. The default times both prover adapters.
//! `BENCH_CHECK_ROWS=1` includes witness row checks in warm timing for Gnark.
//! `BENCH_CHECK_ROWS=expanded` checks by expanding rows and leaves the prover's
//! row evaluator unchanged. Both print the check duration after verification.
//! For split resident CPU proofs, `BENCH_RESIDENT_PROFILE=1` records task spans.
//! Use it with `BENCH_TIME=1 BENCH_WARM_BACKEND=cpu` and an SDK statement directory.
//! For either Privacy Rings timelock fixture, set `BENCH_PUBLIC_STATEMENTS` to
//! the directory containing `public.json` and `public-changed.json`.
//! `query-msm` takes that directory as an argument and times the decoded B1
//! and B2 queries in isolation. It alternates backend order and checks every
//! group result against Arkworks before reporting timings. Use
//! `RAYON_NUM_THREADS` to set the shared worker budget and `NO_GLV=1` to
//! disable GLV for Xark's query benchmark.
//! `query-msm-xark` times Xark's B1 and B2 queries in separate batches and
//! checks each result against precomputed Arkworks references.
//! With `--features msm-g2-endpoint-bench`, set `BENCH_G2_TRIM_INVERSE_ENDPOINTS`
//! to `1` to omit redundant products in G2 affine batch inversion. `0` is the default.
//! `query-msm-g2-endpoints-paired` takes the same arguments as `query-msm-xark`
//! and alternates both modes for B2 in one process. Leave the selector unset.
//! `BENCH_G2_SPARSE_ENDOMORPHISM=1` specializes the G2 GLV point map.
//! `query-msm-g2-factorial` checks all four combinations on the same B2 inputs.
//! `query-msm-b2-shifted` compares the B2 MSM with a resident table of original
//! and 128-bit-shifted points. It times preparation separately and checks both
//! outputs against Arkworks. The 3 MiB table cap covers its retained affine
//! payload. Warm timings include scalar splitting and allocation. The ordinary
//! B2 baseline already uses a GLV split for eligible full-width scalars.
//! Build with `--features msm-g2-shifted-bench`. In `warm`, set
//! `BENCH_G2_SHIFTED=1 BENCH_WARM_BACKEND=cpu` with fixture statements to
//! measure the same shifted operation in a complete resident CPU proof.
//! `query-msm-b2-cached-gls` caches four public G2 images per B2 base and
//! measures exact scalar recoding separately. The same-process ordinary Xark
//! baseline and cached arm are independently checked against Arkworks. The
//! reciprocal mode replaces BigInt recoding and checks the ordered recoded
//! fixture against exact division before timing.
//! In `warm`, `BENCH_G2_CACHED_GLS=1` uses that fixed-limb path for complete
//! split resident CPU proofs with `--features msm-g2-shifted-bench`.
//! Use `check-g2-subgroup PROVING_KEY PAIRS` to compare public-key validation
//! algorithms. `BENCH_G2_SIGNED_SUBGROUP=1` selects signed validation in cached
//! GLS warm proofs, including all on-curve and subgroup checks.
//! `BENCH_SHARED_B_SCALARS=1` with `msm-b-shared-bench` shares a canonical
//! scalar vector across the two unchunked B queries for one CPU proof.
//! `query-msm-export` writes both ordered queries, the witness scalars, and
//! Arkworks reference sums for a same-input benchmark. Use reproducible test
//! fixtures and keep the witness-bearing export in local scratch storage.

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::time::{Duration, Instant};

use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress};
use ark_snark::SNARK;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use xark_groth16::{
    BytecodeSource, ConstraintSource, Cpu, FftConfig, Probe, ProgramSource, Prover, ProverConfig,
    SerializedPk, prove_with_rng,
};
use xark_ir::VarId;
use xark_prover::XarkCircuit;

#[path = "../tests/support/ark.rs"]
mod ark;
#[path = "../tests/support/arkworks_prover.rs"]
mod arkworks_prover;
#[path = "support/iden3.rs"]
mod iden3;
#[path = "support/query_msm.rs"]
mod query_msm;
#[cfg(feature = "msm-g2-shifted-bench")]
#[path = "support/resident_requests.rs"]
mod resident_requests;
use ark::{ArkCircuit, convert};
use arkworks_prover::Arkworks;

struct PeakAlloc;
static CUR: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
/// Heap tracking costs two contended atomics per allocation, which slows the
/// allocation-heavy (multi-threaded) phases several-fold. `BENCH_TIME=1` turns it
/// off so the same binary reports honest wall-clock; memory runs leave it on.
static TRACK: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

#[inline(always)]
fn tracking() -> bool {
    TRACK.load(Relaxed)
}

unsafe impl GlobalAlloc for PeakAlloc {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(l) };
        if tracking() && !p.is_null() {
            PEAK.fetch_max(CUR.fetch_add(l.size(), Relaxed) + l.size(), Relaxed);
        }
        p
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        let p = unsafe { System.alloc_zeroed(l) };
        if tracking() && !p.is_null() {
            PEAK.fetch_max(CUR.fetch_add(l.size(), Relaxed) + l.size(), Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) };
        if tracking() {
            CUR.fetch_sub(l.size(), Relaxed);
        }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        let q = unsafe { System.realloc(p, l, new) };
        if tracking() && !q.is_null() {
            if new > l.size() {
                let d = new - l.size();
                PEAK.fetch_max(CUR.fetch_add(d, Relaxed) + d, Relaxed);
            } else {
                CUR.fetch_sub(l.size() - new, Relaxed);
            }
        }
        q
    }
}

#[global_allocator]
static A: PeakAlloc = PeakAlloc;

const MB: f64 = 1024.0 * 1024.0;

/// Records `(phase, ms, peak heap during the phase, live heap after)`.
struct Phases {
    t: Instant,
    t0: Instant,
    overall_peak: usize,
    rows: Vec<(String, f64, usize, usize)>,
}

impl Phases {
    fn new() -> Self {
        PEAK.store(CUR.load(Relaxed), Relaxed);
        Phases {
            t: Instant::now(),
            t0: Instant::now(),
            overall_peak: 0,
            rows: Vec::new(),
        }
    }
    fn mark(&mut self, name: &str) {
        let peak = PEAK.load(Relaxed);
        let cur = CUR.load(Relaxed);
        self.overall_peak = self.overall_peak.max(peak);
        self.rows.push((
            name.to_string(),
            self.t.elapsed().as_secs_f64() * 1e3,
            peak,
            cur,
        ));
        PEAK.store(cur, Relaxed);
        self.t = Instant::now();
    }
    fn print(&self, label: &str) {
        eprintln!("── {label}");
        eprintln!(
            "  {:<22} {:>10} {:>14} {:>12}",
            "phase", "ms", "peak heap MB", "live MB"
        );
        for (n, ms, p, c) in &self.rows {
            eprintln!(
                "  {:<22} {:>10.1} {:>14.1} {:>12.1}",
                n,
                ms,
                *p as f64 / MB,
                *c as f64 / MB
            );
        }
        eprintln!(
            "  {:<22} {:>10.1} {:>14.1}",
            "TOTAL",
            self.t0.elapsed().as_secs_f64() * 1e3,
            self.overall_peak as f64 / MB
        );
        println!(
            "{{\"label\":{label:?},\"total_ms\":{:.1},\"peak_heap_mb\":{:.1},\"phases\":[{}]}}",
            self.t0.elapsed().as_secs_f64() * 1e3,
            self.overall_peak as f64 / MB,
            self.rows
                .iter()
                .map(|(n, ms, p, _)| format!(
                    "{{\"phase\":{n:?},\"ms\":{ms:.1},\"peak_mb\":{:.1}}}",
                    *p as f64 / MB
                ))
                .collect::<Vec<_>>()
                .join(",")
        );
    }
}

impl Probe for Phases {
    fn mark(&mut self, phase: &'static str) {
        if phase != "start" {
            Phases::mark(self, phase);
        }
    }
}

struct ResidentProofProbe<'a> {
    timings: Option<&'a xark_groth16::prover::ResidentTimingSink<'a>>,
    #[cfg(feature = "msm-g2-shifted-bench")]
    shifted: Option<&'a xark_groth16::msm::shifted::ShiftedBases<'a>>,
    #[cfg(feature = "msm-g2-shifted-bench")]
    cached_gls: Option<&'a xark_groth16::prover::BenchResidentB2<'a>>,
    #[cfg(feature = "msm-b-shared-bench")]
    share_b_scalars: bool,
}

impl Probe for ResidentProofProbe<'_> {
    fn resident_timings(&self) -> Option<&xark_groth16::prover::ResidentTimingSink<'_>> {
        self.timings
    }

    #[cfg(feature = "msm-g2-shifted-bench")]
    fn shifted_g2(&self) -> Option<&xark_groth16::msm::shifted::ShiftedBases<'_>> {
        self.shifted
    }

    #[cfg(feature = "msm-g2-shifted-bench")]
    fn cached_gls_g2(&self) -> Option<&xark_groth16::prover::BenchResidentB2<'_>> {
        self.cached_gls
    }

    #[cfg(feature = "msm-b-shared-bench")]
    fn share_b_scalars(&self) -> bool {
        self.share_b_scalars
    }
}

struct TaskSpan {
    phase: &'static str,
    offset: Duration,
    elapsed: Duration,
}

struct ProfiledCpu<'a, P> {
    cpu: Cpu<P>,
    profiles: Option<&'a mut Vec<Vec<TaskSpan>>>,
    #[cfg(feature = "msm-g2-shifted-bench")]
    shifted: Option<&'a xark_groth16::msm::shifted::ShiftedBases<'a>>,
    #[cfg(feature = "msm-g2-shifted-bench")]
    cached_gls: Option<&'a xark_groth16::prover::BenchResidentB2<'a>>,
    #[cfg(feature = "msm-b-shared-bench")]
    share_b_scalars: bool,
}

impl<P: xark_groth16::PkSource> Prover for ProfiledCpu<'_, P> {
    fn name(&self) -> &str {
        self.cpu.name()
    }

    fn prove(
        &mut self,
        src: &dyn ConstraintSource,
        z: &[Fr],
        r: Fr,
        s: Fr,
    ) -> Result<xark_groth16::Proof<Bn254>, xark_groth16::ProveError> {
        let Some(profiles) = self.profiles.as_deref_mut() else {
            return xark_groth16::prove_with_randomness(
                src,
                z,
                &mut self.cpu.pk,
                r,
                s,
                &self.cpu.cfg,
                &mut ResidentProofProbe {
                    timings: None,
                    #[cfg(feature = "msm-g2-shifted-bench")]
                    shifted: self.shifted,
                    #[cfg(feature = "msm-g2-shifted-bench")]
                    cached_gls: self.cached_gls,
                    #[cfg(feature = "msm-b-shared-bench")]
                    share_b_scalars: self.share_b_scalars,
                },
            );
        };
        let spans = Mutex::new(Vec::new());
        let origin = Instant::now();
        let record = |phase, started: Instant, elapsed| {
            spans.lock().unwrap().push(TaskSpan {
                phase,
                offset: started.duration_since(origin),
                elapsed,
            });
        };
        let proof = xark_groth16::prove_with_randomness(
            src,
            z,
            &mut self.cpu.pk,
            r,
            s,
            &self.cpu.cfg,
            &mut ResidentProofProbe {
                timings: Some(&record),
                #[cfg(feature = "msm-g2-shifted-bench")]
                shifted: self.shifted,
                #[cfg(feature = "msm-g2-shifted-bench")]
                cached_gls: self.cached_gls,
                #[cfg(feature = "msm-b-shared-bench")]
                share_b_scalars: self.share_b_scalars,
            },
        )?;
        let mut spans = spans.into_inner().unwrap();
        spans.sort_unstable_by_key(|event| event.offset);
        profiles.push(spans);
        Ok(proof)
    }
}

fn arg_val(args: &[String], k: &str) -> Option<String> {
    args.iter()
        .position(|a| a == k)
        .map(|i| args[i + 1].clone())
}

fn solve(xbc: &[u8], inputs_path: &str) -> BTreeMap<VarId, Fr> {
    solve_with_prepared(xbc, inputs_path, None)
}

fn solve_with_prepared(
    xbc: &[u8],
    inputs_path: &str,
    prepared: Option<&xark_ir::function_decode::PreparedStreamSolver>,
) -> BTreeMap<VarId, Fr> {
    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(inputs_path).unwrap()).unwrap();
    let names: BTreeMap<String, String> = json
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
        .collect();
    let (fp, _) = if let Some(prepared) = prepared {
        let ids = xark_prover::resolve_input_ids(prepared.input_vars(), &names).unwrap();
        prepared.solve_verify(&ids)
    } else {
        let vars = xark_ir::function_decode::decode_input_vars(xbc).unwrap();
        let ids = xark_prover::resolve_input_ids(&vars, &names).unwrap();
        drop(vars);
        xark_ir::function_decode::stream_solve_verify(xbc, &ids)
    }
    .unwrap();
    xark_prover::lower_witness(&fp)
}

fn reduced(xbc: &[u8]) -> xark_ir::R1csProgram {
    xark_ir::function_decode::expand_function_blob_reduced(xbc)
        .unwrap()
        .into_r1cs()
}

fn public_hash(path: &std::path::Path) -> Fr {
    let bytes = std::fs::read(path).expect("read public statement");
    let statement: BTreeMap<String, String> =
        serde_json::from_slice(&bytes).expect("decode public statement");
    assert_eq!(statement.len(), 1, "expected one public input");
    statement
        .get("public_hash")
        .expect("statement must contain public_hash")
        .parse()
        .expect("parse public_hash as a field element")
}

fn check_statements(directory: &std::path::Path, actual: &[Fr]) -> Fr {
    let expected = public_hash(&directory.join("public.json"));
    let changed = public_hash(&directory.join("public-changed.json"));
    assert!(
        actual == [expected],
        "witness public input does not match the fixture statement"
    );
    assert!(expected != changed, "changed statement must differ");
    changed
}

fn checked_arkworks_encoding<A: CanonicalSerialize, B: CanonicalDeserialize>(value: &A) -> B {
    let mut bytes = Vec::new();
    value
        .serialize_compressed(&mut bytes)
        .expect("serialize benchmark artifact");
    B::deserialize_compressed(bytes.as_slice()).expect("validate Arkworks benchmark artifact")
}

fn main() {
    // Must be decided before any allocation is tracked (CUR would underflow if
    // tracking switched off/on mid-run).
    if std::env::var("BENCH_TIME").is_ok() {
        TRACK.store(false, Relaxed);
    }
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).is_some_and(|mode| mode == "warm-requests") {
        #[cfg(feature = "msm-g2-shifted-bench")]
        {
            resident_requests::run(&args[2..]);
            return;
        }
        #[cfg(not(feature = "msm-g2-shifted-bench"))]
        panic!("warm-requests requires the msm-g2-shifted-bench feature");
    }
    if args
        .get(1)
        .is_some_and(|mode| mode == "query-msm-g2-factorial")
    {
        #[cfg(feature = "msm-g2-endpoint-bench")]
        {
            query_msm::run_g2_factorial(&args[2..]);
            return;
        }
        #[cfg(not(feature = "msm-g2-endpoint-bench"))]
        panic!("query-msm-g2-factorial requires the msm-g2-endpoint-bench feature");
    }
    if args
        .get(1)
        .is_some_and(|mode| mode == "query-msm-g2-endpoints-paired")
    {
        #[cfg(feature = "msm-g2-endpoint-bench")]
        {
            query_msm::run_g2_endpoint_pairs(&args[2..]);
            return;
        }
        #[cfg(not(feature = "msm-g2-endpoint-bench"))]
        panic!("query-msm-g2-endpoints-paired requires the msm-g2-endpoint-bench feature");
    }
    if std::env::var("NO_BATCH_AFFINE").is_ok() {
        xark_groth16::msm::BATCH_AFFINE.store(false, Relaxed);
    }
    #[cfg(feature = "msm-g2-endpoint-bench")]
    {
        let setting = |name| match std::env::var(name) {
            Err(std::env::VarError::NotPresent) => false,
            Ok(setting) if setting == "0" => false,
            Ok(setting) if setting == "1" => true,
            _ => panic!("{name} must be 0 or 1"),
        };
        let trim = setting("BENCH_G2_TRIM_INVERSE_ENDPOINTS");
        let sparse = setting("BENCH_G2_SPARSE_ENDOMORPHISM");
        assert!(
            !trim || xark_groth16::msm::BATCH_AFFINE.load(Relaxed),
            "trimmed inverse endpoints require batch affine"
        );
        assert!(
            !sparse || std::env::var_os("NO_GLV").is_none(),
            "sparse endomorphism requires GLV"
        );
        xark_groth16::msm::set_bench_g2_trim_inverse_endpoints(trim);
        xark_groth16::msm::set_bench_g2_sparse_endomorphism(sparse);
        eprintln!("bench g2 trim inverse endpoints: {}", u8::from(trim));
        eprintln!("bench g2 sparse endomorphism: {}", u8::from(sparse));
    }
    #[cfg(not(feature = "msm-g2-endpoint-bench"))]
    assert!(
        std::env::var_os("BENCH_G2_TRIM_INVERSE_ENDPOINTS").is_none(),
        "BENCH_G2_TRIM_INVERSE_ENDPOINTS requires the msm-g2-endpoint-bench feature"
    );
    #[cfg(not(feature = "msm-g2-endpoint-bench"))]
    assert!(
        std::env::var_os("BENCH_G2_SPARSE_ENDOMORPHISM").is_none(),
        "BENCH_G2_SPARSE_ENDOMORPHISM requires the msm-g2-endpoint-bench feature"
    );
    let mode = args[1].as_str();
    let signed_subgroup = match std::env::var("BENCH_G2_SIGNED_SUBGROUP").as_deref() {
        Ok("0") | Err(std::env::VarError::NotPresent) => false,
        Ok("1") => true,
        _ => panic!("BENCH_G2_SIGNED_SUBGROUP must be 0 or 1"),
    };
    assert!(
        !signed_subgroup
            || (cfg!(feature = "msm-g2-shifted-bench")
                && mode == "warm"
                && std::env::var("BENCH_G2_CACHED_GLS").as_deref() == Ok("1")),
        "signed subgroup validation requires cached GLS warm mode"
    );
    let share_b_scalars = match std::env::var("BENCH_SHARED_B_SCALARS").as_deref() {
        Err(std::env::VarError::NotPresent) => false,
        Ok(value @ ("0" | "1")) if cfg!(feature = "msm-b-shared-bench") && mode == "warm" => {
            value == "1"
        }
        _ => panic!("BENCH_SHARED_B_SCALARS requires warm mode, msm-b-shared-bench, and 0 or 1"),
    };
    assert!(
        std::env::var_os("BENCH_G2_CACHED_GLS").is_none()
            || (cfg!(feature = "msm-g2-shifted-bench") && mode == "warm"),
        "BENCH_G2_CACHED_GLS requires warm mode and the msm-g2-shifted-bench feature"
    );
    match mode {
        "check-g2-subgroup" => {
            query_msm::cached_gls_b2::run_subgroup_pairs(&args[2..]);
            return;
        }
        "query-msm" | "query-msm-xark" => {
            query_msm::run(&args[2..], mode == "query-msm-xark");
            return;
        }
        #[cfg(feature = "msm-g2-shifted-bench")]
        "query-msm-b2-shifted" => {
            query_msm::shifted_b2::run(&args[2..]);
            return;
        }
        "query-msm-b2-cached-gls" => {
            query_msm::run_cached_gls_b2::<false>(&args[2..]);
            return;
        }
        "query-msm-b2-cached-gls-reciprocal" => {
            query_msm::run_cached_gls_b2::<true>(&args[2..]);
            return;
        }
        "query-msm-export" => {
            query_msm::export(&args[2..]);
            return;
        }
        _ => {}
    }
    let xbc = std::fs::read(&args[2]).unwrap();
    if mode == "check-witness" || mode == "export-iden3" {
        let directory = std::path::Path::new(&args[3]);
        let inputs = directory.join("inputs.json");
        let assign = solve(&xbc, inputs.to_str().expect("UTF-8 input file path"));
        let src = BytecodeSource::new(&xbc).unwrap();
        let z = src.layout().assignment_from_map(&assign);
        check_statements(directory, &z[1..src.layout().num_instance()]);
        if mode == "export-iden3" {
            iden3::write(std::path::Path::new(&args[4]), &src, &z)
                .expect("export the reduced circuit and witness");
            println!(
                "exported reduced iden3 circuit: {} rows, {} wires, {} public inputs",
                src.num_constraints(),
                src.layout().num_vars(),
                src.layout().num_instance() - 1
            );
        }
        println!("fixture witness matches public statement");
        return;
    }
    if mode == "counts" {
        let r = reduced(&xbc);
        let m = XarkCircuit::for_setup(r.clone()).prog().clone();
        let s = BytecodeSource::new(&xbc).unwrap();
        let nnz = |p: &xark_ir::R1csProgram| {
            p.constraints
                .iter()
                .map(|c| c.a.terms.len() + c.b.terms.len() + c.c.terms.len())
                .sum::<usize>()
        };
        println!(
            "reduced: {} rows {} vars {} nnz | minimized: {} rows {} vars {} nnz | xbc items: {} (largest {} rows)",
            r.constraints.len(),
            r.variables.len(),
            nnz(&r),
            m.constraints.len(),
            m.variables.len(),
            nnz(&m),
            s.stream().num_items(),
            s.max_item_rows()
        );
        return;
    }
    let pk_path = std::path::PathBuf::from(&args[3]);

    if mode == "setup-reduced" {
        let prog = reduced(&xbc);
        eprintln!("reduced circuit: {} constraints", prog.constraints.len());
        let circ = XarkCircuit::for_setup_preminimized(prog);
        let (pk, _) = Groth16::<Bn254>::circuit_specific_setup(
            ArkCircuit::of(&circ),
            &mut ChaCha20Rng::seed_from_u64(7),
        )
        .unwrap();
        let mut buf = b"XKPK\x01\x00".to_vec();
        pk.serialize_with_mode(&mut buf, Compress::Yes).unwrap();
        std::fs::write(&pk_path, buf).unwrap();
        return;
    }
    if mode == "rows" {
        // ⟨A_i,z⟩, ⟨B_i,z⟩, ⟨C_i,z⟩ for every row: compiled templates vs expansion.
        let assign = solve(&xbc, &args[4]);
        let mut src = BytecodeSource::new(&xbc).unwrap();
        let z = src.layout().assignment_from_map(&assign);
        let m = src.num_constraints();
        for threads in [1usize, 16] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap();
            for compiled in [false, true] {
                src.set_compiled(compiled);
                let best = (0..3)
                    .map(|_| {
                        pool.install(|| {
                            let (mut a, mut b, mut c) = (
                                vec![Fr::from(0u64); m],
                                vec![Fr::from(0u64); m],
                                vec![Fr::from(0u64); m],
                            );
                            let t = Instant::now();
                            xark_groth16::r1cs::eval_rows(
                                &src,
                                &z,
                                1 << 14,
                                [Some(&mut a), Some(&mut b), Some(&mut c)],
                            );
                            t.elapsed().as_secs_f64()
                        })
                    })
                    .fold(f64::MAX, f64::min);
                println!(
                    "threads {threads:2} {:>9}: {best:.3}s per pass ({m} rows)",
                    if compiled { "compiled" } else { "expanded" }
                );
            }
        }
        return;
    }
    if mode == "srcmem" {
        let before = CUR.load(Relaxed);
        PEAK.store(before, Relaxed);
        let src = BytecodeSource::new(&xbc).unwrap();
        println!(
            "BytecodeSource: live {:.1} MB, peak during build {:.1} MB, {} items",
            (CUR.load(Relaxed) - before) as f64 / MB,
            (PEAK.load(Relaxed) - before) as f64 / MB,
            src.stream().num_items()
        );
        return;
    }
    if mode == "solve" {
        let json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&args[4]).unwrap()).unwrap();
        let names: BTreeMap<String, String> = json
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
            .collect();
        let vars = xark_ir::function_decode::decode_input_vars(&xbc).unwrap();
        let ids = xark_prover::resolve_input_ids(&vars, &names).unwrap();
        for _ in 0..2 {
            let t = Instant::now();
            xark_ir::function_decode::stream_solve(&xbc, &ids).unwrap();
            let solve = t.elapsed().as_secs_f64();
            let t = Instant::now();
            xark_ir::function_decode::stream_solve_verify(&xbc, &ids).unwrap();
            println!(
                "stream_solve {solve:.2}s  solve+check+analyze {:.2}s",
                t.elapsed().as_secs_f64()
            );
        }
        return;
    }
    if mode == "warm" {
        // Key already resident (prove-many server): prove time only, every prover,
        // a line a proof: `warm <xbc> <pk> <inputs> [proofs] [warmups]`.
        let runs: usize = args
            .get(5)
            .map_or(30, |n| n.parse().expect("a number of proofs"));
        let warmups: usize = args
            .get(6)
            .map_or(3, |n| n.parse().expect("a number of warmups"));
        assert!(runs > 0, "warm mode requires at least one measured proof");
        let assign = solve(&xbc, &args[4]);
        let pk = xark_backend::Groth16Keys::read_proving_key(&pk_path).unwrap();
        let src = BytecodeSource::new(&xbc).unwrap();
        let z = src.layout().assignment_from_map(&assign);
        let public = &z[1..src.layout().num_instance()];
        assert_eq!(
            pk.vk.gamma_abc_g1.len(),
            public.len() + 1,
            "verifying key and circuit have different public input counts"
        );
        let changed_public_hash = std::env::var_os("BENCH_PUBLIC_STATEMENTS")
            .or_else(|| std::env::var_os("BENCH_ESCROW_STATEMENTS"))
            .map(|directory| check_statements(std::path::Path::new(&directory), public));
        let vk: ark_groth16::VerifyingKey<Bn254> = checked_arkworks_encoding(&pk.vk);
        let prepared_vk = Groth16::<Bn254>::process_vk(&vk).expect("prepare Arkworks key");
        let mut cfg = ProverConfig::default();
        if let Some(value) = std::env::var_os("BENCH_MERGE_BELOW") {
            cfg.merge_below = value
                .to_str()
                .and_then(|value| value.parse().ok())
                .expect("BENCH_MERGE_BELOW must be a nonnegative integer");
        }
        let profile = std::env::var_os("BENCH_RESIDENT_PROFILE").is_some();
        if profile {
            assert!(!tracking(), "set BENCH_TIME=1 for resident task timing");
            assert_eq!(std::env::var("BENCH_WARM_BACKEND").as_deref(), Ok("cpu"));
            assert!(
                pk.a_query.len() >= cfg.merge_below,
                "resident task timing uses split MSMs"
            );
            assert!(
                changed_public_hash.is_some(),
                "resident task timing needs the SDK statements"
            );
        }
        let mut profiles = Vec::new();
        eprintln!(
            "resident CPU: a_query_len={} merge_below={} merged={}",
            pk.a_query.len(),
            cfg.merge_below,
            pk.a_query.len() < cfg.merge_below
        );
        #[cfg(feature = "msm-g2-shifted-bench")]
        let shifted = match std::env::var("BENCH_G2_SHIFTED").as_deref() {
            Ok("1") => {
                assert_eq!(std::env::var("BENCH_WARM_BACKEND").as_deref(), Ok("cpu"));
                assert!(
                    pk.a_query.len() >= cfg.merge_below,
                    "shifted B2 uses split MSMs"
                );
                assert!(
                    changed_public_hash.is_some(),
                    "shifted B2 needs fixture statements"
                );
                let start = Instant::now();
                let table = xark_groth16::msm::shifted::ShiftedBases::new(&pk.b_g2_query)
                    .expect("prepare shifted B2 table");
                eprintln!(
                    "bench g2 shifted: 1 setup_ns={} table_payload_bytes={}",
                    start.elapsed().as_nanos(),
                    table.payload_bytes(),
                );
                Some(table)
            }
            Ok("0") | Err(std::env::VarError::NotPresent) => None,
            _ => panic!("BENCH_G2_SHIFTED must be 0 or 1"),
        };
        #[cfg(feature = "msm-g2-shifted-bench")]
        let cached_gls = match std::env::var("BENCH_G2_CACHED_GLS").as_deref() {
            Ok("1") => {
                assert_eq!(std::env::var("BENCH_WARM_BACKEND").as_deref(), Ok("cpu"));
                assert!(
                    shifted.is_none(),
                    "cached GLS and shifted B2 are separate modes"
                );
                assert!(
                    pk.a_query.len() >= cfg.merge_below,
                    "cached GLS B2 uses split MSMs"
                );
                assert!(
                    changed_public_hash.is_some(),
                    "cached GLS B2 needs fixture statements"
                );
                let started = Instant::now();
                let table = query_msm::cached_gls_b2::ResidentCachedGls::new(
                    &pk.b_g2_query,
                    signed_subgroup,
                )
                .expect("validate and prepare cached GLS B2 table");
                eprintln!(
                    "bench g2 cached GLS: 1 rounding=fixed-limb subgroup_points={} setup_ns={} table_payload_bytes={}",
                    pk.b_g2_query.len(),
                    started.elapsed().as_nanos(),
                    table.payload_bytes()
                );
                eprintln!("bench g2 signed subgroup: {}", u8::from(signed_subgroup));
                Some(table)
            }
            Ok("0") | Err(std::env::VarError::NotPresent) => None,
            _ => panic!("BENCH_G2_CACHED_GLS must be 0 or 1"),
        };
        #[cfg(feature = "msm-g2-shifted-bench")]
        let cached_gls_msm = cached_gls.as_ref().map(|table| {
            move |bases: &[ark_bn254::G2Affine], scalars: &[xark_groth16::msm::Scalar]| {
                table.msm(bases, scalars)
            }
        });
        #[cfg(feature = "msm-g2-shifted-bench")]
        let use_probe = profile || shifted.is_some() || cached_gls_msm.is_some() || share_b_scalars;
        #[cfg(not(feature = "msm-g2-shifted-bench"))]
        let use_probe = profile || share_b_scalars;
        #[cfg(feature = "msm-b-shared-bench")]
        {
            if share_b_scalars {
                assert_eq!(std::env::var("BENCH_WARM_BACKEND").as_deref(), Ok("cpu"));
                assert!(
                    pk.a_query.len() >= cfg.merge_below,
                    "shared B scalars require split proving"
                );
                assert!(
                    cfg.msm_chunk >= pk.b_g2_query.len(),
                    "shared B scalars require unchunked queries"
                );
            }
            eprintln!("bench shared B scalars: {}", u8::from(share_b_scalars));
        }
        let mut provers: Vec<Box<dyn Prover + '_>> = Vec::new();
        match std::env::var("BENCH_WARM_BACKEND").as_deref() {
            Ok("both") | Err(std::env::VarError::NotPresent) => {
                provers.push(Box::new(Arkworks::new(&pk)));
            }
            Ok("cpu") => {}
            _ => panic!("BENCH_WARM_BACKEND must be both or cpu"),
        }
        let cpu = Cpu::new(xark_groth16::InMemoryPk::new(&pk), cfg);
        if use_probe {
            provers.push(Box::new(ProfiledCpu {
                cpu,
                profiles: profile.then_some(&mut profiles),
                #[cfg(feature = "msm-g2-shifted-bench")]
                shifted: shifted.as_ref(),
                #[cfg(feature = "msm-g2-shifted-bench")]
                cached_gls: cached_gls_msm
                    .as_ref()
                    .map(|msm| msm as &xark_groth16::prover::BenchResidentB2<'_>),
                #[cfg(feature = "msm-b-shared-bench")]
                share_b_scalars,
            }));
        } else {
            provers.push(Box::new(cpu));
        }
        // Each prover's proofs back to back, as a prove-many server makes them
        // (and as gnark's benchmark times its own), not one interleaved with the
        // other's: a millisecond proof right after an arkworks one measures the
        // arkworks proof's cache and pool aftermath too.
        let mut rng = rand::thread_rng();
        let row_check = std::env::var_os("BENCH_CHECK_ROWS");
        let expanded_check = row_check.as_deref() == Some(std::ffi::OsStr::new("expanded"));
        let check_src = expanded_check.then(|| {
            let mut expanded = BytecodeSource::new(&xbc).expect("read rows to check");
            expanded.set_compiled(false);
            expanded
        });
        let check_rows = row_check.is_some();
        let check_witness = || {
            if check_rows {
                assert!(
                    xark_groth16::r1cs::first_unsatisfied(check_src.as_ref().unwrap_or(&src), &z)
                        .is_none(),
                    "the supplied witness fails a constraint"
                );
            }
        };
        eprintln!("resident includes row checks: {check_rows}");
        if check_rows {
            eprintln!(
                "witness row checker: {}",
                if expanded_check {
                    "expanded"
                } else {
                    "compiled"
                }
            );
        }
        let batches: Vec<_> = provers
            .iter_mut()
            .map(|p| {
                let warmup_proofs = (0..warmups)
                    .map(|_| {
                        check_witness();
                        prove_with_rng(&mut **p, &src, &z, &mut rng).expect("warm up prover")
                    })
                    .collect::<Vec<_>>();
                let samples = (0..runs)
                    .map(|_| {
                        let t = Instant::now();
                        check_witness();
                        let checked_in = check_rows.then(|| t.elapsed());
                        let proof =
                            prove_with_rng(&mut **p, &src, &z, &mut rng).expect("measure proof");
                        (t.elapsed().as_secs_f64(), proof, checked_in)
                    })
                    .collect::<Vec<_>>();
                (warmup_proofs, samples)
            })
            .collect();
        // Verify after all timed batches so pairings cannot affect the samples.
        // Reject the batch before printing any timings if any proof fails.
        for (prover, (warmup_proofs, batch)) in provers.iter().zip(&batches) {
            let proofs = warmup_proofs
                .iter()
                .chain(batch.iter().map(|(_, proof, _)| proof));
            for (index, proof) in proofs.enumerate() {
                let ark_proof: ark_groth16::Proof<Bn254> = checked_arkworks_encoding(proof);
                let ark_valid =
                    Groth16::<Bn254>::verify_with_processed_vk(&prepared_vk, public, &ark_proof)
                        .expect("verify measured proof with Arkworks");
                let xark_valid = xark_groth16::verify(&pk.vk, public, proof)
                    .expect("verify measured proof with Xark");
                assert!(
                    ark_valid && xark_valid,
                    "{} proof {} failed verification (Arkworks={ark_valid}, Xark={xark_valid})",
                    prover.name(),
                    index + 1
                );
                if let Some(changed) = changed_public_hash.as_ref().filter(|_| index == warmups) {
                    let changed = std::slice::from_ref(changed);
                    let ark_accepts = Groth16::<Bn254>::verify_with_processed_vk(
                        &prepared_vk,
                        changed,
                        &ark_proof,
                    )
                    .expect("verify changed statement with Arkworks");
                    let xark_accepts = xark_groth16::verify(&pk.vk, changed, proof)
                        .expect("verify changed statement with Xark");
                    assert!(
                        !ark_accepts && !xark_accepts,
                        "{} proof accepted under changed statement (Arkworks={ark_accepts}, Xark={xark_accepts})",
                        prover.name()
                    );
                }
            }
            eprintln!(
                "warm proofs verified by Arkworks and Xark: {} warmups={} measured={}",
                prover.name(),
                warmup_proofs.len(),
                batch.len()
            );
        }
        if changed_public_hash.is_some() {
            println!("changed statement rejected by Arkworks and Xark for each backend");
        }
        for i in 0..runs {
            let line: Vec<String> = provers
                .iter()
                .zip(&batches)
                .map(|(p, (_, batch))| format!("{} {:.6}s", p.name(), batch[i].0))
                .collect();
            println!("warm prove: {}", line.join("  "));
        }
        for (prover, (_, batch)) in provers.iter().zip(&batches) {
            for (_, _, checked_in) in batch {
                if let Some(elapsed) = checked_in {
                    println!(
                        "warm row check: {} {} ns",
                        prover.name(),
                        elapsed.as_nanos()
                    );
                }
            }
        }
        drop(provers);
        if profile {
            assert_eq!(profiles.len(), warmups + runs);
            for (sample, spans) in profiles.iter().skip(warmups).enumerate() {
                assert!(!spans.is_empty(), "split resident timing produced no spans");
                for span in spans {
                    println!(
                        "resident task: {} {} {} {}",
                        sample + 1,
                        span.phase,
                        span.offset.as_nanos(),
                        span.elapsed.as_nanos()
                    );
                }
            }
        }
        return;
    }
    if mode == "phases" {
        // `phases <xbc> <pk> <inputs> [proofs]`: the streaming prover alone, key
        // resident, a phase breakdown a proof (CHECK=1 adds the self-check).
        let runs: u64 = args.get(5).map_or(5, |n| n.parse().unwrap());
        let assign = solve(&xbc, &args[4]);
        let pk = xark_backend::Groth16Keys::read_proving_key(&pk_path).unwrap();
        let src = BytecodeSource::new(&xbc).unwrap();
        let z = src.layout().assignment_from_map(&assign);
        let cfg = ProverConfig {
            self_check: std::env::var("CHECK").is_ok(),
            ..ProverConfig::default()
        };
        let mut totals = Vec::new();
        for i in 0..runs {
            let mut rng = ChaCha20Rng::seed_from_u64(i);
            use ark_ff::UniformRand;
            let (r, s) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
            let mut ph = Phases::new();
            let t = Instant::now();
            xark_groth16::prove_with_randomness(
                &src,
                &z,
                &mut xark_groth16::InMemoryPk::new(&pk),
                r,
                s,
                &cfg,
                &mut ph,
            )
            .unwrap();
            totals.push(t.elapsed().as_secs_f64() * 1e3);
            if i + 1 == runs {
                ph.print("phases (last proof)");
            }
        }
        totals.sort_by(f64::total_cmp);
        println!("median_ms={:.2}", totals[totals.len() / 2]);
        return;
    }
    if mode == "proof-hex" {
        // Cross-runtime oracle: arkworks (CLI-equivalent minimized circuit) vs the
        // streaming prover from bytecode, same seed → same (r, s).
        let seed: u64 = args[5].parse().unwrap();
        let assign = solve(&xbc, &args[4]);
        let pk = xark_backend::Groth16Keys::read_proving_key(&pk_path).unwrap();
        // Key the arkworks side to whichever form this key was generated for.
        let red = reduced(&xbc);
        let circ = if pk.a_query.len() == red.variables.len() + 1 {
            XarkCircuit::for_proving_preminimized(red, assign.clone())
        } else {
            XarkCircuit::for_proving(red, assign.clone())
        };
        let ark_pk: ark_groth16::ProvingKey<Bn254> = convert(&pk);
        let ark = Groth16::<Bn254>::prove(
            &ark_pk,
            ArkCircuit::of(&circ),
            &mut ChaCha20Rng::seed_from_u64(seed),
        )
        .unwrap();
        let src = BytecodeSource::new(&xbc).unwrap();
        let z = src.layout().assignment_from_map(&assign);
        let ours = xark_groth16::prove(
            &src,
            &z,
            &mut SerializedPk::open(&pk_path).unwrap(),
            &mut ChaCha20Rng::seed_from_u64(seed),
            &ProverConfig::default(),
        )
        .unwrap();
        fn hex(p: &impl CanonicalSerialize) -> String {
            let mut b = Vec::new();
            p.serialize_compressed(&mut b).unwrap();
            b.iter().map(|x| format!("{x:02x}")).collect::<String>()
        }
        println!("arkworks  {}", hex(&ark));
        println!("streaming {}", hex(&ours));
        return;
    }

    let inputs = &args[4];
    let use_reduced = args.iter().any(|a| a == "--reduced");
    let source = arg_val(&args, "--source").unwrap_or_else(|| "min".into());
    let mut ph = Phases::new();

    let assign = solve(&xbc, inputs);
    ph.mark("solve_witness");

    match mode {
        "ark" => {
            let prog = reduced(&xbc);
            let circ = if use_reduced {
                XarkCircuit::for_proving_preminimized(prog, assign)
            } else {
                XarkCircuit::for_proving(prog, assign)
            };
            let public = circ.public_inputs();
            ph.mark("expand+minimize");
            let pk = xark_backend::Groth16Keys::read_proving_key(&pk_path).unwrap();
            ph.mark("load_pk");
            let ark_pk: ark_groth16::ProvingKey<Bn254> = convert(&pk);
            let _ = public;
            let proof = Groth16::<Bn254>::prove(
                &ark_pk,
                ArkCircuit::of(&circ),
                &mut ChaCha20Rng::seed_from_u64(1),
            )
            .unwrap();
            ph.mark("groth16_prove");
            drop(pk);
            let _ = proof;
            ph.print(if use_reduced {
                "arkworks (reduced key)"
            } else {
                "arkworks (minimized key)"
            });
        }
        "stream" => {
            let mut cfg = ProverConfig::default();
            if let Some(t) = arg_val(&args, "--tile") {
                cfg.fft = FftConfig {
                    tile: t.parse().unwrap(),
                    ..cfg.fft
                };
            }
            if let Some(c) = arg_val(&args, "--chunk") {
                cfg.msm_chunk = c.parse().unwrap();
            }
            if let Some(d) = arg_val(&args, "--spill") {
                cfg.spill_dir = Some(d.into());
            }
            let mut spk = SerializedPk::open(&pk_path).unwrap();
            let run = |src: &dyn ConstraintSource, ph: &mut Phases, spk: &mut SerializedPk<_>| {
                let z = src.layout().assignment_from_map(&assign);
                ph.mark("witness_vector");
                let mut rng = ChaCha20Rng::seed_from_u64(1);
                use ark_ff::UniformRand;
                let (r, s) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
                xark_groth16::prove_with_randomness(src, &z, spk, r, s, &cfg, ph).unwrap()
            };
            if source == "xbc" {
                let src = BytecodeSource::new(&xbc).unwrap();
                ph.mark("bytecode_source");
                drop(xbc);
                run(&src, &mut ph, &mut spk);
                ph.print("streaming (bytecode source, reduced key)");
            } else {
                let prog = XarkCircuit::for_setup(reduced(&xbc)).prog().clone();
                ph.mark("expand+minimize");
                let src = ProgramSource::new(&prog);
                run(&src, &mut ph, &mut spk);
                ph.print("streaming (minimized program, existing key)");
            }
        }
        m => panic!("unknown mode {m}"),
    }
}
