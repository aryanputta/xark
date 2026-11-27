# Prepared quadratic coefficient cleanup

The prepared IR solver retains witness-derived BN254 `(a, b)` row coefficients in `OnceLock` entries. Before this experiment, accepted requests dropped the entries without explicit clearing; rejected constraints cleared them. [Branch `fix/prepared-quadratic-wipe`](https://github.com/aryanputta/xark/tree/fix/prepared-quadratic-wipe) at `4595d765a8338f276bf8815d2e0f9d7ede02ebbf`, based on prepared/shared-B integration `916d438`, puts the vector behind a drop guard that clears initialized BN254 entries on normal return and unwinding. The existing rejection-path wipe is subsumed. This is a request-local cleanup change, not a complete witness confidentiality or constant-time claim. Other field variants and temporary witness copies remain outside its scope. Process aborts do not run Rust destructors.

## Correctness

- Offline locked IR library and reduced-soundness suites: 40 and 4 tests passed, including the new coefficient-clearing unit test.
- Prepared typed Groth16 request regression passed: full proof verification, concurrent requests, altered-statement rejection, and malformed/non-subgroup key rejection.
- Strict Clippy for `xark-ir` and `xark-prover` all targets, and `cargo fmt --all --check`, passed.
- The diagnostic request runner, identical by SHA256 `8180e9af0885c9b78897f3df0823d7f940c69d71ff34b45d94caf6b3d2149572` in both arms, generated 32 baseline and 32 candidate measured synthetic Privacy Rings proofs. All 64 passed independent Arkworks verification and all 64 altered statements were rejected. The fixture manifest SHA256 was `0436bedbae33912331d7306b9c1406956be5695d43f85f5c750f19bbb9bcce41`.
- The complete offline locked `xark-ir` and `xark-prover` suites passed, including 11 adversarial witness-search tests and all 13 prover unit tests. Two explicitly ignored microbenchmarks were not run.

## Diagnostic performance

The optimized baseline binary SHA256 was `f90cce93ddd2d13e09da5347388c36d3b937cecb9600dac5b80437eead43b4c5`; candidate SHA256 was `f6222e24b6ccef7a625d5210fcb9f397b5b29a95570d142755bd928de11e83c3`. Four alternating blocks per circuit each timed four proofs per arm. The candidate's paired median changes were **3.993% slower for escrow** (two of four blocks faster) and **2.977% slower for withdrawal** (zero of four blocks faster). These are contended-Mac diagnostics, not production latency claims. Raw timings and per-run verification counts are in [report.json](paired-control/report.json); raw request logs are the `paired-control/*stdout` files. The withdrawal direction warrants a stable Linux replay and an isolated wipe-cost profile before accepting this change for the fast path.

## Decision

Keep the focused correctness implementation available for review. Do not integrate it into a fastest-prover branch or claim performance improvement until a qualified host establishes its cost and a narrower cleanup strategy is evaluated. No private witness values were printed by the runner.
