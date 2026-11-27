# Prepared Privacy Rings proof soak

`run_soak.py` runs the existing `bench_prove warm-requests` path with the opt-in
prepared solver, CPU MSM, two Rayon workers by default, and a pinned synthetic
fixture set. It records process exit status, binary and fixture hashes, raw
verification receipts, tracked Rust heap after each request wave, and peak
process RSS. The benchmark validates all decoded proving-key points before
proving and records the validation duration separately; this cost is part of
setup, outside each warm request interval.
`verify_soak.py` checks that all requested proofs and memory waves have receipts,
that altered and cross-request statements were rejected, and that the complete
key-validation marker is present for new runs.

Build from this branch with the locked dependency set:

```sh
cargo build --locked --profile ci -p xark-groth16 \
  --features msm-b-shared-bench,msm-g2-shifted-bench,msm-g2-endpoint-bench \
  --example bench_prove
```

Use the synthetic Privacy Rings fixture directory described in the sprint
evidence. Its `fixtures.sha256` must hash to
`0436bedbae33912331d7306b9c1406956be5695d43f85f5c750f19bbb9bcce41`.
The runner checks the manifest and all 28 listed files before invoking the
binary. The directory contains `reference/{escrow,withdrawal}/circuit.xbc`,
`test-key.bin`, and four request directories per circuit. Do not replace it
with production witnesses.

```sh
python3 benches/prepared-soak/run_soak.py \
  target/ci/examples/bench_prove FIXTURE_DIR RESULT_DIR escrow \
  --requests 1000 --concurrency 4 --threads 2
python3 benches/prepared-soak/run_soak.py \
  target/ci/examples/bench_prove FIXTURE_DIR RESULT_DIR withdrawal \
  --requests 1000 --concurrency 4 --threads 2
python3 benches/prepared-soak/verify_soak.py RESULT_DIR escrow
python3 benches/prepared-soak/verify_soak.py RESULT_DIR withdrawal
```

The runner refuses to overwrite existing circuit results. Results are private
to the local user by default. Archive raw `*.stdout`, `*.stderr`, and
`*-process.json` with the source revision and fixture manifest. The benchmark
generates each witness for its request, verifies every proof with Xark and
Arkworks, and tests altered and cross-request public statements. It does not
validate every proving-key point in the benchmark loader, measure actual
freed-memory erasure, or establish confidentiality against co-resident users.
The fixture and receipt gates use explicit errors, including under Python
optimized mode (`python3 -O`); a tampered receipt and an overwrite were rejected
in that mode. Archived runs made before the full key check are reported with
`proving_key_validated: false`; their proof-verification and memory evidence
remains useful, but the new validator does not relabel them as key-validated.

Do not use this soak's service timings as a performance comparison. For a speed
claim, run balanced baseline and candidate proofs with equivalent verification
settings on a stable host and retain raw samples. The 2026-11-27 1,000-proof
runs per circuit on a contended macOS x86-64 host are correctness and memory
evidence only. They found a flat post-wave tracked live heap and no proof
verification failures; see the archived sprint evidence for raw receipts.
