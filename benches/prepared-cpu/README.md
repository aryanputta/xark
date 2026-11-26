# Matched resident Privacy Rings replay

This benchmark-only branch adds a verified resident request example to the exact
Xark 0.5 upstream code. `paired.py` alternates that baseline with the opt-in
`PreparedCpuProver` candidate. It first needs a same-binary control with
`--control`; a passing control is required before treating a candidate difference
as performance evidence. The script always records `performance_eligible: false`
because host stability and equivalence require human review.

The pinned candidate is `d6bb5ce8a39384d5ed881f046b654cf20c30e866` on
`feat/prepared-cpu-prover`. To build it, copy
`check_prepared_cpu_requests.rs` into that checkout's
`crates/groth16/examples/` directory, then run:

```sh
cargo build --locked --profile ci -p xark-groth16 \
  --features msm-b-shared-bench,msm-g2-shifted-bench,msm-g2-endpoint-bench \
  --example check_prepared_cpu_requests
```

Build the upstream arm at `a12b9a9` with:

```sh
cargo build --locked --profile ci -p xark-groth16 --example bench_verified_warm
```

The fixture root must have `reference/{escrow,withdrawal}/circuit.xbc`,
`test-key.bin`, and four request directories per circuit. Use the 28-file
synthetic Privacy Rings fixture manifest from the sprint evidence, and verify
its SHA-256 is
`0436bedbae33912331d7306b9c1406956be5695d43f85f5c750f19bbb9bcce41`.
The fixtures are intentionally not committed here.

```sh
python3 -m unittest discover -s benches/prepared-cpu -p 'test_*.py' -v
python3 benches/prepared-cpu/paired.py \
  /path/to/upstream/bench_verified_warm \
  /path/to/candidate/check_prepared_cpu_requests \
  /path/to/fixture \
  /path/to/fixture/fixtures.sha256 \
  /path/to/control-output --control
python3 benches/prepared-cpu/paired.py \
  /path/to/upstream/bench_verified_warm \
  /path/to/candidate/check_prepared_cpu_requests \
  /path/to/fixture \
  /path/to/fixture/fixtures.sha256 \
  /path/to/direct-output
```

Both examples verify valid proofs with Xark and Arkworks and require both
verifiers to reject altered and cross-request public statements. The timer
includes fixture read, witness work, proof construction, positive Xark
verification and serialization. Independent Arkworks verification and negative
statement tests are outside the timer. Setup is recorded separately. Two Rayon
workers are fixed in this initial replay, so hardware topology must be reported.

The 2026-11-26 Intel Mac same-binary control verified 128 measured proofs but
failed the 3% stability gate: escrow block drift reached 4.88%. Those timings
cannot establish a candidate speedup. Raw receipts remain in the local sprint
record under `evidence/benchmark-lab/2026-11-26-matched-request-boundary/`.
