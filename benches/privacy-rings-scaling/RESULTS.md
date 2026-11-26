# Privacy Rings CPU proof receipts

These runs used the pinned escrow and withdrawal circuits on an Intel Core i9-9880H at 2.30 GHz, 16 logical CPUs, macOS 26.5.1, and Rust 1.94.1. Rayon workers were unpinned. The tests used release builds, compiled witness row checks, and split CPU MSMs.

## Shared resident scheduling

Commit `e7b54f3` compares three schedules at a fixed two-thread proving budget. Each schedule ran three 40-proof batches for each fixture. Xark and Arkworks verified all 720 measured proofs and rejected 30 changed statements. The one-minute load across arm boundaries was 15.23–27.35.

| Shared-key lanes vs. serial proofs with two Rayon threads | Escrow | Withdrawal |
| --- | ---: | ---: |
| Verified batch makespan | 8.0–11.2% lower | 4.6–17.2% higher |
| Individual proof median | 77–90% higher | 108–118% higher |
| Queue-inclusive completion p95 | 7.1–9.7% lower | 6.2–18.6% higher |

## G2 batch inversion

Commit `6c8ed90` batch-inverts the norms of the G2 affine addition denominators in the base field. Each fixture ran 30 proofs per arm with baseline-first and candidate-first orderings. Both verifiers accepted all 240 timed proofs and rejected eight changed statements. Arkworks also matched all 192 timed query sums. Six fixed-randomness fixture proofs matched byte-for-byte between both Xark builds and Arkworks. The locked release build, 48 Groth16 release tests, and Clippy with warnings denied passed.

| Candidate vs. baseline | Escrow | Withdrawal |
| --- | ---: | ---: |
| Individual proof median | 3.14–4.51% lower | 2.10–2.53% lower |
| Verified batch makespan | 3.71–9.32% lower | 1.31–2.38% lower |
| Individual proof p95 | 6.53–21.78% lower | 0.96–10.16% higher |
| Peak process RSS | −2.74% to +2.42% | 3.20–4.69% higher |

One-minute load across the arm boundaries was 20.42–32.66. The tables show the range of changes from paired arms on this host. The 30-proof batches give limited resolution for p95.

## Withdrawal follow-up

The same binaries ran two reversed pairs with 60 fresh proofs per arm and four warmups. Both verifiers accepted all 240 proofs and rejected four changed statements. The original withdrawal median gain did not reproduce. The candidate's p95 was higher in both the first run and the follow-up.

| Candidate vs. baseline | Baseline first | Candidate first |
| --- | ---: | ---: |
| Individual proof median | 3.37% higher | 9.98% higher |
| Individual proof p95 | 17.69% higher | 34.34% higher |
| Verified batch makespan | 5.47% higher | 11.37% higher |
| Peak process RSS | 0.04% higher | 6.87% higher |

One-minute load across the follow-up arm boundaries was 12.23–60.08. Escrow has two same-host measurements per build from the original pairs. Withdrawal needs a controlled-host run before drawing a performance conclusion.

## Replay

Use the [fixture setup and scheduling instructions](README.md). Check the fixture files against the [SHA-256 manifest](fixture-sha256.txt). The manifest contains file fingerprints. Build `e7b54f3` and `6c8ed90` in separate checkouts or target directories.

```sh
cargo build --locked --release -p xark-groth16 --example bench_prove
cargo test --locked --release -p xark-groth16
cargo clippy --locked --release -p xark-groth16 --all-targets -- -D warnings
```

Use the following command once per binary and fixture, reversing binary order for the second pair. Set `binary` to the release example and `fixture` to the fixture directory.

```sh
BENCH_TIME=1 BENCH_WARM_BACKEND=cpu BENCH_CHECK_ROWS=1 BENCH_MERGE_BELOW=0 \
  RAYON_NUM_THREADS=2 BENCH_PUBLIC_STATEMENTS="$fixture" \
  "$binary" warm "$fixture/circuit.xbc" "$fixture/test-key.bin" "$fixture/inputs.json" 30 4
```

Run with 60 samples for the withdrawal follow-up. The [arm measurements](results.csv) list individual proof p50 and p95 in milliseconds and verified batch time in seconds. Batch time includes startup, key loading, solving, warmups, proving, and verification. Each row in the [sample data](samples.jsonl) contains the measurements from a proof worker or query. Proof and completion durations are in nanoseconds, converted from the precision emitted by the example. Completion clocks are local to each process, with a common batch start for both shared proof lanes.

| Release example | SHA-256 |
| --- | --- |
| `e7b54f3` baseline | `093ca541802026f7ba52def35d07bc5e6079fbf8051f2c06e59cff1729890315` |
| `6c8ed90` candidate | `879118e529626e10322d0fab6bb6812b781b80bd8ca7ba1ce79a511f481be70c` |
