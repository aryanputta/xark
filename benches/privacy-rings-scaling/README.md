# Privacy Rings resident proof scaling

See the [CPU proof receipts](RESULTS.md) for measured results, sample data, and fixture hashes.

Run the same escrow and withdrawal inputs with one Rayon worker, two Rayon workers in one process, and two concurrent processes with one worker each. Each process loads its key and witness once. The runner fixes CPU-only split MSMs and compiled witness row checks. The example verifies every measured proof with Xark and Arkworks and checks one changed public statement per process.

Build the release example on Linux or macOS and run the benchmark with Python 3.11 or newer.

```sh
cargo build --locked --release -p xark-groth16 --example bench_prove
python3 benches/privacy-rings-scaling/run.py \
  target/release/examples/bench_prove /path/to/pinned-fixtures /path/to/new-output
```

The fixture root needs `escrow` and `withdrawal` directories. Each contains the real Privacy Rings `circuit.xbc`, its test-only `test-key.bin`, `inputs.json`, `public.json`, and `public-changed.json`. Use the same fixtures and `setup-reduced` key generation as the [matched Gnark benchmark](../privacy-rings-gnark/README.md). Verify them against the pinned fixture digests before running. The runner records SHA-256 for the inputs and executable and checks it again before writing the summary.

Each configuration measures 20 proofs by default. Use an even `--samples` to raise the count. Every arm runs four total warmup proofs, so the two-process arm warms each process twice. Each configuration occupies each run position once per fixture. The runner leaves CPU placement to the host scheduler.

- `p50_ms` and `p95_ms` measure individual checked proofs. They exclude queuing, warmups, and the verification pass. The two-process arm pools samples from both processes.
- `verified_makespan_s` measures from the first worker launch to the last worker exit. It includes key loading, witness solving, warmups, proving, and verification. `verified_proofs_s` divides measured proof count by that time. Verification can overlap proving in the other process.
- `worker_peak_rss_sum_mib` sums each process's own peak RSS. In the parallel arm it bounds aggregate worker RSS from above because individual peaks can occur at different times.
- Per-worker logs retain the samples and verification markers. The CSV summary is written after all arms pass and the fingerprints still match.

Pass `--shared-resident --samples 100` to compare three schedules at a fixed two-thread proving budget. The two original two-thread arms run alongside two concurrent proof lanes in one process. Each lane uses a private one-thread Rayon pool and borrows the same loaded key, circuit, and solved witness. Every measured proof is row-checked and verified with both verifiers. Both lanes check the changed statement.

In this comparison, `warm_batch_ms` measures from the start of a preloaded batch to the last proof and `warm_batch_completion_p95_ms` measures the 95th-percentile completion from that same start. These clocks include the time each proof waits for a lane and stop before verification. The two-process arm has independent clocks and its batch completion columns are empty. Compare all three arms using verified makespan. The shared process reports one process peak RSS, and summing the separate process peaks gives an upper bound on their aggregate RSS.

To compare two release builds, pass the candidate as the first argument and the baseline as `--against`. The runner uses two Rayon threads for one proof at a time, then reverses binary order for the second pair. Both binaries are fingerprinted before and after the run. Use the same binary for both arguments to measure host variation before interpreting an A/B.

```sh
python3 benches/privacy-rings-scaling/run.py \
  /path/to/candidate/bench_prove /path/to/pinned-fixtures /path/to/new-output \
  --against /path/to/baseline/bench_prove --fixture withdrawal --samples 60
```

On Linux, run under `taskset` with two available CPU IDs to give each arm the same affinity. The host receipt records that CPU set. Per-arm summaries also record total user and system CPU seconds and voluntary and involuntary context switches from the worker processes. These counters cover process startup through verification. Compare them with wall time and load readings when diagnosing timing variation.
