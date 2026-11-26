# Privacy Rings resident proof scaling

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
