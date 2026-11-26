# Privacy Rings B2 ablation

This branch combines three opt-in experimental factors in one exact executable. Keep Linux runs on the same two allowed CPUs throughout a pass. Use two SMT siblings to reproduce the historical CPU budget, then run a separate distinct-core replay. Use an idle host and record the guest topology and CPU quota.

```sh
cargo build --locked --release -p xark-groth16 \
  --features msm-g2-endpoint-bench,msm-g2-shifted-bench --example bench_prove
taskset -c "$B2_CPU_LIST" python3 benches/g2/ablation.py \
  --binary target/release/examples/bench_prove --source . \
  --runner "$PINNED_COMPETITIVE_RUNNER" --fixtures "$PINNED_OFFLINE_FIXTURE_DIR" \
  --output "$B2_RESULTS"
```

Use the competitive runner at commit `225735659def0780b268e481794a24d1e3196eea` in the fork's `review/competitive-benchmark-harness-v05` branch. The ablation checks both the runner digest and its fixture manifest before measuring. Supply the extracted test archive with the pinned escrow and withdrawal keys and statements. Use a new output directory.

The arm number is the sum of enabled factors. Add 1 for trimmed inversion endpoints, 2 for the sparse G2 map and 4 for shifted bases. Each block visits all eight arms. Blocks balance execution positions and adjacent arm pairs. The default eight blocks use 13 measured proofs plus three warmups per arm and workload. The runner records setup before warming, timed resident proving with explicit row checks, B2 and peer spans, and independent Arkworks and Xark verification outside the timed interval. It also tests an altered public statement in every arm. Fixture solving happens before the timed interval.

The kernel uses the same preset of two 128-bit shifted components in every shifted arm. Each component fits Xark's 128-bit no-GLV threshold, so the sparse map should have no B2 work to reduce when the shifted table is active. Arms 4 and 6, and 5 and 7, are useful controls for this interaction. Report the table's break-even relative to the same arithmetic settings with shifting off. A result needs positive recurring proof savings and a block interval above zero.

The `--diagnostic` switch is for a local correctness and instrumentation check. A short smoke can use `--blocks 1 --samples 1 --warmups 1`. It always reports ineligible performance. A manifest error, unsuccessful proof, missing timing receipt, or strict host gate failure aborts the run.
