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

The arm number is the sum of enabled factors. Add 1 for trimmed inversion endpoints, 2 for the sparse G2 map and 4 for the selected precomputation. The default precomputation is `shifted`. Pass `--precompute cached-gls` for a separate eight-arm pass using the four public Frobenius images and fixed-limb scalar recoding. Cached GLS setup includes the decoded B2 subgroup check, construction of the public table and recoder initialization. The JSON report names the selected precomputation and the setting for each arm bit.

For a controlled two-worker comparison, run once with one SMT pair and `--topology siblings`, then with two distinct physical cores and `--topology distinct`. Leave `--threads 2` in both commands. Linux verifies the selected CPUs against its reported core sibling groups and includes those groups in the JSON report. Inside a VM these are the topology groups exposed to the guest.

Each block visits all eight arms. Blocks balance execution positions and adjacent arm pairs. The default eight blocks use 13 measured proofs plus three warmups per arm and workload. The runner records setup before warming, timed resident proving with explicit row checks, B2 and peer spans, and independent Arkworks and Xark verification outside the timed interval. It also tests an altered public statement in every arm. Fixture solving happens before the timed interval.

The shifted kernel uses a preset of two 128-bit components. Cached GLS recodes full-width scalars into four components with at most 64 magnitude bits. It preserves the original magnitude for already-short scalars. In either pass, the scalar classes fit Xark's 128-bit no-GLV threshold when precomputation is on. Arms 4 and 6, and 5 and 7, control for an apparent sparse-map effect under those conditions. The break-even estimate compares against the same arithmetic settings with precomputation off. A supported estimate needs positive recurring proof savings and a block interval above zero.

The `--diagnostic` switch is for a local correctness and instrumentation check. A short smoke can use `--blocks 1 --samples 1 --warmups 1`. It always reports ineligible performance. A manifest error, unsuccessful proof, missing timing receipt, or strict host gate failure aborts the run.

Run a separate `--perf-counters` pass to capture cycles, instructions, cache references, cache misses, branches and branch misses when the Linux host grants access. These counts cover the entire benchmark process including setup, warming and verification. They cannot be interpreted as B2-only counters. The sampler cannot attribute the perf wrapper RSS to the prover.
