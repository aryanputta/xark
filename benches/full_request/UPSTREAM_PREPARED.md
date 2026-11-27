# Upstream versus prepared request replay

`upstream_prepared_replay.py` compares the Xark 0.5 CPU prover with the prepared satisfaction-only path on the same checked synthetic Privacy Rings escrow and withdrawal fixtures. The baseline source must be `72236af142115e48101ece4ecacdf8ae3876d7d2`; the candidate source must be `c2a3922480b1d60b285f065c941bd1dbf84b8cdd`. Those branches add benchmark wrappers to the unchanged upstream and experimental candidate implementations. The candidate includes other prepared-prover changes, so this comparison measures the complete path. Use the same-binary prepared-solver replay to isolate the row-check change.

The runner requires a 28-file SHA256 fixture manifest, clean source checkouts, distinct binary hashes, exact mode receipts, and Xark plus Arkworks proof-verification receipts. Altered and cross-request statements must be rejected. It gates measurements on same-binary controls with at most 2% median and 10% p95 drift. It keeps all raw timings, setup duration, peak process RSS, and source and binary fingerprints.

Build the two examples with `cargo build --locked --profile ci`: upstream `-p xark-groth16 --example bench_verified_warm`; prepared `-p xark-groth16 --features msm-b-shared-bench,msm-g2-shifted-bench,msm-g2-endpoint-bench --example bench_prove`. Run `python3 -m unittest -v test_upstream_prepared_replay.py` in this directory. The required private fixtures are distributed separately; do not commit witness inputs.

On an idle Linux host, pin one logical CPU per physical core. A one-core run is useful as secondary evidence; reproduce on two physical cores before a production speed claim. From this directory:

```sh
taskset -c 0,2 python3 upstream_prepared_replay.py \
  /path/upstream/target/ci/examples/bench_verified_warm \
  /path/prepared/target/ci/examples/bench_prove \
  /path/fixtures /path/fixtures/fixtures.sha256 /path/new-output \
  --upstream-source-dir /path/upstream --prepared-source-dir /path/prepared \
  --workers 2 --concurrency 1 --requests 25 --blocks 4
```

The runner measures 100 proofs per arm and circuit only after all control pairs pass. It is not an equivalent Gnark comparison and does not establish witness-confidentiality or constant-time guarantees.
