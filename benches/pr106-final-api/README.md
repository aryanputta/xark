# PR #106 final API replay

This benchmark-only branch descends from the final PR #106 implementation at
`98ef685895a9c594938ae6528e8e57bfaf637734`. The candidate example invokes
`PreparedCpuProver::prove` without any library patch. The upstream arm is the
benchmark-only `bench/upstream-api-equivalent` wrapper at
`d126d3cb2a306e7c53d9fc7638dc7860ce086b30`, descended from the current
Xark 0.5 upstream head `03a7f519d28df6718f7ce6dda41f1e57e5ea55db`.

Both timed request intervals start before reading `inputs.json` and end after
witness solving, row checking, proof construction, positive Xark self-check,
and canonical proof/public serialization. The candidate uses its public
`PreparedCpuProver::prove` method; the upstream wrapper performs the equivalent
ordinary CPU steps directly. Independent positive and negative verification with
Xark and Arkworks is outside the timed interval. Both arms load the same XBC,
key, and four distinct synthetic Privacy Rings requests per circuit. The
synthetic requests exercise real Privacy Rings circuits and produce real,
verified proofs. The fixture manifest SHA-256 is
`0436bedbae33912331d7306b9c1406956be5695d43f85f5c750f19bbb9bcce41`.
The fixture archive and raw receipts must accompany any published speed claim.

Build each arm in its own clean worktree, with the same profile and target CPU:

```sh
CARGO_HOME=/Users/srini/.cache/xark-v05-cargo-offline cargo build --locked --offline --profile ci -p xark-groth16 --example bench_verified_warm
CARGO_HOME=/Users/srini/.cache/xark-v05-cargo-offline cargo build --locked --offline --profile ci -p xark-groth16 --example bench_prepared_api
```

First run the smoke with `--smoke`. Then run without it on a pinned Linux host
with exactly two logical CPUs from distinct physical cores visible to the
process. The script makes 32 verified proofs in each of two same-binary control
runs per arm and circuit, then requires p50 drift at most 2% and p95 drift at
most 10%. If the controls or topology gate fail, it stops before comparing
arms. A full eligible replay uses four alternating blocks of 25 requests per
arm and circuit. It reports preparation time, warm p50/p95, peak process RSS,
and estimated requests to amortize extra preparation cost. The estimate uses
median setup and p50 service time and is only emitted when eligible.

```sh
python3 -m unittest discover -s benches/pr106-final-api -p 'test_*.py' -v
python3 benches/pr106-final-api/replay.py \
  /path/to/upstream/target/ci/examples/bench_verified_warm \
  /path/to/candidate/target/ci/examples/bench_prepared_api \
  /path/to/fixtures /path/to/fixtures/fixtures.sha256 \
  /path/to/new-output --upstream-source /path/to/upstream \
  --prepared-source /path/to/candidate --smoke
```

The source and binary hashes, host topology, raw proof timing receipts,
controls, and summary are retained in the output directory. `performance_eligible`
means this script's mechanical gates passed, not that the benchmark has had an
independent performance audit. The API still requires callers to authenticate
XBC and key ownership; this replay does not establish soundness of an unaudited
circuit, constant-time witness handling, complete memory erasure, or side-channel
equivalence. The CPU backend remains variable-time.
