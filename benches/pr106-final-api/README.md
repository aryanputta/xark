# PR #106 final API replay

This benchmark-only branch descends from the final PR #106 implementation at
`ddce2df8ea5d8f624a5ed6da5eac149a8dd6b04a`. The candidate example invokes
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
The fixture archive is retained in the
[public evidence bundle](https://github.com/aryanputta/xark/blob/913825b/benches/prepared_review_evidence/fixtures-synthetic.tar.gz)
at SHA-256 `73a2bdad7c9043ee761dee7d29a5abff0263b8761db7067acafdc9030d3db0cc`.
Its 28-file manifest is checked in at [evidence/fixtures.sha256](evidence/fixtures.sha256).

The [hosted Linux replay workflow](../../.github/workflows/pr106-final-api-replay.yml)
checks out exact upstream and candidate source commits, verifies the public
fixture archive and all 28 manifest entries, pins two logical CPUs from distinct
physical cores, runs runner unit tests and proof smokes, then performs the
predeclared same-binary stability gate. It uploads raw stdout/stderr, topology,
binary/source hashes, and the report even when the gate rejects the host. The
workflow run and artifact must be linked before any final-head speed claim.

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

Earlier Mac correctness and failed-control receipts are retained on
[the initial replay branch](https://github.com/aryanputta/xark/tree/1708a0b/benches/pr106-final-api/evidence).

The final-head Mac correctness smoke is retained there at
`evidence/smoke-2026-11-28`.
It completed four varied measured requests and one verified warmup for each
arm and circuit; every valid proof passed both verifiers, and both rejected
altered and cross-request statements. Its `performance_eligible` value is
`false`, so its request timings do not support a speed claim or break-even
estimate.

The final-head Mac control run is retained there at
`evidence/control-2026-11-28`.
All 256 control proofs completed and passed the proof and statement checks.
No arm comparison ran. The host failed all four same-binary control pairs:

| Circuit | Arm | p50 drift | p95 drift |
| --- | --- | ---: | ---: |
| Escrow | Upstream | 41.34% | 50.04% |
| Escrow | Prepared | 19.37% | 18.92% |
| Withdrawal | Upstream | 1.27% | 16.93% |
| Withdrawal | Prepared | 11.33% | 43.83% |

The gate allows at most 2% p50 and 10% p95 drift. This macOS host also fails
the two-distinct-physical-Linux-core topology requirement. These receipts
confirm the proof paths work, but they do not establish a speedup or
break-even count. A matched replay on an eligible host remains open.
