# Privacy Rings competitive benchmark

Run the real timelock escrow and withdrawal workloads from one manifest. The
runner verifies fixture hashes, exports shared inputs and runs one process
at a time with alternating Xark-first and competitor-first pairs. Every
timed batch must pass its adapter's correctness checks before the runner
publishes CSV and JSON output.

| Selection | Timed work | Verification outside timing |
| --- | --- | --- |
| `xark` | Native CPU resident proving and compiled row checks | Every proof accepted by Arkworks and Xark. The changed statement is rejected by both. |
| `gnark` | Xark and Gnark resident proving with witness row checks, using the same ordered reduced relation and witness | Each prover checks its own proofs. Xark also uses Arkworks. Both arms reject the changed statement. |
| `rapidsnark` | Xark resident proving and the Rapidsnark resident C API. The C API includes witness decoding and proof JSON serialization. | snarkjs checks the shared witness, every Rapidsnark proof and the altered statement. Xark uses its usual two verifiers. Both arms check witness rows outside timing. |
| `constantine` | Resident synchronous CPU B1 query MSM on the exported Arkworks bundle | Both arms match the Arkworks result. Constantine must also reject a bundle with an incorrect B1 reference. |
| `icicle` | Resident synchronous ICICLE CPU B1 and B2 query MSM, including per-call API scratch work | Both arms match the Arkworks references. ICICLE must reject incorrect reference points in separate B1 and B2 control runs. |

Query bundles use the supplied proving key and a witness whose derived public
hash matches the valid fixture statement. Xark and the competitor consume
the same ordered points and scalars. Query negative controls test the MSM
result. The full-proof lanes exercise cryptographic statement rejection.
All lanes use CPU execution.

## Fixture setup

Use Python 3.11 or newer and a Unix host. This revision uses the public
synthetic fixture archive from the final PR #106 evidence commit
[`913825bb`](https://github.com/aryanputta/xark/commit/913825bb3a520bd248ff5d3b398b705c585f5cd7).
The hosted workflow copies its reference circuit and key plus the first
verified request for each workload into the competitive fixture layout. It
checks every copied file against `fixtures.sha256` before starting a proof.
Keep extracted keys and witnesses in a private test-only directory.

```sh
umask 077
archive="$HOME/Downloads/fixtures-synthetic.tar.gz"
printf '%s  %s\n' 73a2bdad7c9043ee761dee7d29a5abff0263b8761db7067acafdc9030d3db0cc "$archive" |
  shasum -a 256 -c -
fixtures=$(mktemp -d)
tar -xzf "$archive" -C "$fixtures"
(cd "$fixtures" && shasum -a 256 -c SHA256SUMS)
```

The pinned application source for these fixtures is Privacy Rings examples
`a02886da343e5f3a14d6d8a2843bdb3fd696d94e`. The archive contains
synthetic requests that exercise real escrow and withdrawal circuits and
produce verified proofs.

## Build and run

Build the selected adapters from clean pinned sources. The Xark build helper
requires an empty, isolated Cargo target directory and records the source
commit, lockfile, compiler, command, logs and resulting binary hash. This
prevents a shared target directory from silently supplying an object built
from another experimental worktree. Save other compiler versions, commands,
dependency locks, and library linkage receipts as `additional_artifacts` in
the [example manifest](config.example.json).
Manifest paths are relative to the manifest location unless absolute. The
Xark source pin covers the benchmark example, Arkworks Cargo.lock, and the
Gnark adapter and Go locks. The report records the checkout revisions and
hashes of the actual executables, shared libraries and inputs. Keep the
build receipts to associate the executable fingerprints with source builds.

```sh
root=$(pwd)
pin=$(git -C "$root" rev-parse HEAD)
python3 benches/competitive/build_xark.py \
  --source "$root" --expected-commit "$pin" \
  --target-dir /path/to/new-empty-xark-target
mkdir -p /path/to/bin
python3 benches/competitive/build_gnark.py \
  --source "$root" --expected-commit "$pin" \
  --target-dir /path/to/new-empty-gnark-target
cp benches/competitive/config.example.json /path/to/run.json
```

Set `binaries.bench` to the helper's `release/examples/bench_prove` executable
and `xark_build_manifest` to its `xark-build-manifest.json`. For a Gnark lane,
set `sources.gnark`, `binaries.gnark`, and `gnark_build_manifest` to the
competitive-harness checkout, its built adapter, and its build receipt. The
Gnark helper pins `main.go`, `go.mod`, `go.sum`, the embedded module list,
the binary hash and build logs. The runner verifies that receipt before timing.
Manifest version 2
requires a self-consistent Xark build record before any timed request. Version
1 remains readable but reports the Xark build as `unattested`. The manifest is
an auditable build record, not a cryptographic attestation of the compiler or
an uncontended-host guarantee. Fill in the checkout commit, fixture root, and
the paths for the lanes you want to run. Build [Constantine](../privacy-rings-constantine/README.md) and
[ICICLE](../privacy-rings-icicle/README.md) with their pinned upstream
revisions and record their compiler flags and runtime dependencies.
Use the pinned [Rapidsnark C API source](https://github.com/iden3/rapidsnark/tree/81eddf1a536d26497b237c0b8a04fe90baf7e439)
and build its shared `rapidsnark` target in Release mode with
`-DUSE_ASM=ON -DUSE_OPENMP=ON -DUSE_LOGGER=OFF`. Install snarkjs 0.7.6 with an npm
lockfile. Provide a prepared BN254 Phase 2 powers-of-tau file of power 14 or
higher and its verified digest. snarkjs generates test keys from the
freshly exported circuit outside the measured interval. The resident driver
was adapted from the Xark sprint's Rapidsnark comparison.

A Linux VM with two online vCPUs gives every engine the default two-thread
budget. Rapidsnark's worker pool also reads the host CPU count, so CPU
affinity alone is insufficient to qualify that lane. For other lanes, use
the same CPU affinity for the whole process tree when available and record
whether the chosen cores share a physical core.

```sh
# Run all lanes with the default four pairs, 30 samples and three warmups per arm.
python3 benches/competitive/run.py --config /path/to/run.json \
  --output /path/to/results --strict-contention

# Xark and Arkworks proof-only smoke on both fixtures.
python3 benches/competitive/run.py --config /path/to/run.json \
  --output /path/to/native-smoke --competitor xark --pairs 2 --samples 3 --warmups 1
```

Repeat `--competitor` to select a subset or use `--workload` to select one
fixture. Each pair runs after the previous process exits. At least two
pairs are required so both orders appear. Opposite workloads start with
opposite orders. The standalone `xark` lane repeats the native proof
measurement. Select `xark-query` to run both native queries against
Arkworks without installing an external MSM engine.

For a public Gnark latency claim, run a control cohort before the measured
cohort and audit each cohort with `gnark_gate.py`. It independently reparses
every raw sample, matches the report's p50/p95/p99, and requires each backend's
same-binary pairs to stay within the preset 2% p50 and 10% p95 drift limits.
Retain failed-control receipts. This lane times resident row checks and proving
on an exported identical relation and witness; it is distinct from the
`PreparedCpuProver::prove` full request interval in PR #106.

```sh
python3 benches/competitive/run.py --config /path/to/run.json \
  --output /path/to/control --competitor gnark --pairs 2 --samples 32 \
  --warmups 3 --strict-contention
python3 benches/competitive/gnark_gate.py /path/to/control --pairs 2 --samples 32
python3 benches/competitive/run.py --config /path/to/run.json \
  --output /path/to/measured --competitor gnark --pairs 4 --samples 30 \
  --warmups 3 --strict-contention
python3 benches/competitive/gnark_gate.py /path/to/measured --pairs 4 --samples 30
```

## Read the output

- `samples.csv` contains every accepted sample in nanoseconds, including
  fixture, lane, pair, process position, engine and metric. Xark and
  Rapidsnark proof receipts report microsecond precision.
- `report.json` contains p50, nearest-rank p95 and p99, per-pair medians,
  timing boundaries, executable and input fingerprints, CPU topology,
  affinity, worker configuration, process observations and raw log paths.
  Tails from small batches often select the maximum, so use the sample
  counts when interpreting them.
- The runner samples external process CPU use about once a second and
  records host load before and after each arm. This is a coarse indicator
  of overlap. Short activity, kernel scheduling and other VM tenants can
  escape detection. Flagged pairs retain raw samples and have no ratio.
  `--strict-contention` also fails when process monitoring is unavailable.
- Ratio fields are competitor over Xark for each eligible pair and
  operation. The Rapidsnark comparison retains both medians but omits
  ratios because its ABI boundary differs. There is no overall ranking.
- Raw logs, derived inputs and any test keys are kept under the private
  result root. A failed run leaves diagnostic logs and no verified JSON.
  Share reviewed report and CSV files separately from the result directory.

Run receipt contract tests with
`python3 -m unittest discover -s benches/competitive -v`. Set
`XARK_ARCHIVED_RECEIPTS` to the sprint's `evidence/benchmark-lab` directory
to test archived Gnark, Rapidsnark, Constantine and ICICLE receipts. This
exercises parsing of previously recorded samples.
