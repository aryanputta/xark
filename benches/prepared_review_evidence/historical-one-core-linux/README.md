# Prepared solver Linux replay

This private offline package compares two modes of **one identical Xark binary** on synthetic Privacy Rings escrow and withdrawal fixtures. The binary is built from `bench/prepared-solver-soundness-phase` at `c2a3922480b1d60b285f065c941bd1dbf84b8cdd`. The focused production source patch is `perf/prepared-satisfied-proving` at `76b13ab1eb981c4f88fab73d83934205e8c13aa9` and has no benchmark instrumentation.

The archive contains synthetic witness inputs. Keep it inside a trusted proving environment. It does not contain a Cargo dependency vendor directory; use an authorized machine with Rust 1.94.1 and access to the pinned dependencies or an already populated cache. Do not publish the fixture archive.

## Verify, extract and build

On an idle Linux machine with at least two physical cores, record `rustc -Vv`, `cargo -V`, `lscpu -e=CPU,CORE,SOCKET,NODE,ONLINE`, CPU affinity, frequency policy and memory limit. Inspect archive paths before extraction. Then, from the extracted package directory:

```sh
sha256sum -c SHA256SUMS
git clone -b bench/prepared-solver-soundness-phase xark-prepared-solver.bundle source
test "$(git -C source rev-parse HEAD)" = c2a3922480b1d60b285f065c941bd1dbf84b8cdd
mkdir fixtures
tar -xzf fixtures-synthetic.tar.gz -C fixtures
(cd fixtures && sha256sum -c fixtures.sha256)
(cd source && cargo build --locked --profile ci -p xark-groth16 --features msm-b-shared-bench,msm-g2-shifted-bench,msm-g2-endpoint-bench --example bench_prove)
sha256sum source/target/ci/examples/bench_prove
```

The source bundle and fixture archive are separately checksummed in `SHA256SUMS`. The runner checks all 28 fixture files again and records the binary fingerprint and source commit.

## Correctness preflight

The short smoke runs four distinct requests per circuit and mode, verifies each valid proof with Xark and Arkworks, and rejects altered and cross-request statements. Its report is explicitly ineligible for speed claims.

```sh
python3 paired_linux_replay.py source/target/ci/examples/bench_prove fixtures fixtures/fixtures.sha256 smoke --source-dir source --smoke --workers 2 --concurrency 1
```

## Qualified replay

Choose two separate **physical** cores and pin the process to them. The runner verifies that the CPU affinity covers exactly two distinct physical cores. It first executes four same-binary, same-mode control pairs, with 32 verified requests in each control. It stops before comparing modes if any pair drifts over 2% in median or 10% in p95. If controls pass, four alternating blocks of 25 requests per mode and circuit yield 100 measured proof samples per arm. Raw stdout/stderr, service and solver samples, independent verification receipts, setup time, active throughput, peak process RSS and host load are saved under a new output directory.

```sh
CPU_LIST=0,2  # replace with two distinct physical cores from lscpu
taskset -c "$CPU_LIST" python3 paired_linux_replay.py source/target/ci/examples/bench_prove fixtures fixtures/fixtures.sha256 qualified --source-dir source --requests 25 --blocks 4 --workers 2 --concurrency 1
```

Do not treat a passing gate on a shared CI runner as the sole production performance evidence. Repeat independently on an idle machine. This package isolates the prepared solver mode within one binary; comparing to current upstream Xark and equivalent Gnark requires a separate matched full-proof replay using the same relation, witness, public statement, hardware budget and timed boundary. The security review and process-memory behavior still need broad validation.
