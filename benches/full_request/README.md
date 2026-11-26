# Verified full-request host control

`host_control.py` runs the same upstream Xark executable, fixture files, worker budget and environment in alternating A/B process order. Each process solves distinct synthetic Privacy Rings requests, checks constraints, generates proofs with fresh randomness, verifies every proof through Xark and Arkworks, and rejects altered and cross-request public statements. The parser refuses missing receipts, incomplete request coverage and invalid phase timings. The fixture manifest must match all 28 private test files before execution.

The prespecified gate rejects a host if **any** fixture/block pair drifts by more than 2% in p50 or 10% in p95 between the two identical arms. At eight requests, the reported p95 is the maximum sample and is only a screening statistic. Passing this gate is necessary but does not itself make a shared host authoritative. The report always has `performance_eligible: false`; a separate host, topology, contention, proof and comparison audit decides acceptance.

## 2026-11-26 Mac screen

The first actual screen used the exact `bench/verified-upstream-requests` source at `a23bed4`, an optimized `ci` profile binary with SHA-256 `c0574e7fedb778b9ec10fef5b57be151e752f1d037db138702f309f2800fca16`, Rust 1.94.1, two Rayon workers, one concurrent request, eight measured requests per process and two balanced blocks. All 28 fixture files matched the pinned manifest. Eight processes produced 64 independently checked request proofs; all altered and cross-request statements were rejected. [Raw process receipts and per-request timings](evidence/).

| Fixture/block | Same-binary p50 drift | Same-binary p95 drift | Gate |
| --- | ---: | ---: | --- |
| Escrow 1 | 0.82% | 0.62% | Pass |
| Escrow 2 | **4.57%** | 0.28% | **Fail** |
| Withdrawal 1 | 1.11% | 3.88% | Pass |
| Withdrawal 2 | 1.12% | 3.41% | Pass |

The Mac's one-minute load was roughly 9–11 during the run. The complete host control **failed**, so the candidate binary was not timed in this block. No Xark speedup or Gnark comparison follows from these data. The candidate was separately built from `perf/sparse-resident-solver-metadata` at `5b749a4` with SHA-256 `0178fa36bef4758f9aefa3644ef3bfa79fb7ca685ccbdedaa56b739c2fc57490`; its build is preparation, not a measurement.

Run the unit gate and a new screen on an authorized private host:

```sh
python3 -m unittest discover -s benches/full_request -p test_host_control.py
python3 benches/full_request/host_control.py /path/to/bench_verified_warm \
  /path/to/private-fixtures /path/to/fixtures.sha256 /path/to/new-output \
  --requests 8 --blocks 4 --workers 2 --concurrency 1
```

Use a new output directory for each attempt. Run both concurrency 1 and 2 before qualifying complete-request latency and throughput. Keep the synthetic witness inputs and keys on the authorized host; only the aggregate timing receipts are archived here. The eight process stdout/stderr logs were screened for scalar, witness and input values before committing.
