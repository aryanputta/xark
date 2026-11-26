# G1 affine bucket batch-limit screen, 2026-11-26

## Hypothesis and scope

With two workers, withdrawal often finishes on the H/A/B1 G1 lane after B2 is accelerated. A smaller affine flush limit might improve G1 cache locality enough to offset additional batch inversions. This experiment changes only the G1 affine bucket flush limit; the MSM window-selection model remains fixed at its existing 512-addition assumption. The 512 arm is the existing behavior. The selector is behind `msm-g1-batch-bench`, set once from a public process configuration before proving; no production default was changed.

The experimental [branch](https://github.com/aryanputta/xark/tree/perf/g1-affine-batch-screen) is `perf/g1-affine-batch-screen` at `5ea5ea1`, based on prepared request phase branch `c1c87fe`. Optimized binary SHA256: `358c4fb744671c174a92262c4dee3f0b449e8a5d68f5b0bda5d71ffeb10458e0`. Locked Cargo `ci` build, two Rayon workers, one active proof request, and the same binary for every setting. The [runner](run.py) checks all 28 fixture hashes and rotates 128, 256 and 512 through three blocks for escrow and withdrawal.

Each of 18 processes generated four measured proofs and one warmup, for **72 measured and 18 warmup complete proofs**. Xark and Arkworks verified every proof and rejected altered and cross-request statements. Every measured request emitted all nine task spans and a phase receipt. The independent G1 projective-addition test passed at limits 64, 128, 256, 512 and 1024, including cancellation, queueing and spill behavior. Eleven default-feature library tests, five MSM integration tests, strict example Clippy and formatting passed.

## Diagnostic results

| Circuit | Limit | Request p50 ms, 12 samples | Median H task ms | Median A task ms | Median B1 task ms | Paired mean 512 minus arm ms | Arm wins / 12 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Escrow | 128 | 273.2 | 75.9 | 40.0 | 57.0 | -5.0 | 2 |
| Escrow | 256 | 255.5 | 68.3 | 36.4 | 50.8 | -4.0 | 7 |
| Escrow | 512 | 265.7 | 69.6 | 37.2 | 52.1 | baseline | baseline |
| Withdrawal | 128 | 254.4 | 90.7 | 35.7 | 51.3 | -6.0 | 3 |
| Withdrawal | 256 | 241.0 | 84.0 | 34.2 | 48.0 | +2.8 | 10 |
| Withdrawal | 512 | 242.8 | 85.2 | 35.3 | 48.0 | baseline | baseline |

The paired calculation matches each arm with the 512 arm at the same block and request index. Escrow B2 still finished last in all 36 requests. Withdrawal B1 finished last in 35 of 36 requests, with one B2 finish in the 256 arm. Process peak RSS is in `report.json`; across arms it varied by several MiB on this shared Mac and cannot establish a memory benefit. The host's one-minute load ranged from 6.52 to 8.23 during this short screen. Earlier same-binary controls failed their preset stability gate, and this report sets `performance_eligible: false`.

## Decision and security

Reject 128: it regressed both circuits and the G1 task timings. Retain 256 only as an inconclusive diagnostic: its small withdrawal gain was not reproduced as an escrow gain and is below the host's observed drift. Do not enable either setting in production or claim a complete-proof speedup. The algorithmic grouping changes no curve identity; every screened proof and the independent bucket test passed. The selector uses only public configuration, while the pre-existing variable-time MSM still needs its separate witness side-channel assessment. No private witness values or scalar digits are retained in the public raw timing files.

Next, examine mathematical work reduction or a more effective joint B1/H/B2 schedule. Reproduce any promising batch value on stable Linux with a same-binary host gate and at least 100 paired requests before reconsidering it. Raw stdout, stderr, load, RSS and service timings are preserved beside this report.
