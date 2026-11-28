# Paired Xark review receipts for PR #101 and #103

These are the original November 25, 2026 benchmark logs, runner scripts, host receipts, binary hashes, and fixture hash manifests. `SOURCE-README.md` in each directory preserves the contemporaneous summary. The outer `SHA256SUMS` locks the published copies; each inner `files.sha256` locks the original receipt files. Run `python3 audit.py` from any directory to check the inner hashes, count the samples, and recompute the proof-time medians and reductions.

## What was measured

| PR | Source under test | Comparison | Timing boundary |
| --- | --- | --- | --- |
| [#101](https://github.com/blueshift-gg/xark/pull/101) | [`e6a36bec`](https://github.com/aryanputta/xark/commit/e6a36becf44baedc5897369b55ecc1c421fb054c) | Expanded versus compiled witness-row evaluator in the same resident prover binary | Warm proof **with explicit row preflight enabled**; setup, witness solving, and proof verification outside timer |
| [#103](https://github.com/blueshift-gg/xark/pull/103) | [`5a3217d0`](https://github.com/aryanputta/xark/commit/5a3217d0015a3292144fd9a6ac19bc6e3133077c) | Portable versus `-C target-feature=+adx,+bmi2` release build from the same source and lockfile, default Arkworks features | Warm resident proof with compiled row preflight enabled; setup, witness solving, and proof verification outside timer |

One Intel Xeon 2.20 GHz physical core exposed two SMT siblings; each process used two Rayon workers. Every arm had three warmups and 30 timed proofs. Two process-order pairs per circuit reduce order bias. The source receipts report Xark and Arkworks verification of all 240 proofs per PR and changed-statement rejection. The 30-sample p95 is exploratory.

| PR / circuit | Pair | Baseline p50 (ms) | Candidate p50 (ms) | p50 saved (ms) | p50 saved |
| --- | ---: | ---: | ---: | ---: | ---: |
| #101 escrow | 1 | 474.0610 | 434.7365 | 39.3245 | 8.30% |
| #101 escrow | 2 | 480.9575 | 435.0160 | 45.9415 | 9.55% |
| #101 withdrawal | 1 | 394.3215 | 348.7950 | 45.5265 | 11.55% |
| #101 withdrawal | 2 | 380.5985 | 354.5335 | 26.0650 | 6.85% |
| #103 escrow | 1 | 424.2385 | 362.8275 | 61.4110 | 14.48% |
| #103 escrow | 2 | 434.3225 | 358.6730 | 75.6495 | 17.42% |
| #103 withdrawal | 1 | 345.1305 | 305.1645 | 39.9660 | 11.58% |
| #103 withdrawal | 2 | 357.1665 | 298.3180 | 58.8485 | 16.48% |

These are differences between arm medians, not paired per-request deltas. The PR #101 result does not imply a default proof speedup when row preflight is disabled. The PR #103 result applies to this CPU and build and does not imply all machines benefit. The fixture hash manifests identify the original XBC, key, input, and statement files, but the exact original request JSON bundle is not in this directory, so this publication supports independent arithmetic audit and receipt inspection, not a complete fixture replay. The source runners refer to the original Colab paths and require those fixture files for a replay.

## Validate

```sh
shasum -a 256 -c SHA256SUMS
python3 audit.py
python3 -O audit.py
```
