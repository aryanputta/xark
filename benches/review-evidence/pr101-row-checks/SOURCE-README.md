# Compiled witness row checks on Privacy Rings

The Xark 0.5 branch at `e6a36be` used the existing numeric template evaluator to check each bytecode row directly. The control materialized and evaluated the same rows. Both arms ran the same resident prover in the same executable. The expanded arm held a separate prebuilt row source for the check. Compare timings here and record memory separately before drawing memory conclusions.

| Workload and pair | Expanded row check p50 | Compiled row check p50 | Expanded checked prove p50 | Compiled checked prove p50 | Checked prove p50 reduction |
| --- | ---: | ---: | ---: | ---: | ---: |
| Escrow 1 | 57.234 ms | 10.321 ms | 474.061 ms | 434.736 ms | 8.30% |
| Escrow 2 | 57.116 ms | 10.740 ms | 480.957 ms | 435.016 ms | 9.55% |
| Withdrawal 1 | 42.449 ms | 7.402 ms | 394.322 ms | 348.795 ms | 11.55% |
| Withdrawal 2 | 40.681 ms | 7.180 ms | 380.598 ms | 354.534 ms | 6.85% |

Each arm used three warmups and 30 measured calls. Pair 1 ran expanded then compiled. Pair 2 reversed the order. Two Rayon workers ran on the single reported Intel Xeon core with two SMT siblings. The once-per-second process monitor flagged no overlap. The interval includes row checking and resident proving. Setup, witness solving, and proof verification were outside that interval. These measurements cover warm, checked resident proving on this host. [Host](host.log) · [Exact launcher](run-row-checks.sh) · [Raw log fingerprints](files.sha256)

Both Xark and Arkworks verified all 240 measured proofs and rejected the changed statement for the first proof of every arm. The locked release suite passed 25 of 25 tests. The new test compares the earliest failing row, including the fallback for a noncanonical constant wire. The circuit, key, ordered witness and statement hashes agree with the [guarded Gnark comparison](../2026-11-25-colab-gnark-paired/README.md). [Regression log](tests.log) · [Escrow manifest](escrow.sha256) · [Withdrawal manifest](withdrawal.sha256)

The imported patch was SHA-256 `16e8abba0b71be7e198aadbf9b7cb3ffefcda2576dfc632da8f37da80301118a` and the downloaded log archive matched SHA-256 `3ce52fa233ddf194d5be5d7b7d1914296339d01b6931d5aaf8e282e0a5e76f72`. To recreate the bundle from the integration checkout, write `git diff --binary 3c290d8 e6a36be` to `xark-row-checks.patch`, place it beside the launcher, and write a `row-checks.sha256` manifest for both files. The launcher uses the existing pinned Colab fixtures and Rust environment.

## Direct post-patch Xark and Gnark comparison

The same Xark candidate binary ran directly against the pinned Gnark 0.14.0 helper. The launcher matched the prior guarded run's artifact and Gnark binary hashes, re-exported and checked the ordered rows and witness, and reversed the order for its second 30-sample pair. The sampled process monitor flagged no overlap. Xark and Arkworks independently verified Xark's proofs. Gnark verified its proofs and rejected the changed public statement. Witness solving, setup and verification were outside the timer. [Escrow run](vs-gnark/escrow/status.log) · [Withdrawal run](vs-gnark/withdrawal/status.log) · [Raw fingerprints](vs-gnark/files.sha256)

| Workload and pair | Xark p50 | Gnark p50 | Median gap | Gnark p50 reduction |
| --- | ---: | ---: | ---: | ---: |
| Escrow 1 | 425.377 ms | 331.351 ms | 94.026 ms | 22.10% |
| Escrow 2 | 434.163 ms | 334.255 ms | 99.908 ms | 23.01% |
| Withdrawal 1 | 361.768 ms | 282.961 ms | 78.807 ms | 21.78% |
| Withdrawal 2 | 356.456 ms | 279.736 ms | 76.720 ms | 21.52% |

After subtracting each sample's row-check duration before taking the median, Xark's remaining resident interval was 416–424 ms for escrow and 349–355 ms for withdrawal. Gnark's measured interval still includes its witness check. The remaining difference warrants profiling G1 and G2 MSM, QAP row evaluation and FFT separately. The results cover one physical core with two SMT siblings.

The direct comparison archive matched SHA-256 `018da3f69b5f0faa2e6df87205cd69d67a02c227926ec8fa2d2207a729cd015b`.
