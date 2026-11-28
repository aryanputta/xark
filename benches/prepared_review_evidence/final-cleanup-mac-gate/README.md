# PR #106 final-cleanup Mac host control

Date: 2026-11-28. This is an ineligible host-control receipt, not a speed comparison.

- PR source head: `98ef685895a9c594938ae6528e8e57bfaf637734` on `feat/prepared-cpu-prover-clean`, based on upstream `xark-0.5` at `03a7f519d28df6718f7ce6dda41f1e57e5ea55db`.
- Benchmark source: `89b43b11510a068d62e078a14fd95b084fe0dca2`, formed by applying the same two cleanup commits to the pinned benchmark instrumentation at `c2a3922480b1d60b285f065c941bd1dbf84b8cdd`. This is not the byte-identical PR source tree; it exercises the PR's final cleanup logic in the benchmark runner.
- The benchmark source is published on Aryan's fork as [`bench/pr106-final-cleanup`](https://github.com/aryanputta/xark/tree/bench/pr106-final-cleanup). The synthetic fixture archive is included in this review evidence directory.
- Binary: isolated optimized `ci` profile, SHA-256 `da73c0a1050e23adc3e0029d61967e1f38bd894cc3f3ce4a753d2e83d35de440`.
- Fixtures: synthetic Privacy Rings escrow and withdrawal inputs. The runner verified all 28 fixture hashes before execution. The fixture archive is published in this evidence directory's parent.
- Host: shared Intel macOS, Python 3.13.9; one-minute load at start 26.28. Two Rayon workers, one concurrent request.
- Command: `python3 paired_linux_replay.py <binary> <fixtures> <fixtures.sha256> <new-output-dir> --source-dir <benchmark-source> --requests 25 --blocks 4 --workers 2 --concurrency 1` using the runner archived in `evidence/benchmark-lab/2026-11-27-prepared-solver-phase/`.

The runner generated 256 complete control proofs, 32 per run across eight audit-mode runs. It parsed exact Xark verification and altered/cross-request rejection receipts for every run. Both arms of each control pair used the same binary and mode. The preset gate was at most 2% median and 10% p95 drift. All four pairs failed:

| Circuit/block | Median drift | p95 drift |
| --- | ---: | ---: |
| Escrow 1 | 5.34% | 36.58% |
| Escrow 2 | 1.06% | 42.82% |
| Withdrawal 1 | 9.07% | 9.83% |
| Withdrawal 2 | 22.87% | 33.23% |

No audit-versus-satisfaction measurements ran after the failed gate. The Mac run cannot estimate final-head speed or cleanup cost. An idle Linux host with a passing same-binary control is required. Cleanup cost itself also requires a separate matched before/after binary comparison; this runner compares two modes within one binary.

Raw `report.json` and every stdout/stderr control receipt are preserved next to this README. `SHA256SUMS` checks their byte identities.
