# G1 window screen, 2026-11-26

This is an exploratory, same-binary screen of the G1 Pippenger window choice on synthetic Privacy Rings escrow and withdrawal requests. The branch starts at `c1c87fe881c4a6c43e54527c5549e1015becfea2`. The benchmark feature only changes G1's selected window by -1, 0, or +1; the default build stays unchanged. The tested optimized binary SHA-256 is `f34b35fa12d6266fc07bbc4ad71e1daca05f910f479171f18111f5bf24c11592`.

The runner checked all 28 fixture hashes against manifest SHA-256 `0436bedbae33912331d7306b9c1406956be5695d43f85f5c750f19bbb9bcce41`. Use the full fixture tree at `/private/tmp/xark-upstream-request.qVgDhH` or an equivalent extracted tree with the same manifest. Each of 18 process runs used two Rayon workers, four distinct requests and one concurrent proof; the first request warmed the process. All 72 proofs were independently verified by the benchmark example; 54 were measured after excluding 18 warmups. All runs rejected an altered statement and a cross-request statement. Arm order rotated across three blocks per circuit. Full stdout, stderr, runner output, and JSON are retained here.

| Circuit | Window delta | Service p50, ms | Paired baseline minus candidate mean, ms | Paired wins / 9 | B1 task p50, ms | B2 task p50, ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Escrow | -1 | 380.5 | -12.4 | 3 | 78.6 | 213.2 |
| Escrow | 0 | 371.7 | 0 |  | 73.0 | 209.6 |
| Escrow | +1 | 367.1 | +2.9 | 5 | 73.9 | 209.9 |
| Withdrawal | -1 | 262.6 | -10.9 | 2 | 51.3 | 142.0 |
| Withdrawal | 0 | 258.2 | 0 |  | 50.7 | 149.5 |
| Withdrawal | +1 | 248.5 | +4.3 | 5 | 52.0 | 143.1 |

Task p50 values exclude warmup. Escrow ended on B2 for all 27 measured requests; withdrawal ended on B1 for 22 of 27. The +1 arm did not consistently shorten B1, despite lower service medians. The -1 arm is a regression in this screen. All numbers come from a shared, contended macOS x86-64 host and are **not performance claims**. No window setting was promoted. A larger screen is justified only if a stable Linux host or a new G1 cost-model hypothesis becomes available.

Reproduce with the branch's `bench_prove` example built with `--profile ci --features msm-g2-shifted-bench,msm-b-shared-bench,msm-g2-endpoint-bench,msm-g1-window-bench`, then invoke `python3 run.py BINARY FIXTURE_TREE EMPTY_OUTPUT_DIR`. The runner fails on missing proof or rejection receipts. The feature's unit test checks -1, 0 and +1 against Arkworks on 521 bases and mixed scalar classes. `cargo test --offline --locked -p xark-groth16 --lib --features msm-g1-window-bench` passed 12 tests. See the local test log or rerun strict Clippy and formatting gates before reuse.
