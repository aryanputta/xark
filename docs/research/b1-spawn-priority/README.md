# B1 insertion-order screen, 2026-11-26

This benchmark-only branch starts at `c1c87fe881c4a6c43e54527c5549e1015becfea2`. It varies only when the resident CPU prover submits B1 to the Rayon scope. The B2 task remains spawned, and all MSM arithmetic, source relation, key and proof format are unchanged. The earlier B-query schedule experiment also ran B2 inline; this screen isolates that confound. The default task order remains unchanged when the feature is absent or the flag is zero.

The optimized binary SHA-256 is `fee9da24d0e9c5612d47e3ff5461def081d1a3d83ad7b6f031d3950cec51f655`, built with locked dependencies and `--profile ci` using `msm-g2-shifted-bench,msm-b-shared-bench,msm-g2-endpoint-bench,msm-b1-spawn-bench`. The runner checked all 28 synthetic Privacy Rings fixture files against manifest SHA-256 `0436bedbae33912331d7306b9c1406956be5695d43f85f5c750f19bbb9bcce41`. The complete tree used was `/private/tmp/xark-matched-local/fixture`. Each of 24 process runs used two Rayon workers, one concurrent request and four distinct requests. The first request warmed the process; 72 post-warmup proofs were measured. Every one of the 96 proofs passed Xark and Arkworks verification, and all runs rejected altered and cross-request statements. The two task orders alternated over three blocks per circuit and mode.

| Circuit | Mode | B1 first | Service p50, ms | Paired baseline minus candidate mean, ms | Candidate wins / 9 | B1 start p50, ms | B2 end p50, ms | Latest task |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| Escrow | CPU | 0 | 442.8 | 0 |  | 215.7 | 347.6 | B2, 9/9 |
| Escrow | CPU | 1 | 430.1 | +14.4 | 8 | 0.1 | 331.1 | B2, 9/9 |
| Escrow | GLS | 0 | 507.8 | 0 |  | 253.3 | 386.4 | B2, 9/9 |
| Escrow | GLS | 1 | 544.6 | -45.6 | 1 | 0.4 | 399.1 | B2, 9/9 |
| Withdrawal | CPU | 0 | 432.2 | 0 |  | 257.4 | 339.4 | B1, 7/9 |
| Withdrawal | CPU | 1 | 417.3 | +1.2 | 2 | 0.1 | 325.6 | A, 9/9 |
| Withdrawal | GLS | 0 | 394.9 | 0 |  | 233.5 | 292.6 | B1, 9/9 |
| Withdrawal | GLS | 1 | 398.1 | -12.3 | 3 | 0.3 | 304.7 | A, 9/9 |

All task numbers exclude process warmups and are from per-proof spans. The median CPU setup was 736 ms escrow and 661 ms withdrawal; GLS setup was 2067 and 1569 ms. These setup figures include key and table preparation and are diagnostic. One-minute host load ranged from 11.28 to 21.84 on a shared macOS x86-64 machine. This host failed previous same-binary stability gates. The screen **does not establish any performance improvement**, including the apparent CPU escrow gain. It does show that early B1 submission moves withdrawal's last-finishing task to A. No production schedule was changed.

The targeted Rust test proves byte-identical output for both orders with nonzero and zero `r`, and independently verifies the resulting proof. The complete-request runner also checks proof and negative-statement receipts. Reproduce using `python3 run.py BINARY FIXTURE_TREE EMPTY_OUTPUT_DIR` with the exact binary feature set above. Raw JSON, stdout and task-span stderr are retained here. The next scheduling experiment should balance A and B1 release under a qualifying host control rather than repeatedly moving B1 alone. Treat both the original upstream MSM and cached GLS as variable-time with witness-dependent access; this insertion-order flag is public configuration and retains no private data across requests.
