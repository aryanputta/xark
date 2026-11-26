# B1 shifted-base screen, 2026-11-26

This is a **contended macOS diagnostic**, not an accepted prover speedup. The 128-bit shifted public-base table was compared against the existing G1 GLV path on exact synthetic Privacy Rings B1 queries. The export reader checked canonical scalars, curve and subgroup membership, and the Arkworks MSM reference. Each timed result was checked against that reference outside the timer. Both arms used the same optimized binary and two Rayon workers; order alternated each pair. The 30-pair screen was followed by a separate 100-pair block per circuit, with five warmups.

Source: `perf/b1-shifted-screen`, based on `integration/b2-ablation` at `b0c3eb157e58f519a3a932f7f7cfb9966d2d87bc`. Binary SHA-256: `f22404b1e7136ba784655dabb0818e82429bbec8e0d4cf55a770d71089a4fa71` (before formatting-only source change). Rust `1.94.1`; locked offline `ci` profile. Query SHA-256: escrow `735c2881111ae60c08c4e9128cdebfa15fdc766b0c2daefd1116ea49bfbdd75d`, withdrawal `cfdd6f228e4255945ef11326fdd9db5639c28a45c50bf15e27634c33f55e9670`. Query exports were kept in `/private/tmp` because they contain witness-derived synthetic scalars. Host load around the experiment changed from 6.16/17.29/15.81 to 5.47/15.22/15.14; process inspection and CPU topology queries were denied by the sandbox. This host cannot establish portable or production performance.

| Circuit, measured pairs | Existing GLV p50 | Shifted p50 | Mean paired B1 gain | 95% paired bootstrap interval | Shifted wins | Shifted p95 | Table payload | Setup |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Escrow, 30 | 54.847 ms | 53.454 ms | 1.498 ms | 0.695 to 2.301 ms | 23/30 | 55.611 ms | 973,568 B | 296.838 ms |
| Withdrawal, 30 | 37.855 ms | 36.719 ms | 1.049 ms | 0.575 to 1.555 ms | 23/30 | 38.273 ms | 691,968 B | 178.604 ms |
| Escrow, 100 | 52.454 ms | 51.150 ms | 1.230 ms | 0.816 to 1.636 ms | 74/100 | 54.181 ms | 973,568 B | 273.221 ms |
| Withdrawal, 100 | 38.819 ms | 38.194 ms | 0.288 ms | 0.019 to 0.552 ms | 66/100 | 41.876 ms | 691,968 B | 185.999 ms |

Intervals resample the **mean within-pair difference** with a fixed RNG seed and 10,000 bootstrap draws. The reported p95 is the empirical index at 95% of sorted samples, not a supported production tail claim. In the 100-pair block, withdrawal existing GLV p95 was 41.079 ms, so the shifted tail moved in the wrong direction. Both order strata favored shifted for escrow (mean gain 0.935 and 1.525 ms) and withdrawal (0.243 and 0.332 ms), but withdrawal's gain contracted by about 72% between blocks. The host's changing load prevents a causal speed claim.

Naive table-setup divided by the 100-pair mean B1 gain gives roughly **222 escrow** and **646 withdrawal** B1 invocations. These are diagnostic amortization ratios, not complete-proof break-even counts. No full proofs used this B1 table, so complete-proof latency, memory peak, verification and critical-path effects remain unmeasured. The existing B2 table and its setup are separate.

Decision: keep this as a focused experimental benchmark. Do not enable it in production or claim a Privacy Rings improvement. A qualifying Linux replay should use a same-binary host-control gate, then measure paired B1/B2 task spans and independently verified full proofs before considering integration. The table uses only public immutable proving-key points; scalar splitting and bucket assignments remain request-local in this benchmark. The existing variable-time MSM and the proposed table access pattern still need a side-channel review for shared-tenant proving.

Raw data: [escrow 30](escrow.csv), [withdrawal 30](withdrawal.csv), [escrow 100](escrow-100.csv), [withdrawal 100](withdrawal-100.csv). Fixture exporter: `crates/groth16/examples/support/query_msm.rs` at the pinned source. Benchmark build and strict Clippy passed. All 520 measured B1 outputs and 32 warmup outputs matched the independent Arkworks reference.
