# PR #106 buffer cleanup cost ablation

This separate replay isolates the two final buffer-cleanup commits from later
unwind-guard changes. All three arms use the same benchmark-only caller of the
public `PreparedCpuProver::prove` API, XBC/key pairs, and four synthetic Privacy
Rings requests per circuit. Every request must produce a proof that passes
positive Xark and Arkworks verification and rejects altered and cross-request
statements. The service interval starts before reading the request and ends
when the public API returns. Independent verifier checks run after that interval.

| Arm | Production source | Interpretation |
| --- | --- | --- |
| `before` | `2b7190abbc6fc1696f23a23fb049d7917416ccc1` | Before two cleanup commits |
| `cleanup` | `98ef685895a9c594938ae6528e8e57bfaf637734` | After the two commits; diff from `before` is `crates/ir/src/function_decode.rs` |
| `guarded` | `5cadc60e1aca6f5ed557da41c501d4f3f89e3549` | Final PR head with unwind guards |

The fixture archive is pinned at `913825bb3a520bd248ff5d3b398b705c585f5cd7`,
SHA-256 `73a2bdad7c9043ee761dee7d29a5abff0263b8761db7067acafdc9030d3db0cc`.
All 28 fixture files must match [fixtures.sha256](evidence/fixtures.sha256).
Each arm builds separately with the same `--locked --profile ci` settings.

The runner pins two logical CPUs on distinct physical Linux cores and uses two
Rayon workers. Before comparing arms, it runs two same-binary controls of 32
verified requests per arm and circuit. Every pair must have p50 drift at most
2% and p95 drift at most 10%. Passing runs use six balanced order blocks of
20 requests per arm and circuit, so each arm appears twice in each position
and has 120 measured verified requests per circuit. It reports preparation,
warm p50/p95, peak process RSS, and separate `before→cleanup`,
`cleanup→guarded`, and `before→guarded` deltas. If a control fails, no cost
comparison is eligible. The workflow uploads raw stdout/stderr and the report
even when the gate rejects the host.

This is a bounded, host-specific ablation. It does not establish constant-time
witness handling, complete erasure, or side-channel equivalence. The CPU backend
remains variable-time.
