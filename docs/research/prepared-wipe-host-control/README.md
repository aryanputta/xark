# Identical-binary host gate for prepared quadratic wipe

The candidate source was `fix/prepared-quadratic-wipe` at `c66df4de7e966b5b616e8e3d3fec7ae3116683ff`. Both arms used the exact same isolated-target optimized binary, SHA256 `f6222e24b6ccef7a625d5210fcb9f397b5b29a95570d142755bd928de11e83c3`. The runner source SHA256 was `8180e9af0885c9b78897f3df0823d7f940c69d71ff34b45d94caf6b3d2149572`; the fixture manifest SHA256 was `0436bedbae33912331d7306b9c1406956be5695d43f85f5c750f19bbb9bcce41`. The locked optimized `ci` build used Rust/Cargo 1.94.1 on `x86_64-apple-darwin` and a dedicated Cargo target directory. A one-request preflight confirmed no diagnostic instrumentation in the binary and independently verified the withdrawal proof while rejecting an altered statement.

The existing `replay_full_proof.py` script ran four balanced blocks per circuit, four complete synthetic proof requests per arm per block. All 64 measured proofs passed Arkworks verification and all 64 altered statements were rejected. Raw proof and timing outputs are in `*stdout` and [report.json](report.json).

| Circuit | Largest absolute paired block drift | Four paired block changes |
| --- | ---: | --- |
| Escrow | 2.797% | -1.919%, +1.026%, -2.797%, -1.767% |
| Withdrawal | 16.195% | +0.664%, +16.195%, -0.761%, +6.013% |

The existing 2% same-binary gate **failed**, most clearly for withdrawal. The machine had three logged-in users; one-minute load was 6.60 near the run. These numbers are measurement instability, not a candidate speed or slowdown. No candidate-versus-control replay followed. The earlier 2.977% withdrawal slowdown signal is not adequate for a promotion or rejection decision on this host.

## Artifact isolation finding

A preliminary rebuild in a target directory shared with an instrumented worktree silently linked the instrumented `xark-ir` dependency. It printed `quadratic_wipe` diagnostics and produced binary SHA256 `88685ebd25f7e3b5c1187a5e5cd6245ba066db990112`, despite the production source worktree being selected. That binary was rejected before the host control. Rebuilding into `/private/tmp/xark-quadratic-production-target` restored the original production hash `f6222e24` and removed the diagnostics. Brain failure triage case `1187cb935cd86297` records the root cause, fix and validation. Keep separate target directories across experimental worktrees and check post-build binary fingerprints before timing.

## Linux access status

This managed shell reports `No DNS configuration available`; `dig` cannot create its socket, and direct SSH to a historically published Rutgers iLab IP is denied with `Operation not permitted` even with the known host key pinned. This is a sandbox networking restriction. It does not prove the Rutgers host itself is down. Use an authorized network-capable session for the pinned Linux package. Do not use shared GitHub CI timing as the acceptance benchmark.
