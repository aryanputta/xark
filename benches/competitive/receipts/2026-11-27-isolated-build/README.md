# Isolated competitive Xark build receipt

The stacked [feat/competitive-build-provenance](https://github.com/aryanputta/xark/tree/feat/competitive-build-provenance) candidate at `b2ddcc1` extends the existing competitive harness at `703fadf`. Its helper rejects an existing or in-tree Cargo target directory, checks the exact clean source commit before and after compilation, uses a new isolated target, disables Rust compiler wrappers, and writes a manifest with the lockfile, toolchain, build command, logs and executable hashes. Harness config version 2 checks that manifest before timed requests; version 1 remains readable and is marked `unattested`. A manifest is a self-consistent build record, not a cryptographic compiler attestation.

## Real build and proof smoke

- Clean source commit: `7cd0e9076dd1e59267c1a25c16462b5dec4b774e` on the focused prepared quadratic wipe branch.
- Build: offline, locked Cargo `ci` profile, no optional features, `xark-groth16` `bench_prove`, in a new target directory with Rust/Cargo 1.94.1 on `x86_64-apple-darwin`.
- Cargo.lock SHA256: `851637cbc3f13c6976dbbc5bcc126d380b0757e2ede3eb1f774c30c68e36f51d`.
- Executable SHA256: `f02272bed2889c1696c4c0d339406282765aba84277da29c82df8b7fd41edfd0`, size 5,761,064 bytes.
- [Raw build manifest](manifest.json), SHA256 `f62b9c9f312e92b712c3b1d4cd0cf6313c7490a0bd0d21ffc0c77d6f5b5e9aa5`, was rechecked against the source checkout and executable through the harness's `xark_build_record` path.
- The newly built executable ran one warmup and two measured complete synthetic proofs for each of escrow and withdrawal. Its own output reports Arkworks and Xark verification for both arms and both circuits. [Escrow output](escrow.stderr) · [Withdrawal output](withdrawal.stderr). This smoke does not exercise altered-statement rejection, which is covered by separate complete-request regressions; it does not establish a speed comparison.
- Fifteen Python harness tests passed, including build-manifest tampering and version-2 enforcement; one archived-receipt test was intentionally skipped because the optional archive environment variable was absent. Ruff lint/format and JSON syntax checks passed. `cargo fmt --all --check`, all 26 Groth16 `prover` tests and strict Groth16 Clippy across all targets passed with the locked offline dependency cache.

The first offline attempt used the default Cargo home and failed before compilation because `ark-relations` was missing; [failure log](failed-default-cache.stderr). The successful attempt used the prepared locked dependency cache and a *new* target directory. [Successful Cargo log](build.stderr). Brain triage case `72c7851969caa4bc` records this resolved environment issue.

The Mac is shared and this run lacks a same-binary host control. Timings in the smoke outputs are diagnostics only. A qualified Linux host is still required for competitive latency and throughput claims.
