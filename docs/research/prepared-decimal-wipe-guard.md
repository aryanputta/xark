# Prepared prover decimal witness cleanup

Source branch: `fix/prepared-decimal-wipe-guard`, based on `fix/prepared-witness-scratch-wipe` at `d6e6649` (which already contains the prepared CPU prover and dense witness cleanup). The prior `PreparedCpuProver::prove` manually zeroized converted decimal witness strings after `solve_verify` returned, including ordinary errors. A panic or unwind inside that call skipped the manual cleanup. A request-local `RequestDecimals` guard now zeroizes every string in `Drop`; the normal path explicitly drops it immediately after solving, before proof generation. The map is never shared or retained by the prepared prover.

This is a narrow cleanup hardening, not a speed optimization. It does not add another wipe on successful requests. It does not prove full witness erasure: solver frame temporaries, other field copies, allocator remnants, registers, swap, crash dumps and variable-time arithmetic remain outside this guard. It does not establish constant-time behavior or safety against an untrusted prover operator.

Executed on the local Mac with locked offline Cargo dependencies:

- `cargo test --offline --locked -p xark-prover request_decimal_values_are_cleared_in_place`: 1 passed. The unit test checks that both request strings are emptied in place.
- `cargo test --offline --locked -p xark-groth16 --test prover prepared_cpu_prover_checks_and_isolates_typed_requests -- --nocapture`: 1 passed. This covers malformed key rejection, concurrent distinct requests, fresh proof randomness, independent Arkworks and Xark verification and altered/cross-request rejection.
- `cargo test --offline --locked -p xark-prover --lib`: 13 passed.
- `cargo clippy --offline --locked -p xark-prover -p xark-ir --all-targets -- -D warnings`: passed.
- `cargo fmt --all -- --check`, `git diff --check` and `graphify update .`: passed.

The current sandbox denied the existing Colima host-agent socket (`operation not permitted`), and the configured Rutgers Linux host did not resolve. Neither failure is a proof result. Existing shared-host timings remain insufficient for a production speed claim. No performance measurement or full security review was added by this branch.
