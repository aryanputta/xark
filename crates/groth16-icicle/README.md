# ICICLE G1 MSM adapter (validation pending)

This crate isolates the ICICLE v4 G1 MSM adapter authored for Xark PR #47 and
connects it to Xark 0.5's `Accelerator` interface. It requests only G1 MSMs.
G2 MSMs and every other prover stage use Xark's CPU implementation. The crate
does not add a CLI option or replace Xark 0.5's OpenCL backend.

The ICICLE dependency is pinned to commit
`6c77775961b0e4dc2be359feec1ac11536c18043`. The host test suite covers
field conversion, canonical scalar rejection, point decoding, malformed input,
chunk boundaries, and proof equivalence with verification. On a machine without
a CUDA device, the proof test exercises the CPU fallback. It cannot establish
that ICICLE processed any MSM work.

Validation required before asking for review or making performance claims:

1. Fetch the pinned ICICLE revision and run
   `cargo test -p xark-groth16-icicle` and
   `cargo clippy -p xark-groth16-icicle --all-targets -- -D warnings`.
2. On an NVIDIA device with ICICLE CUDA backend installed, record the device
   model and driver, prove and verify a representative circuit, and instrument
   ICICLE MSM dispatch to prove that the GPU processed G1 work.
3. Separately run the same proof with CUDA unavailable to verify CPU fallback.
   Run a CUDA sanitizer before reporting device safety. Benchmark only with
   matched fixtures, thread budget, proof verification, and raw samples.

The adapter has no audited constant-time or GPU memory-erasure guarantee.
