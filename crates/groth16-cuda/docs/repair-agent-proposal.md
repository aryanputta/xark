# Optional idea: proof-gated repair agent for GPU MSM

This is a proposal for a later, optional CI experiment. It does not change the
prover or enable automated code changes.

An agent could help investigate a failed CUDA MSM change and prepare one patch
for review. A separate verifier would decide whether that patch is ready for a
human to inspect. The agent must not supply its own test results or change the
verification rules.

## Verification contract

The verifier should run from a trusted checkout of the base branch and use a
fixed test suite. A candidate is ready for review only after all of these pass:

1. Rust formatting and the adapter's host-side representation tests.
2. A required GPU MSM comparison against Xark's CPU Pippenger, including edge
   cases and deterministic full-width scalars.
3. A fixed-randomness CPU/GPU proof comparison and successful verification of
   the resulting proof.
4. Any GPU memory or race checks supported by the selected runner.

The GPU tests must fail when the required CUDA device is unavailable. A skipped
test is not evidence that the change is correct. The verifier should record the
commit, GPU model, driver and toolkit versions, exact commands, and results.

## Failure handling

The first version should report failures without editing code. If maintainers
later want automatic recovery, limit it to one retry for a recognized setup
failure that occurred before compilation or tests began. A compiler error, test
failure, MSM mismatch, proof failure, CUDA runtime error, timeout, or unknown
failure should stop the run for a person to review.

An agent may propose one patch in an isolated checkout. It must not edit the
verifier, its test vectors, workflow permissions, or the protected acceptance
tests. The verifier reruns the fixed suite independently. Passing checks makes
the patch reviewable; it never merges or pushes it.

## Runner boundary

Pull request code is untrusted. The job must use an ephemeral runner with no
repository secrets, no write token, and no access to a persistent GPU host. The
workflow and verifier must come from the trusted base revision, not from the
candidate patch. If those conditions cannot be provided, keep the workflow
report-only and require a maintainer to run the GPU suite manually.

The first implementation step should be a report-only failure classifier. A
repair loop should be considered only after the GPU MSM and proof-equivalence
tests run reliably on a suitable isolated runner.
