# B2 optimization research

The research branch starts from Xark 0.5 commit `03a7f519d28df6718f7ce6dda41f1e57e5ea55db`. Candidate binaries can use the published sprint benchmark companion at `dc8ad92`, which exports ordered B1/B2 data and independently checks complete proofs. The performance target is a reproducible B2 improvement of 20–40% and at least 10% end-to-end on the selected Privacy Rings workload.

Upstream already includes GLV, tuned batch-affine windows, queued affine conflicts and parallel resident MSM and quotient work. The comparison in PR #91 covered PR #84's circuits. The paired results below use the separate Privacy Rings fixtures and their stated checking boundary. PR #47 covers GPU backends. PRs #97–#103 cover key validation, test staging, cache safety, witness-row evaluation, OpenCL test setup and x86 build documentation. The candidate work here targets the native G2 kernel. [Existing prover optimization](https://github.com/blueshift-gg/xark/commit/0822bfb) · [GPU PR](https://github.com/blueshift-gg/xark/pull/47)

## Reconstruct the evidence

```sh
python3 benches/g2/reconstruct.py "$HOME/Downloads" /tmp/xark-g2-evidence
```

The tool checks the eleven original archive digests, reads validated regular members directly and writes only numeric results and fingerprints. `samples.csv` preserves run, archive member, workload, backend, timing scope, raw samples, task offsets, and sampled RSS. `reconstructed.json` includes per-cohort medians and p95, artifact and host-log fingerprints, and the last timed top-level proving task in each profiled proof. Guest process guards, compiler settings and binary provenance remain in the associated archive logs. Archives are benchmark test material. Keep the fixture data and witness-derived query scalars on the trusted machine.

## Baseline and ranked bottlenecks

The most comparable B2 baseline is the pinned ADX/BMI2 Xark and Gnark Crypto A/B, with two worker threads sharing one physical Xeon core, identical ordered BN254 inputs and projective outputs checked against Arkworks. Each arm used 30 measured samples.

| Real workload | Xark B2 p50 | Gnark Crypto B2 p50 | Interpretation |
| --- | ---: | ---: | --- |
| Withdrawal | 99.3–100.4 ms | 86.1–86.2 ms | Xark trailed by 13.2–14.2 ms in both orders. |
| Escrow | 129.6–209.5 ms | 107.5–191.5 ms | The faster implementation changed with order. |

In the separate full-proof A/B, targeted Xark trailed Gnark by 8.7–18.9 ms for withdrawal and 25.6–26.8 ms for escrow. The B2 and proof intervals differ. The measured task spans overlap, so the B2 difference cannot simply be subtracted from proof latency.

1. **G2 bucket arithmetic and affine flush.** The targeted withdrawal proof stack sample had G2 MSM ancestry in 32.47% of CPU samples and a G2 affine flush in 18.63%. Fq two-product work within the G2 flush accounted for 10.82% of proof-process samples. The categories overlap, and an inlined operation can disappear into another symbol.
2. **Task completion order.** In the two-worker instrumented run, B2 finished last in 15 of 15 escrow proofs and four of 15 withdrawal proofs. B1 finished last in the remaining 11 withdrawals. At one worker, H finished last in all 30. The highlighted 135 ms withdrawal B2 sample came from the one-worker profile. Actual critical-path savings depend on the workload and schedule.
3. **Scalar recoding, allocation, and synchronization.** The current receipts do not isolate per-phase elapsed time for these. The symbol pass recovered 89 point-addition, 36 Fq2-squaring, 15 base-field inversion, 52 bucket-loop, and eight whole-process synchronization leaf samples from the checked proof. It left 291 G2 samples unclassified. An absent allocation or recoding symbol can reflect inlining or sampling. A fresh Linux profile needs coarse recoding and bucket checkpoints before allocating effort to these phases.

```sh
python3 benches/g2/profile.py "$HOME/Downloads/aaa-xark-linux-withdrawal-profile.tar.gz"
```

## Experiments and decisions

| Experiment | Reconstructed result | Decision |
| --- | --- | --- |
| One-step window width changes | Kernel medians and tails varied across reversed orders. | Keep the modeled default. A new test needs an occupancy-based predictor and stable paired controls. |
| Fq2 Karatsuba | All 480 measured full proofs verified. Median proving grew 1.0–7.9% across four pairs. | Retain the existing Fq2 multiplication. |
| Disabling batch affine | Checked proving p50 grew 25–29%. | Keep batch affine. Target the work inside flush rather than turning it off. |
| Raising the MSM merge cutoff | Withdrawal p50 gained 2.9–7.3%, with 15–16% higher sampled peak RSS. Escrow reversed with order. | Keep the split default. |
| Moving B2 earlier | Earlier completion shifted the longest task, while a withdrawal run regressed p50 by 20%. | Retain existing scheduling. |
| Two independent G2 denominator chains | The opt-in candidate splits the forward and reverse product chains and computes both lane inverses from one shared Fq2 inversion. It adds three products per multi-entry batch. Debug tests matched eight real B1/B2 outputs against Arkworks. Both verifiers accepted four complete proofs and rejected four altered statements. | Proceed to the release benchmark with fixed window policy. [Candidate branch](https://github.com/aryanputta/xark/tree/perf/privacy-rings-g2-inverse-lanes) |
| Immutable G2 endomorphism coordinates | An opt-in candidate reuses only the transformed x-coordinate of each proving-key base. It estimates roughly 476 KiB for escrow and 338 KiB for withdrawal. | Measure query-level latency and cold preparation cost first. |

The archived witness statement and circuit manifests anchor all prover-only comparisons. The new candidates are isolated. User-derived scalars and buckets stay request-local. Benchmark receipts and vectors never belong in production logs. Production proving keeps fresh cryptographic randomness. Neither passing proofs nor equivalent group outputs establish constant-time behavior. Existing scalar-dependent work needs separate side-channel review for co-tenant deployments.

## Competitor source notes

- **Gnark Crypto.** The pinned G2 MSM generator uses width-specialized chunk implementations and identifies G2 cache footprint and cross-word scalar extraction as separate choices. The first transferable hypothesis is a bucket footprint change measured at a fixed width. The archived withdrawal comparison is the matched G2 result. [Gnark Crypto v0.19.0 G2 MSM](https://github.com/Consensys/gnark-crypto/blob/v0.19.0/ecc/bn254/multiexp.go)
- **Arkworks.** The shared variable-base module provides the independent MSM reference. The correctness benchmark compares normalized group elements so differing projective representatives remain valid. [Arkworks variable-base MSM](https://github.com/arkworks-rs/algebra/blob/master/ec/src/scalar_mul/variable_base/mod.rs)
- **Constantine and Rapidsnark.** The saved Constantine experiment measures B1 only. The saved Rapidsnark experiment measures its resident prover C ABI and includes witness parsing and proof JSON output. A common G2 comparison requires per-library adapters over the same validated vectors. These observations do not support a four-way G2 ranking. [Constantine pin](https://github.com/mratsim/constantine/tree/4083170f19ec8dba15604bf0d443b5d852d634d6) · [Rapidsnark pin](https://github.com/iden3/rapidsnark/tree/81eddf1a536d26497b237c0b8a04fe90baf7e439)

The candidates implement separate hypotheses in Xark code. Competitor implementations remain in their own repositories and retain their licenses. Seeded synthetic subgroup points can isolate arithmetic and boundary behavior. Promotion requires real held-out workloads and verified complete proofs.

## Run the tuning screen

Use the [paired benchmark runner](https://github.com/aryanputta/xark/tree/review/competitive-benchmark-harness-v05/benches/competitive). Define a plan with one factor per item.

```json
[
  {
    "name": "inverse-lanes",
    "factor": "G2 denominator product chain width",
    "config": "inverse-lanes.json"
  }
]
```

The runner config pins both Xark revisions, fixture digests and binary paths, and may select one candidate-only environment value. For the same-binary inverse-chain experiment, use `BENCH_G2_INVERSE_LANES=2` in `candidate.environment` and expect `bench g2 inverse lanes: 2` as its receipt. The baseline uses the feature's default of one chain.

```sh
python3 benches/g2/tune.py --runner /path/to/competitive/run.py \
  --plan /bench/g2-plan.json --output /bench/g2-screen \
  --tune-workload withdrawal --threads 2 --samples 100
```

The screen tests B2 first with reversed process order on the chosen workload. A candidate reaches full proofs only if both pairs clear the B2 median and tail gate. The proof screen measures the tuning workload and the other Privacy Rings workload, checks paired p50 and p95 plus sampled Linux RSS, and records every attempted stage and its exit status. Candidates that pass are ranked by their worst paired proof median ratio, then their worst B2 median ratio, then sampled memory. The other Privacy Rings circuit is a holdout for this screen. A separate application circuit is needed to validate generalization. Use `--smoke` only to exercise the pipeline. Cold proving, sustained throughput and independent hardware are further acceptance gates. The tool never changes a production default.

## Verified release checkpoint

The exact portable release binary of the inverse-chain candidate produced four checked withdrawal B2 samples and eight complete proofs across escrow and withdrawal in the automated smoke. The full proofs passed Xark and Arkworks and rejected the altered statements. Both focused boundary tests and strict feature-on Clippy passed. The separate fixed-base prototype verified six pairs of real B2 inputs and rejected both malformed controls before reporting timings. Its retained coordinate payload measured 486,784 bytes for escrow and 345,984 bytes for withdrawal. [Fixed-base candidate](https://github.com/aryanputta/xark/tree/perf/g2-b2-fixed-base) · [Inverse-chain hosted checks](https://github.com/aryanputta/xark/actions/runs/45762462934)

Process monitoring was unavailable on the native workstation and the host showed competing load. The strict preflight refused to start measurements, and the smoke reported no performance winner. Keep both experiments separate from production until a pinned Linux replay provides eligible paired medians, tails, and memory results.

## Expanded timing diagnostic

The native replay measured 120 verified withdrawal B2 samples and 120 independently verified withdrawal proofs. Two-chain B2 p50 improved 7.71% in one order and regressed 4.74% in the other. Full-proof p50 moved −2.13% and −1.40%, while p95 moved −23.88% and +13.24%. The unchanged B1 control moved about −29% and +39%, and the host monitor was inaccessible. A separate fixed-base replay checked 30 alternating-order pairs for each fixture. Its median within-pair B2 change was −1.68% for escrow and −0.36% for withdrawal. The withdrawal change reversed across order groups. These native results lack an eligible speed improvement.

[The pinned Colab replay](run-colab.sh) uses the original fixture fingerprints, the same release binary across both arms, two CPU workers, strict host monitoring, and independently verified B2 and complete-proof results. It records compiler flags and affinity for comparison with earlier runs. The synthetic adapter also passed five release tests and exported a byte-identical Arkworks-checked vector accepted by the ICICLE framing reader. [Synthetic adapter](https://github.com/aryanputta/xark/tree/perf/synthetic-query-msm-v05)
