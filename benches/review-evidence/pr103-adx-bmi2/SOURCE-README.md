# ADX and BMI2 Xark release build compared with portable Xark

## Paired setup

The two Linux executables have the same `5a3217d` source, lockfile, Rust 1.100.0 and release settings. The targeted build sets `RUSTFLAGS="-C target-feature=+adx,+bmi2"`. Both builds use the default Arkworks feature configuration. The [previous sweep](../2026-11-25-colab-ark-ff-asm/README.md) isolated the separate Arkworks Cargo feature.

One Intel Xeon 2.20 GHz core presented two SMT siblings. The host advertised both target features and each process used two Rayon workers. Keys, circuits, public statements and witnesses match the prior verified runs. Each process began with three warmups and timed 30 resident proofs with compiled row checks and split MSMs. Each fixture ran in both process orders. The visible-process guard recorded no overlap. Both Xark and Arkworks accepted all 240 measured proofs and rejected the altered statement in all eight cohorts. [Host](host.log) · [Binary hashes](binary.sha256) · [Runner](run-x86-build-target-paired.sh)

## Results

| Circuit | Order | Portable p50 / p95 | Targeted p50 / p95 | Targeted p50 reduction | Targeted p95 reduction |
| --- | --- | ---: | ---: | ---: | ---: |
| Escrow | Portable, targeted | 424.238 / 774.840 ms | 362.827 / 664.758 ms | 14.48% | 14.21% |
| Escrow | Targeted, portable | 434.322 / 742.822 ms | 358.673 / 652.593 ms | 17.42% | 12.15% |
| Withdrawal | Targeted, portable | 345.130 / 663.411 ms | 305.164 / 576.633 ms | 11.58% | 13.08% |
| Withdrawal | Portable, targeted | 357.167 / 662.480 ms | 298.318 / 545.223 ms | 16.48% | 17.70% |

These pairs measure the combined compiler target flags on this CPU. Both observed tails improved, using an exploratory p95 based on 30 samples. The next comparison uses the same targeted binary against Gnark with checked rows and resident artifacts.

The build recipe applies to qualified CPUs. Use portable builds when the deployment fleet mixes CPUs with different instruction support. The review at `cb135d8` documents the validated benchmark build and leaves CPU targeting opt-in. Test the intended deployment CPU before distributing a targeted binary. [PR draft](../../../reviews/x86-resident-prover-build.md)

## Replay

Use the same source tree and Rust version for both builds. The eight-arm runner verifies each cohort and retains its rows.

```sh
CARGO_TARGET_DIR=/tmp/portable-proof cargo build --locked --release -p xark-groth16 --example bench_prove
CARGO_TARGET_DIR=/tmp/targeted-proof RUSTFLAGS="-C target-feature=+adx,+bmi2" \
  cargo build --locked --release -p xark-groth16 --example bench_prove
bash run-x86-build-target-paired.sh \
  /tmp/portable-proof/release/examples/bench_prove \
  /tmp/targeted-proof/release/examples/bench_prove
```

Raw archive SHA-256 `19f908f25ad70ab948760cd35d23289cc9aae10053e42d2ef44af772f50a141e`.
