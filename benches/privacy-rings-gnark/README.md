# Matched Privacy Rings proof benchmark

This benchmark compares the same ordered reduced BN254 rows and solved witness
on Xark and Gnark. It uses separate setup keys for each proving system and
keeps native application comparisons in a separate cohort.

From the Xark source checkout on a dependency-connected machine, build the
resident benchmark and use the pinned Privacy Rings inputs. The directory
passed to `export-iden3` must be new. The exported witness contains all
private and derived values, so keep it in the benchmark runtime.

```sh
cargo build --locked --release -p xark-groth16 --example bench_prove
CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-target}
bench="$CARGO_TARGET_DIR/release/examples/bench_prove"
"$bench" export-iden3 "$XBC" "$FIXTURE" "$EXPORT_DIR"
"$bench" setup-reduced "$XBC" "$TEST_PK"
```

Set `XBC` to the circuit artifact matching the escrow or withdrawal fixture.
Set `FIXTURE` to the directory with the SDK's `inputs.json`, `public.json`
and `public-changed.json`. Keep the compiler revision in the run receipt.
The Xark key in the example is deterministic and for test use only.

Run both resident provers with the same thread budget and samples. Set
`BENCH_CHECK_ROWS=1` for Xark to include row checks. Gnark's prover checks
the supplied witness by default. Both time those checks and proving after
setup and witness generation, then verify every sample outside the timer.

```sh
BENCH_TIME=1 BENCH_WARM_BACKEND=cpu BENCH_CHECK_ROWS=1 \
  BENCH_PUBLIC_STATEMENTS="$FIXTURE" RAYON_NUM_THREADS="$THREADS" \
  "$bench" warm "$XBC" "$TEST_PK" "$FIXTURE/inputs.json" 100 3

(cd benches/privacy-rings-gnark && go build -mod=readonly -o "$GNARK_BIN" .)
"$GNARK_BIN" "$EXPORT_DIR/circuit.r1cs" "$EXPORT_DIR/witness.wtns" \
  "$FIXTURE/public.json" "$FIXTURE/public-changed.json" "$THREADS" 100 3
```

Before comparing raw samples, match exported row and wire counts to Gnark's
receipt and confirm the same hashes and thread settings. Record the actual
radix-2 domain and the implementation's row-check cost. Repeat in both
process orders on the same hardware. Gnark's statements and samples appear
only after all of its proofs verify and the changed statement is rejected.

The iden3 binary codec and Go reader are adapted from the MIT-licensed Xark
exporter at `zz-sol/xark@160ee0af97c434044961037886b445fc4aec6982`.
The Go module keeps that source's Gnark v0.14.0 dependency pin.
