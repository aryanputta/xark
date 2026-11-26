# Privacy Rings ICICLE CPU query benchmark

The benchmark reads the verified escrow and withdrawal `XKQMSM01` exports produced by
`bench_prove query-msm-export`. It executes the B1 (BN254 G1) and B2 (BN254 G2)
query MSMs on ICICLE v4's CPU backend. It checks both outputs against the Arkworks
points in the bundle before emitting any samples. The results describe individual
query MSMs.

Use only the already validated test-fixture bundles. They contain witness-derived
scalars. Keep them private to the benchmark host. The adapter checks framing,
canonical fields, curve equations and the constant-one scalar. Subgroup assurance
comes from the trusted exporter and the existing Gnark bundle validation. Verify
the bundle hash against the checked-in fixture receipt before each run.

## Existing Colab CPU build

Use the v4.0.0 source pin `6c77775961b0e4dc2be359feec1ac11536c18043` and the
existing source-built install. Set `ICICLE_SOURCE` to its checkout and
`ICICLE_PREFIX` to `/content/xark-competitors/icicle-install`.

```sh
bench=benches/privacy-rings-icicle
OUT=$(mktemp -d /content/xark-icicle-query.XXXXXX)
test "$(git -C "$ICICLE_SOURCE" rev-parse HEAD)" = 6c77775961b0e4dc2be359feec1ac11536c18043
libs="$ICICLE_PREFIX/lib"
nm -D --defined-only "$libs/libicicle_curve_bn254.so" | grep -E '[[:space:]]bn254_msm$'
nm -D --defined-only "$libs/libicicle_curve_bn254.so" | grep -E '[[:space:]]bn254_g2_msm$'
c++ -std=c++17 -O3 -I"$ICICLE_SOURCE/icicle/include" \
  "$bench/query_msm.cpp" -L"$libs" -Wl,-rpath,"$libs" -Wl,--no-as-needed \
  -licicle_curve_bn254 -licicle_field_bn254 -licicle_hash -licicle_device -pthread \
  -o "$OUT/icicle-query-msm"
c++ -std=c++17 -Wall -Wextra -Werror "$bench/query_bundle_test.cpp" -o "$OUT/query-bundle-test"
"$OUT/query-bundle-test"
ldd "$OUT/icicle-query-msm"
sha256sum "$OUT/icicle-query-msm" "$libs"/libicicle_{curve_bn254,field_bn254,hash,device}.so
```

Use the existing G1 smoke adapter's header search paths and link configuration if
the local installation differs. Both symbols must be present. An install without
G2 support requires a separately verified build with `-DG2=ON`.

On the quiet host used for the Xark/Gnark comparison, with the same CPU affinity,
set `VECTOR_DIR` to the directory containing both verified exports and their
`.sha256` receipts. Run both fixtures with three warmups and 30 measured samples
per query.

```sh
cd "$VECTOR_DIR"
for fixture in escrow withdrawal; do
  awk -v file="$fixture.test-vector" '$2 == file' "$fixture.sha256" | sha256sum -c -
  "$OUT/icicle-query-msm" "$fixture.test-vector" 2 30 3 > "$OUT/$fixture-icicle.log"
  test "$(grep -c '^query msm icicle: query=b1 ' "$OUT/$fixture-icicle.log")" -eq 30
  test "$(grep -c '^query msm icicle: query=b2 ' "$OUT/$fixture-icicle.log")" -eq 30
  awk -v file="$fixture.test-vector" '$2 == file' "$fixture.sha256" | sha256sum -c -
done
```

For speed comparisons, run the matching Xark mode on that host in reversed
process orders and check the host for overlap. Record source and binary hashes,
compiler flags, SMT topology, affinity and the worker configuration. ICICLE's
`n_threads` limits workers to the specified cap. Its backend may select fewer
workers. Timings cover a synchronous, precomputation-free MSM API call with
canonical resident host inputs and a projective result, including the CPU
backend's own per-call construction and scratch allocation. Parsing, validation,
affine normalization and equality checks happen outside the measured interval.
