# Privacy Rings B1 on Constantine CPU

This adapter measures the B1 BN254 G1 query MSM on the exact escrow and
withdrawal inputs from `bench_prove query-msm-export`. Each bundle includes
the ordered witness scalars, proving-key bases, and independent Arkworks
references. Use the digest-verified benchmark exports and keep the raw
bundles private to the runtime.

The adapter checks the size, constant-one scalar, canonical fields, and G1
curve membership. The B2 fields are checked for canonical encoding. The
comparison covers B1, with subgroup assurance provided by the upstream
bundle export and independent bundle validation.

## Build in the existing Colab CPU runtime

Run from the Xark checkout containing this directory, or set `ADAPTER` to
the transferred directory. The build uses the existing checksum-verified
Nim 2.4.2 installation and the GCC flags from the completed stock smoke.

```bash
set -euo pipefail
umask 077
ADAPTER="${ADAPTER:-$(pwd)/benches/privacy-rings-constantine}"
CT=/content/xark-competitors/constantine
NIM=/content/xark-competitors/nim-2.4.2/bin/nim
OUT=$(mktemp -d /content/xark-constantine-b1.XXXXXX)
test "$(git -C "$CT" rev-parse HEAD)" = 4083170f19ec8dba15604bf0d443b5d852d634d6
git -C "$CT" diff --quiet HEAD
"$NIM" --version | tee "$OUT/nim.log"
grep -Fq 'git hash: b27dcb4f70883978e984e427cc24b64eeb7c875f' "$OUT/nim.log"
gcc --version > "$OUT/gcc.log"
"$NIM" c --path:"$CT" --cc:gcc --tlsEmulation=off -d:danger --panics:on \
  -d:noSignalHandler --mm:arc -d:useMalloc --passC:-fno-semantic-interposition \
  --passC:-falign-functions=64 --passC:-fmerge-all-constants \
  --nimcache:"$OUT/nimcache" -o:"$OUT/constantine-b1" "$ADAPTER/query_b1.nim" \
  > "$OUT/build.log" 2>&1
sha256sum "$ADAPTER/query_b1.nim" "$ADAPTER/check_rejection.py" \
  "$OUT/constantine-b1" > "$OUT/adapter.sha256"
```

## Replay on the existing two-vCPU host

Set `VECTOR_DIR` to the directory containing the verified `*.test-vector`
files from the Gnark or ICICLE replay. Confirm the host is quiet and use
the same two allowed CPU IDs for both implementations. Record the affinity
and SMT topology. Each process performs three warmups and 30 measured
iterations. Run mirrored pairs for each fixture to expose order effects.

```bash
XARK=/content/xark-gnark-query-msm.mj9T66/target/release/examples/bench_prove
ROOT=/content/xark-sprint-run
printf '%s  %s\n' 369a885a9240fe8680e03fff22b4f3b4a85eb09f347fda471de3eb04032d63dc "$XARK" |
  sha256sum -c -
CPUS=$(awk '/^Cpus_allowed_list:/ {print $2}' /proc/self/status)
{
  date -u
  uname -sm
  lscpu
  printf 'allowed CPUs %s\n' "$CPUS"
} > "$OUT/host.log"
export BENCH_TIME=1 RAYON_NUM_THREADS=2
unset BENCH_RESIDENT_PROFILE BENCH_CHECK_ROWS NO_BATCH_AFFINE NO_GLV CHECK BENCH_G2_WINDOW_DELTA
cd "$OUT"
for fixture in escrow withdrawal; do
  vector="$VECTOR_DIR/$fixture.test-vector"
  hash=617fcfa09ff2eb37b7c44535d0ceb8b9878b18d5ddca4b98c6feafdc4bbe2cbc
  circuit=escrow
  order=(xark constantine constantine xark)
  if [[ "$fixture" == withdrawal ]]; then
    hash=a9978e8bc01658ee04fe09b0bc261759ed41ce4f5c3c52c5d1f569a7a5414e0b
    circuit=withdraw
    order=(constantine xark xark constantine)
  fi
  printf '%s  %s\n' "$hash" "$vector" > "$fixture.vector.sha256"
  sha256sum -c "$fixture.vector.sha256"
  python3 "$ADAPTER/check_rejection.py" "$OUT/constantine-b1" "$vector" \
    > "$fixture-controls.log"
  xbc="$ROOT/examples/escrow/xark/target/zk/timelock-escrow-program/$circuit/circuit.xbc"
  key="$ROOT/$fixture-test-key.bin"
  inputs=("$ROOT/$fixture-witness"/*/inputs.json)
  [[ ${#inputs[@]} == 1 && -s ${inputs[0]} ]]
  statement=$(dirname "${inputs[0]}")
  sha256sum "$xbc" "$key" "${inputs[0]}" "$statement/public.json" > "$fixture.inputs.sha256"
  "$XARK" query-msm-export "$xbc" "$key" "$statement" "$fixture-reexport.test-vector" \
    > "$fixture-export.log"
  cmp -s "$vector" "$fixture-reexport.test-vector"
  for i in "${!order[@]}"; do
    mode=${order[i]}
    log="$fixture-$((i + 1))-$mode.log"
    if [[ "$mode" == xark ]]; then
      taskset -c "$CPUS" "$XARK" query-msm-xark "$xbc" "$key" "$statement" 30 3 > "$log"
      grep -Eq '^query msm xark verified: terms=[0-9]+ threads=2 samples=30 warmups=3 xark_glv=true xark_batch_affine=true$' "$log"
    else
      taskset -c "$CPUS" "$OUT/constantine-b1" "$vector" 2 30 3 > "$log"
      grep -Eq '^query msm constantine verified: terms=[0-9]+ threads=2 samples=30 warmups=3 ' "$log"
    fi
    [[ $(grep -c "^query msm $mode: query=b1 " "$log") == 30 ]]
  done
  sha256sum -c "$fixture.vector.sha256" "$fixture.inputs.sha256"
done
```

The control replaces the expected Arkworks B1 point with a different valid
B1 base from the same verified fixture. It requires exit 1, the specific
result-mismatch error, and empty stdout. It also checks rejection of an
out-of-range field, a truncated bundle and trailing bytes. Temporary control
bundles stay in the runtime and are removed by the control process.
The Xark re-exports match the shared bundles byte for byte and also stay
in the runtime.

Measurements cover one synchronous B1 MSM call with a Jacobian output.
The Constantine pool is created once and includes the caller in its two
threads. Input parsing, canonical-to-Montgomery coordinate conversion,
result normalization and Arkworks equality checks are outside the timer.
Report descriptive per-process B1 medians by fixture and order with host
and toolchain receipts. Xark B2 rows are excluded from this comparison.
