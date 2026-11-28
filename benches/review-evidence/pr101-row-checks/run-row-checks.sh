#!/usr/bin/env bash
set -euo pipefail
umask 077
source "$HOME/.cargo/env"
bundle=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
(cd "$bundle" && sha256sum -c row-checks.sha256)
root=/content/xark-sprint-run
run=$(mktemp -d /content/xark-compiled-rows.XXXXXX)
echo "RUN_DIR=$run"
cd "$run"
cp -a "$root/xark" source
mkdir target
cp -a "$root/xark-target/release" target/
export CARGO_TARGET_DIR="$run/target" CARGO_BUILD_JOBS=2
cd source
git apply --check "$bundle/xark-row-checks.patch"
git apply "$bundle/xark-row-checks.patch"
{
    date -u
    uname -sm
    lscpu | grep -E '^(CPU\(s\)|Model name|Thread\(s\) per core|Core\(s\) per socket):'
    rustc -Vv
    git ls-remote https://github.com/blueshift-gg/xark.git 'refs/heads/xark-0.5' 'refs/heads/master' || true
} > "$run/host.log"
cargo build --locked --release -p xark-groth16 --example bench_prove > "$run/build.log" 2>&1
RUST_TEST_THREADS=1 cargo test --locked --release -p xark-groth16 --test prover > "$run/tests.log" 2>&1
echo REGRESSIONS_PASSED
bench="$CARGO_TARGET_DIR/release/examples/bench_prove"
sha256sum "$bench" "$bundle/xark-row-checks.patch" > "$run/binary.sha256"
cd "$run"
work='cargo|rustc|compile|go|cc1plus|cc1|cmake|make|clang-17|prover|privacy-rings-g|bench_prove'
if pgrep -x "$work" >/dev/null; then
    echo BENCHMARK_HOST_BUSY
    exit 1
fi
export RAYON_NUM_THREADS=2 BENCH_TIME=1 BENCH_WARM_BACKEND=cpu
unset BENCH_MERGE_BELOW NO_BATCH_AFFINE
for workload in escrow withdrawal; do
    circuit=$workload
    [[ $workload != withdrawal ]] || circuit=withdraw
    set -- "$root/$workload-witness"/*/inputs.json
    [[ $# == 1 && -s $1 ]]
    inputs=$1
    fixture=$(dirname "$inputs")
    xbc="$root/examples/escrow/xark/target/zk/timelock-escrow-program/$circuit/circuit.xbc"
    key="$root/$workload-test-key.bin"
    sha256sum "$xbc" "$key" "$inputs" "$fixture/public.json" "$fixture/public-changed.json" > "$workload.sha256"
    for trial in 1 2; do
        modes=(expanded 1)
        if [[ $trial == 2 ]]; then modes=(1 expanded); fi
        for method in "${modes[@]}"; do
            log="$workload-$trial-$method.log"
            BENCH_CHECK_ROWS="$method" BENCH_PUBLIC_STATEMENTS="$fixture" "$bench" warm "$xbc" "$key" "$inputs" 30 3 > "$log" 2>&1 &
            proof_pid=$!
            while kill -0 "$proof_pid" 2>/dev/null; do
                if pgrep -x "$work" | grep -vx "$proof_pid" >/dev/null; then
                    printf 'overlap %s %s %s\n' "$workload" "$trial" "$method" >> overlap.log
                fi
                sleep 1
            done
            wait "$proof_pid"
            grep -Fqx 'changed statement rejected by Arkworks and Xark for each backend' "$log"
            [[ $(grep -c '^warm prove:' "$log") == 30 ]]
            [[ $(grep -c '^warm row check:' "$log") == 30 ]]
            printf 'VERIFIED %s %s %s\n' "$workload" "$trial" "$method"
        done
    done
    sha256sum -c "$workload.sha256"
done
sha256sum -c binary.sha256
shopt -s nullglob
files=(./*.log ./*.sha256)
tar -czf /content/xark-compiled-row-check-evidence.tar.gz "${files[@]}"
sha256sum /content/xark-compiled-row-check-evidence.tar.gz
[[ ! -s overlap.log ]]
echo ROW_CHECK_COMPARISON_COMPLETE
