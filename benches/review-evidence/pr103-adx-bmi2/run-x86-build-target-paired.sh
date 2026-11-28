#!/usr/bin/env bash
set -euo pipefail
umask 077

portable=${1:?portable Xark benchmark binary}
targeted=${2:?ADX/BMI2 Xark benchmark binary}
root=/content/xark-sprint-run
out=$(mktemp -d /content/xark-x86-build-target.XXXXXX)
echo "X86_TARGET_DIR=$out"
cd "$out"
archive() {
    local rc=$?
    shopt -s nullglob
    local files=(./*.log ./*.sha256)
    tar -czf /content/xark-x86-build-target.tar.gz "${files[@]}"
    sha256sum /content/xark-x86-build-target.tar.gz
    echo "X86_TARGET_EXIT=$rc"
}
trap archive EXIT
work='cargo|rustc|compile|go|cc1plus|cc1|cmake|make|clang-17|prover|privacy-rings-g|bench_prove|xark'
if pgrep -x "$work" > initial-processes.log; then
    echo X86_TARGET_HOST_BUSY
    exit 1
fi
grep -qw adx /proc/cpuinfo
grep -qw bmi2 /proc/cpuinfo
{ date -u; uname -sm; lscpu | grep -E '^(CPU\(s\)|Model name|Thread\(s\) per core|Core\(s\) per socket):'; } > host.log
sha256sum "$portable" "$targeted" > binary.sha256
export BENCH_TIME=1 BENCH_WARM_BACKEND=cpu BENCH_CHECK_ROWS=1 BENCH_MERGE_BELOW=0
unset BENCH_RESIDENT_PROFILE NO_BATCH_AFFINE
run_proofs() {
    local log=$1 bench=$2 samples=$3 pid other
    "$bench" warm "$xbc" "$key" "$inputs" "$samples" 3 > "$log" 2>&1 &
    pid=$!
    while kill -0 "$pid" 2>/dev/null; do
        other=$(pgrep -x "$work" | grep -vx "$pid" || true)
        if [[ -n $other ]]; then
            printf 'overlap %s %s\n' "$log" "$other" >> overlap.log
        fi
        sleep 1
    done
    wait "$pid"
    grep -Fqx 'changed statement rejected by Arkworks and Xark for each backend' "$log"
    grep -Eq '^resident CPU: .* merged=false$' "$log"
    grep -Fqx 'resident includes row checks: true' "$log"
    [[ $(grep -c '^warm prove:' "$log") == "$samples" ]]
    printf 'VERIFIED %s\n' "$log"
}
for w in escrow withdrawal; do
    c=$w
    [[ $w != withdrawal ]] || c=withdraw
    set -- "$root/$w-witness"/*/inputs.json
    [[ $# == 1 && -s $1 ]]
    inputs=$1
    export BENCH_PUBLIC_STATEMENTS=$(dirname "$inputs")
    xbc="$root/examples/escrow/xark/target/zk/timelock-escrow-program/$c/circuit.xbc"
    key="$root/$w-test-key.bin"
    sha256sum "$xbc" "$key" "$inputs" "$BENCH_PUBLIC_STATEMENTS/public.json" "$BENCH_PUBLIC_STATEMENTS/public-changed.json" > "$w.sha256"
    export RAYON_NUM_THREADS=2
    order=(portable targeted targeted portable)
    if [[ $w == withdrawal ]]; then
        order=(targeted portable portable targeted)
    fi
    for index in "${!order[@]}"; do
        mode=${order[index]}
        run_proofs "$w-$((index + 1))-$mode.log" "${!mode}" 30
    done
    sha256sum -c "$w.sha256"
done
sha256sum -c binary.sha256
[[ ! -s overlap.log ]]
echo X86_TARGET_COMPLETE
