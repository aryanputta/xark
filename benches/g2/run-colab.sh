#!/usr/bin/env bash
# Run a same-binary Privacy Rings comparison on a Colab Linux CPU runtime.
set -euo pipefail
umask 077

archive=${1:?provide the uploaded aaa-xark-offline-fixtures.tar.gz}
out=${2:?provide a new output directory}
samples=${3:-30}
candidate=1dc7867c873f8d9f5b8cef5e6cbca61a25ae7c07
runner=225735659def0780b268e481794a24d1e3196eea
examples=9e5d69ade7e0c107a2929306d3b758a8969e1089
fixture_hash=82caa7cee2b155afc2bd32cdc9661ba8cfb758888f4837bf9d6af31eb05c36a7

[[ -f "$archive" ]] || { echo "Fixture archive was not uploaded" >&2; exit 1; }
[[ "$samples" =~ ^[0-9]+$ && "$samples" -ge 30 ]] || { echo "At least 30 samples required" >&2; exit 1; }
printf '%s  %s\n' "$fixture_hash" "$archive" | sha256sum --check --status
archive=$(cd "$(dirname "$archive")" && pwd)/$(basename "$archive")

mkdir "$out"
out=$(cd "$out" && pwd)
workspace=${XARK_COLAB_WORKSPACE:-/content}
cd "$workspace"

pin_checkout() {
    local repository=$1 branch=$2 revision=$3 checkout=$4
    if [[ ! -d "$checkout/.git" ]]; then
        git clone --depth 1 --branch "$branch" "$repository" "$checkout"
    fi
    [[ $(git -C "$checkout" rev-parse HEAD) == "$revision" ]]
}

pin_checkout https://github.com/aryanputta/xark.git perf/privacy-rings-g2-inverse-lanes "$candidate" xark-g2
pin_checkout https://github.com/aryanputta/xark.git review/competitive-benchmark-harness-v05 "$runner" xark-bench-runner
if [[ ! -d xark-privacy-examples/.git ]]; then
    git init -q xark-privacy-examples
    git -C xark-privacy-examples fetch --depth 1 https://github.com/helius-labs/privacy-ring-examples.git "$examples"
    git -C xark-privacy-examples checkout --detach FETCH_HEAD
fi
[[ $(git -C xark-privacy-examples rev-parse HEAD) == "$examples" ]]

export PATH="$HOME/.cargo/bin:$PATH"
if ! command -v rustup >/dev/null; then
    curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain none
fi
rustup toolchain install 1.94.1 --profile minimal
if grep -qm1 '\badx\b' /proc/cpuinfo && grep -qm1 '\bbmi2\b' /proc/cpuinfo; then
    export RUSTFLAGS="-C target-feature=+adx,+bmi2"
else
    unset RUSTFLAGS
fi
(
    cd xark-g2
    rustup run 1.94.1 cargo build --locked --release -j 2 -p xark-groth16 \
        --features msm-g2-inverse-bench --example bench_prove
) 2>&1 | tee "$out/build.log"

python3 - "$archive" "$out" "$candidate" "$examples" <<'PY'
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tarfile

archive, output, commit, examples = sys.argv[1:]
root = Path.cwd()
output = Path(output)
fixture = output / "fixtures"
fixture.mkdir()
manifest = root / "xark-bench-runner/benches/competitive/fixtures.sha256"
expected = {name: digest for digest, name in (line.split() for line in manifest.read_text().splitlines())}
with tarfile.open(archive, "r:gz") as data:
    seen = set()
    for member in data:
        name = str(PurePosixPath(member.name))
        if name not in expected:
            continue
        if not member.isfile() or name in seen or member.size > 2 * 1024 * 1024:
            raise ValueError(f"invalid fixture archive member {name}")
        with data.extractfile(member) as stream:
            contents = stream.read()
        if hashlib.sha256(contents).hexdigest() != expected[name]:
            raise ValueError(f"fixture fingerprint mismatch: {name}")
        path = fixture / name
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(contents)
        seen.add(name)
if seen != expected.keys():
    raise ValueError("fixture archive is incomplete")

allowed = sorted(os.sched_getaffinity(0))
assert len(allowed) >= 2, "paired comparison requires two visible logical CPUs"
cores = {}
for line in subprocess.check_output(["lscpu", "-p=CPU,CORE,SOCKET"], text=True).splitlines():
    if line.startswith("#"):
        continue
    cpu, core, socket = line.split(",")
    if int(cpu) in allowed:
        cores.setdefault((core, socket), []).append(int(cpu))
cpus = next((pair[:2] for pair in cores.values() if len(pair) >= 2), allowed[:2])
(output / "affinity.txt").write_text(",".join(map(str, cpus)) + "\n")

xark = {"path": str(root / "xark-g2"), "commit": commit}
binary = str(root / "xark-g2/target/release/examples/bench_prove")
config = {
    "version": 1, "fixtures": str(fixture),
    "sources": {
        "xark": xark, "xark_candidate": xark,
        "examples": {"path": str(root / "xark-privacy-examples"), "commit": examples},
    },
    "binaries": {"bench": binary},
    "candidate": {
        "binary": binary, "environment": {"BENCH_G2_INVERSE_LANES": "2"},
        "receipt": "bench g2 inverse lanes: 2",
    },
    "toolchains": {
        "rustc": subprocess.check_output(["rustup", "run", "1.94.1", "rustc", "-Vv"], text=True),
        "RUSTFLAGS": os.environ.get("RUSTFLAGS", ""),
    },
}
(output / "config.json").write_text(json.dumps(config, indent=2) + "\n")
PY

benchmark=xark-bench-runner/benches/competitive/run.py
affinity=$(cat "$out/affinity.txt")
taskset -c "$affinity" python3 "$benchmark" --config "$out/config.json" \
    --output "$out/b2" --competitor xark --xark-query b2 --threads 2 \
    --samples "$samples" --pairs 2 --strict-contention
taskset -c "$affinity" python3 "$benchmark" --config "$out/config.json" \
    --output "$out/proof" --competitor xark --threads 2 \
    --samples "$samples" --pairs 2 --strict-contention

python3 - "$out" <<'PY'
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
for stage in ("b2", "proof"):
    report = json.loads((root / stage / "report.json").read_text())
    if not report["performance_eligible"]:
        raise SystemExit(f"{stage}: ineligible for a timing claim")
    for pair in report["comparisons"]:
        baseline = pair["arm_statistics"]["xark"][stage]
        candidate = pair["arm_statistics"]["xark-candidate"][stage]
        p50 = (candidate["p50_ns"] / baseline["p50_ns"] - 1) * 100
        p95 = (candidate["p95_ns"] / baseline["p95_ns"] - 1) * 100
        print(f"{stage} {pair['workload']} pair {pair['pair']}: p50 {p50:+.2f}%, p95 {p95:+.2f}%")
PY
