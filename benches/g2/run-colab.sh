#!/usr/bin/env bash
# Run a same-binary Privacy Rings comparison on a Colab Linux CPU runtime.
set -euo pipefail
umask 077

archive=${1:?provide the uploaded aaa-xark-offline-fixtures.tar.gz}
out=${2:?provide a new output directory}
samples=${3:-30}
policy=${4:-auto}
experiment=${5:-inverse-lanes}
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
case "$experiment" in
    inverse-lanes)
        branch=perf/privacy-rings-g2-inverse-lanes
        candidate=1dc7867c873f8d9f5b8cef5e6cbca61a25ae7c07
        checkout=xark-g2
        feature=msm-g2-inverse-bench
        parameter=BENCH_G2_INVERSE_LANES
        value=2
        receipt="bench g2 inverse lanes: 2"
        ;;
    inverse-endpoints)
        branch=perf/privacy-rings-g2-inverse-endpoints
        candidate=aee021c71aa9745ee370f7e3186fce5e70140a96
        checkout=xark-g2-endpoints
        feature=msm-g2-endpoint-bench
        parameter=BENCH_G2_TRIM_INVERSE_ENDPOINTS
        value=1
        receipt="bench g2 trim inverse endpoints: 1"
        ;;
    *)
        echo "Choose inverse-lanes or inverse-endpoints" >&2
        exit 1
        ;;
esac
unset BENCH_G2_INVERSE_LANES BENCH_G2_TRIM_INVERSE_ENDPOINTS
runner=225735659def0780b268e481794a24d1e3196eea
examples=9e5d69ade7e0c107a2929306d3b758a8969e1089
fixture_hash=82caa7cee2b155afc2bd32cdc9661ba8cfb758888f4837bf9d6af31eb05c36a7

[[ -f "$archive" ]] || { echo "Fixture archive was not uploaded" >&2; exit 1; }
[[ "$samples" =~ ^[0-9]+$ && "$samples" -ge 30 ]] || { echo "At least 30 samples required" >&2; exit 1; }
printf '%s  %s\n' "$fixture_hash" "$archive" | sha256sum --check --status
archive=$(cd "$(dirname "$archive")" && pwd)/$(basename "$archive")

mkdir "$out"
out=$(cd "$out" && pwd)
python3 "$script_dir/affinity.py" "$policy" > "$out/affinity.json"
workspace=${XARK_COLAB_WORKSPACE:-/content}
cd "$workspace"

pin_checkout() {
    local repository=$1 branch=$2 revision=$3 checkout=$4
    if [[ ! -d "$checkout/.git" ]]; then
        git clone --depth 1 --branch "$branch" "$repository" "$checkout"
    fi
    [[ $(git -C "$checkout" rev-parse HEAD) == "$revision" ]]
}

pin_checkout https://github.com/aryanputta/xark.git "$branch" "$candidate" "$checkout"
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
    cd "$checkout"
    rustup run 1.94.1 cargo build --locked --release -j 2 -p xark-groth16 \
        --features "$feature" --example bench_prove
) 2>&1 | tee "$out/build.log"

python3 - "$archive" "$out" "$candidate" "$examples" "$checkout" "$parameter" "$value" "$receipt" <<'PY'
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tarfile

archive, output, commit, examples, checkout, parameter, value, receipt = sys.argv[1:]
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

xark = {"path": str(root / checkout), "commit": commit}
binary = str(root / checkout / "target/release/examples/bench_prove")
config = {
    "version": 1, "fixtures": str(fixture),
    "sources": {
        "xark": xark, "xark_candidate": xark,
        "examples": {"path": str(root / "xark-privacy-examples"), "commit": examples},
    },
    "binaries": {"bench": binary},
    "candidate": {
        "binary": binary, "environment": {parameter: value},
        "receipt": receipt,
    },
    "toolchains": {
        "rustc": subprocess.check_output(["rustup", "run", "1.94.1", "rustc", "-Vv"], text=True),
        "RUSTFLAGS": os.environ.get("RUSTFLAGS", ""),
    },
}
(output / "config.json").write_text(json.dumps(config, indent=2) + "\n")
PY

benchmark=xark-bench-runner/benches/competitive/run.py
affinity=$(python3 - "$out/affinity.json" <<'PYCPUS'
import json
import sys
with open(sys.argv[1]) as stream:
    print(",".join(map(str, json.load(stream)["cpus"])))
PYCPUS
)
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
