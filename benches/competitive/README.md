# Competitive Privacy Rings benchmarks

Run verified escrow and withdrawal workloads with the same fixtures, thread budget, and paired process order. The harness compares Xark with Gnark on checked resident proofs. It also runs Rapidsnark resident proofs and compares the same Xark B queries with Constantine and ICICLE. An optional second Xark binary supports whole-proof and B2 experiments.

| Lane | Timed interval | Required correctness evidence |
| --- | --- | --- |
| Xark and Gnark | Resident proof with row checks, after witness solving and key load | Every measured proof verifies. Xark also checks with Arkworks. Both reject the changed statement. |
| Rapidsnark | Resident C ABI call, including witness parsing and proof JSON output. The snarkjs witness check runs separately. | Every proof verifies with snarkjs and the changed statement is rejected. No direct speed ratio is reported for this lane. |
| Constantine | CPU B1 MSM with resident inputs | Check every result against Arkworks and reject a changed B1 reference. |
| ICICLE | CPU B1 and B2 MSM with resident inputs, precomputation factor 1, and synchronous completion | Check every result against Arkworks and reject changed B1 and B2 references. |

## Prepare a runner

Use Python 3.11 or later on Linux or macOS. Use an isolated Linux VM for Rapidsnark with the online vCPU count equal to the requested thread budget. The pinned C++ pool uses online CPUs independently of the OpenMP cap. ICICLE uses a CPU thread cap and may use fewer workers.

1. Extract the existing `aaa-xark-offline-fixtures.tar.gz` benchmark archive into a private scratch directory. Its SHA-256 is `82caa7cee2b155afc2bd32cdc9661ba8cfb758888f4837bf9d6af31eb05c36a7`. The runner checks each escrow and withdrawal artifact against [the fixture manifest](fixtures.sha256). The existing `xark-colab-proof-environment.zip` contains the original environment setup.
2. Check out the pinned benchmark companion and Privacy Rings examples in separate clean checkouts. Build the companion with `cargo build --locked --release -p xark-groth16 --example bench_prove`. The companion supplies checked proving and exports the ordered relation, witness, and query inputs. The harness uses the pinned companion identified in [the example config](config.example.json).
3. For Gnark, run `go build -mod=readonly -o /bench/bin/privacy-rings-gnark .` in the companion's `benches/privacy-rings-gnark` directory. The command uses its locked Gnark `go.mod` and `go.sum`.
4. For query lanes, use the companion's [Constantine build recipe](https://github.com/aryanputta/xark/tree/dc8ad92e0bdf34da5d614b39125127ce91aa116b/benches/privacy-rings-constantine) and [ICICLE build recipe](https://github.com/aryanputta/xark/tree/dc8ad92e0bdf34da5d614b39125127ce91aa116b/benches/privacy-rings-icicle). Preserve their CPU and library build settings.
5. For Rapidsnark, build the pinned source's shared `rapidsnark` CMake target with `-DCMAKE_BUILD_TYPE=Release -DUSE_ASM=ON -DUSE_OPENMP=ON -DUSE_LOGGER=OFF`. Set the path to the Node binary on `PATH` and the installed snarkjs package directory. Supply the existing benchmark-only `test.zkey` and `vk.json` for each exported relation. The adapter checks the exported witness against the relation and verifies the proofs with those keys.
6. Copy `config.example.json` to your scratch directory and update its paths and compiler details. Relative paths resolve from the config directory. Only selected lanes need their corresponding binaries and sources. Add any additional shared libraries and build lockfiles to the optional `additional_artifacts` map to fingerprint them with the run.

Keep the scratch directory private. It contains test witness assignments, keys and witness-derived scalars. Use the archived test material for benchmarks and fresh randomness for each proof.

## Run and read a comparison

```sh
python3 benches/competitive/run.py --config /bench/config.json \
  --output /bench/run-gnark --competitor gnark --threads 2 \
  --pairs 2 --samples 100 --strict-contention
```

Omit `--workload` to run both fixtures. Repeat `--competitor` to select several lanes. Without lane selections the harness runs all lanes. For a quick check, use `--smoke --samples 2 --warmups 1 --pairs 2`. Smoke reports are explicitly ineligible for performance comparisons.

The output directory must be new. It receives logs, raw nanosecond `samples.csv`, and a structured `report.json` with median, nearest-rank p95 and p99, execution order, source commits, SHA-256 fingerprints, machine topology, and thread settings. p95 requires at least 30 samples in the summarized cohort and p99 requires 100. Process polling records visible competing CPU activity above the configured threshold. Pass `--strict-contention` to require successful monitoring and unflagged runs. Guest process polling cannot observe all hypervisor activity or guarantee isolation. Repeat promising results on a quiet host with fixed affinity.

To pair two Xark builds, include a `candidate` object with a `binary` path and add a corresponding `sources.xark_candidate` commit pin. An optional `candidate.environment` map selects candidate-only `BENCH_*` flags. An optional single-line `candidate.receipt` checks that the candidate emitted the expected mode. Run `--competitor xark --xark-query b2` to compare B2 against the Arkworks reference. Omit `--xark-query` to compare checked resident proof times on both workloads.

```sh
python3 -m unittest discover -s benches/competitive -v
```
