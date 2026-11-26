# BN254 G2 research checkpoints

## Upstream and historical evidence

The branch starts from Blueshift `xark-0.5` at `03a7f519d28df6718f7ce6dda41f1e57e5ea55db`. The history bundle verified a complete history at the same revision. PR #47 is the opt-in GPU work. PRs #97, #99 and #102 address verifying-key and cache integrity, #98 fixes test staging, and #100 checks availability of the optional OpenCL syntax tool. PR #103 documents target flags. The existing upstream prover already implements GLV, queued affine conflicts, resident scheduling and modeled window selection. [GPU work](https://github.com/blueshift-gg/xark/pull/47) · [Upstream CPU changes](https://github.com/blueshift-gg/xark/commit/0822bfb)

**PR #101 scope.** Its standalone diff changes `ConstraintSource::first_unsatisfied`. In the ordinary prover, callers enter that method via `self_check_failure` after verification fails. The default configuration sets `self_check=false`. In the CLI, `--verify` sets it, but successful proofs still skip the failure diagnostic. The reported checked-resident gain came from `BENCH_CHECK_ROWS`, which explicitly calls `first_unsatisfied` on each timed proof. Treat the result as faster explicit checking or failure diagnosis. The captured data does not establish lower latency for successful default production proofs. [Exact #101 diff](https://github.com/blueshift-gg/xark/pull/101/files)

`catalog.py` indexed 55 discovered Xark files, 54 unique outer hashes, and 794 distinct archived text members. The two `xark-gnark-evidence` archives are byte-identical. The dependency cache is fingerprinted without member traversal. The earlier numerical reconstruction covers 11 specifically pinned archives and 4,255 parsed records. A catalogued file is not a verified performance experiment.

The original Linux B2 arms report 5,406 withdrawal and 7,606 escrow terms. The two withdrawal Xark medians are 99.280 and 100.446 ms. The matching Gnark Crypto medians are 86.076 and 86.215 ms. Their arithmetic means reproduce the approximate 99.865 and 86.15 ms reported earlier, and should not be called pooled medians. The portable one-worker task profile recorded 135.135 ms median B2 task time. In the separate query CPU profile, `sum_of_products` leaf symbols account for 39.49% of all query-process samples, including the 21.78% seen with G2 affine flush ancestry. In the checked-proof profile the corresponding nested G2 flush value is 10.82%. Those values use different denominators and overlap where nested.

ICICLE's CPU lane verified the same B2 group results but took 9.7–11.4× the Xark B2 median on the sampled CPU. This does not characterize its GPU runtime. Earlier Constantine measurements cover G1 B1 only. The new Constantine B2 adapter has independently checked bundle contents, but its pinned Nim build and native timing still need the appropriate runtime. [ICICLE CPU benchmark](https://github.com/aryanputta/xark/tree/dc8ad92e0bdf34da5d614b39125127ce91aa116b/benches/privacy-rings-icicle)

## Arithmetic and MSM comparisons

| Layer | Xark | Pinned comparison and open question |
| --- | --- | --- |
| Montgomery Fq multiply | Arkworks 0.6, using the emitted instructions under the selected compiler target. | Gnark Crypto v0.19.0 contains a runtime-selected four-limb ADX multiply and a generic fallback. The targeted Xark artifact changes MULQ into MULX for the audited two-product symbols and retains its ADC chain. The archived Gnark binary is available by digest only. Compare the same primitive and actual branch execution before attributing cycle differences. |
| Fq2 multiplication, squaring, inversion | Quadratic extension with `u²=-1` for BN254. The earlier generic Karatsuba replacement regressed all four checked-proof medians. | Compare the extension operations as compiled before extending the field kernel, and hold coordinate representation fixed. |
| G2 mixed addition and bucket flush | Xark uses queued batch-affine work with projective spill handling. | Gnark's BN254 generation includes extended Jacobian and affine bucket helpers. Dependent work, exceptional points, and memory writes need separate counts. |
| Scalar recoding, bucketing, reduction | Xark uses Booth digits, GLV for eligible wide scalars and modeled bucket width. | Gnark generates width-specialized chunks and dispatches affine/projective work. Existing B2 samples justify investigating chunk policy, but the samples do not identify whether instruction cost, memory or scheduling causes the gap. |
| Complete proving | Checked resident Xark proof with fixed circuit, witness, thread budget and ordered output. | The pinned Gnark proof lane times equivalent exported rows. Rapidsnark's resident ABI includes witness parsing and JSON, so retain its distinct timing boundary. |

[Gnark generated MSM source](https://github.com/Consensys/gnark-crypto/blob/v0.19.0/ecc/bn254/multiexp.go) · [Gnark base field](https://github.com/Consensys/gnark-crypto/tree/v0.19.0/ecc/bn254/fp) · [Arkworks implementation](https://github.com/arkworks-rs/algebra/tree/v0.6.0)

MCL's `BN_SNARK1` parameters match this modulus and group order. Its separate curve called `BN254` has different parameters. BLST's BLS12-381 implementation can inform carry scheduling and instruction use but is not a BN254 reference. Fiat Crypto and s2n-bignum are relevant arithmetic-generation or verification references. An exact modulus, implementation revision, and applicable license must be checked before importing generated code. FFIASM/Rapidsnark, Halo2 Curves and Lambdaworks remain source comparison candidates. No external kernel was copied for the two-product, endpoint or sparse-endomorphism experiments. [MCL curve selectors](https://github.com/herumi/mcl/blob/master/api.md#curve-parameters) · [BLST](https://github.com/supranational/blst) · [Fiat Crypto](https://github.com/mit-plv/fiat-crypto) · [s2n-bignum](https://github.com/awslabs/s2n-bignum)

## Source index

The shell could not resolve the public download hosts. The items below were inspected using source pages or the full-paper copies described in the linked digest. A public landing page does not establish that its PDF was downloaded locally.

| Work | Verified source and immediate research use |
| --- | --- |
| El Housni and Botrel, *EdMSM* | [ePrint 2022/1400](https://eprint.iacr.org/2022/1400). Improved CIOS is relevant independently of Edwards coordinates. Edwards-form and benchmark claims need their stated curves checked before any BN254 G2 transfer. |
| Luo, Fu and Gong, fixed-point MSM | [TCHES 2023](https://doi.org/10.46586/tches.v2023.i2.358-380). Bucket-set construction for repeated points. Read alongside the subsequent correction to the original residue coverage. |
| Fan, Kuchta, Sica and Xu, pairing-based MSM | [ePrint 2024/750](https://eprint.iacr.org/2024/750). Generalizes the LFG bucket construction and supplies counterexamples to original coverage. Applies to a fixed-table hypothesis subject to group and representation checks. |
| Le and Sica, optimal bucket sets with endomorphisms | [ePrint 2026/1902](https://eprint.iacr.org/2026/1902) · [paper copy](https://opencryptology.org/2026/1902.pdf). Hexagonal model gives `(7^c+5)/6` buckets for the reviewed construction. The published timings use BLS12-381. The BN254 G2 lift and residency need independent validation. |
| Noël and Plantard, memory-constrained MSM | [ePrint 2026/1316](https://eprint.iacr.org/2026/1316) · [author PDF](https://thomas-plantard.github.io/pdf/NoePla26.pdf). Adaptive buckets under a bucket-only memory limit. Their 15 KB result is BLS12-381 G1 on a different workload and motivates a cap-matched experiment. |
| Oleksandr Hrabar, Pippenger performance | [Waterloo thesis](https://uwspace.uwaterloo.ca/items/43cc12b9-cb03-42bd-a01c-4b0ed5e12403), February 2026. Sections 2.5 and 5 give the test environment, reuse construction, operation counts and timing. See the analysis below. |
| Koç, Acar and Kaliski, Montgomery algorithms | [IEEE Micro 1996 paper](https://www.microsoft.com/en-us/research/wp-content/uploads/1996/01/j37acmon.pdf). CIOS and separated operand-scanning operation counts are a comparison baseline. Counts do not include modern dependencies or cache costs. |
| Bos and Montgomery, software arithmetic | [ePrint 2017/1057](https://eprint.iacr.org/2017/1057). Reduction and latency perspective. Use the exact remainder bound independently of processor-specific cost assumptions. |
| Smith, scalar decomposition | [ePrint 2013/672](https://eprint.iacr.org/2013/672). Lattice-basis perspective for GLV/GLS. For B2 use the existing BN254 subgroup eigenvalue and verify the reconstruction before replacing digit generation. |
| Groth, pairing-based arguments | [ePrint 2016/260](https://eprint.iacr.org/2016/260). Groth16 relation and proof format. Field or group-kernel changes keep the statement and proof equations fixed. |
| Xavier, PipeMSM | [ePrint 2022/999](https://eprint.iacr.org/2022/999). Sections IV–VI distinguish implemented FPGA segmentation from proposed signed-digit and batch-affine changes. See the analysis below. |
| Bernstein and Lange, Explicit-Formulas Database | [Short Weierstrass Jacobian formulas](https://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html). Compare mixed addition and doubling under their stated domain assumptions. Handle identity and exceptional cases independently. |
| Brent and Zimmermann, *Modern Computer Arithmetic* | [Author page and edition links](https://members.loria.fr/PZimmermann/mca/pub226.html). Independent multiple-precision reference and reduction context. |
| ZPrize implementation notes | [ZPrize 2022 implementation notes](https://github.com/mitschabaude/montgomery/blob/main/doc/zprize22.md). Evaluate implementation assumptions before adapting an accelerator or representation strategy. |

The citation chain from the Luo, Fu and Gong paper to Fan et al. and Le and Sica changes the immediate fixed-point experiment. Use the corrected residue coverage, and account for immutable table preparation and memory in addition to per-request latency. [Full-text fixed-point digest](https://github.com/aryanputta/xark/blob/research/fixed-point-msm-literature-v05/docs/research/fixed-point-msm-literature.md)

## Digit clustering and bucket conflicts

Hrabar's cross-row construction finds points that share at least two signed digits at the same window positions. For a matching digit set `J`, use `d_j P + d_j Q = d_j(P + Q)` for each `j` in `J`. This replaces two bucket inputs per matching window with one, after computing one auxiliary point. Under a model with one full addition per bucket input the net upper estimate is `|J| - 1` additions saved. Empty-bucket assignments, mixed versus full additions and scratch traffic reduce the validity of that estimate for Xark. The thesis uses one M4 Pro thread and BLS12-381. Around the 4K and 8K sizes, Table 5.2 reports 3.23% and 5.77% fewer point operations for factorization plus clustering. Table 5.3 reports 1.6% and 2.0% lower latency using the thresholded variant, a different configuration. The choice of auxiliary points and memory accesses depends on private digits. This lane needs a witness-confidentiality analysis before an off-chain prover integration. [Waterloo thesis, §§2.5 and 5](https://uwspace.uwaterloo.ca/bitstreams/697c043d-622c-43a8-bab0-90ce10b68c4a/download)

PipeMSM implements bucket segmentation and scheduling for a BLS12-377 FPGA pipeline. It proposes signed digits and batch-affine accumulation separately. CycloneMSM cites PipeMSM and describes greedy scheduling for the affine software conflict problem, where additions in one batch need distinct destination buckets. Xark already maintains a conflict queue and a projective spill path. These papers motivate a controlled comparison of conflict pressure and batch occupancy with an unchanged G2 window, using counts alongside elapsed time. The FPGA measurements give no expected speedup for the Privacy Rings CPU prover. [PipeMSM, §§IV–VI](https://eprint.iacr.org/2022/999.pdf) · [CycloneMSM, §3](https://eprint.iacr.org/2022/1396.pdf)

## Exact reference models

`model.py` uses integer arithmetic for the BN254 base and scalar moduli. It checks `REDC(T)` for `T < pR` and computes the bound of five products for canonical residues at `R=2²⁵⁶`. This is an end-of-reduction bound. Carry handling at each intermediate limb still needs its own proof and tests. It also checks signed-radix reconstruction, affine/projective coordinate payload estimates, the `3(n−1)` multiplication count for a nonempty endpoint batch inverse, exact Fq2 identities, break-even from positive recurring savings, and wall-time Amdahl limits. The Python model supplements independent Rust field and group tests.

## B2 completion and the resident join

The reconstructed task archive contains 15 checked proofs per workload and thread setting. At fixed recorded start times, shortening B2 only removes the portion of its duration that lies beyond the last finishing profiled peer. The replay gives these medians across the observed runs.

| Worker budget and workload | Median observed B2 duration | Modeled join reduction with B2 20% shorter | Proofs with any modeled reduction |
| --- | ---: | ---: | ---: |
| One worker, escrow | 177.975 ms | 0 ms | 0/15 |
| One worker, withdrawal | 135.135 ms | 0 ms | 0/15 |
| Two workers, escrow | 309.777 ms | 26.253 ms | 15/15 |
| Two workers, withdrawal | 249.894 ms | 0 ms | 4/15 |

Both guest logical CPUs were reported as SMT siblings. The replay freezes task launches and other durations. Earlier completion can change Rayon queueing and CPU contention, including at one worker where a later task might also start sooner. It omits unprofiled work and says nothing about an achieved proof speedup. Use the timing of both B2 finish and the resident join when testing scheduling on distinct cores.
