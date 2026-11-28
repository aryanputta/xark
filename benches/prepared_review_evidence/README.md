# Prepared prover review evidence for Xark PR #106

This directory publishes the synthetic Privacy Rings fixtures, runnable gate/parser, and raw receipts used to describe the prepared-path result in [PR #106](https://github.com/blueshift-gg/xark/pull/106). Publication of the synthetic fixture archive was requested for independent review. It contains four distinct escrow and four distinct withdrawal requests, their expected and altered public statements, XBC circuit artifacts, and test proving keys. These are regression inputs for real Privacy Rings circuit shapes, not production user transactions. The archived JSON inputs were checked to contain numeric field values and no email or private-key text markers. Do not use the test keys for a production circuit.

The two receipts measure **different source states**:

| Receipt | Source | Host and scope | Outcome |
| --- | --- | --- | --- |
| `historical-one-core-linux/control-cpu0/` | `c2a3922480b1d60b285f065c941bd1dbf84b8cdd` | Free Colab Linux, one physical Xeon core, one worker, 256 same-binary controls then 400 measured synthetic complete proofs | Four control pairs passed the 2% median/10% p95 gate. Prepared full-audit versus satisfaction-only p50: escrow 700.228→588.811 ms (15.91%), withdrawal 558.697→481.738 ms (13.77%). This is **not** final PR head or upstream/Gnark timing. |
| `final-cleanup-mac-gate/` | Benchmark instrumentation with the same cleanup changes as PR head: `89b43b11510a068d62e078a14fd95b084fe0dca2` | Shared Intel Mac, two Rayon workers, 256 same-binary controls | All four control pairs failed (worst median 22.87%, p95 42.82%). No candidate mode was timed; no final-head speed or cleanup-cost estimate exists. |

PR #106's code head is `98ef685895a9c594938ae6528e8e57bfaf637734`, based on upstream `xark-0.5` at `03a7f519d28df6718f7ce6dda41f1e57e5ea55db`. The benchmark instrumentation branch here is separate from the PR code branch. The direct final-head API smoke ran four varied requests per circuit; Xark and Arkworks verified every proof and rejected altered statements. All 25 Groth16 prover tests and the exact-head hosted workflows passed. Those correctness checks do not turn the historical timing into a final-head speed claim.

## Audit the published data

Run from this directory:

```sh
sha256sum -c SHA256SUMS
python3 audit_receipts.py
```

`audit_receipts.py` validates all 28 archived fixture-file hashes without extracting them, reparses each raw stdout receipt, checks exact mode/solver receipts in stderr, reconstructs all control and measurement sample counts and p50/p95 values, and checks the Mac host-gate failure. The historical report includes every service sample and host/binary fingerprint. The old source is available as fork commit `c2a3922`; the updated benchmark source is this branch's ancestor `89b43b1`. The runner itself is `paired_linux_replay.py` with `batch_parser.py`.

To repeat the *prepared audit versus satisfaction-only* comparison on a Linux host, extract `fixtures-synthetic.tar.gz` into a new `fixtures/` directory, check `fixtures/fixtures.sha256`, build this branch's `bench_prove` example with the locked `ci` profile and features `msm-b-shared-bench,msm-g2-shifted-bench,msm-g2-endpoint-bench`, and run `paired_linux_replay.py` with the binary, fixture root, fixture manifest and a fresh output directory. For an eligible run, pin one logical CPU on each of two distinct physical cores, use `--workers 2 --concurrency 1 --requests 25 --blocks 4`, and require the runner's 2% median/10% p95 same-binary gate to pass. The wrapper checks each proof with Xark and Arkworks and rejects altered and cross-request statements outside the service interval. A shared runner remains secondary evidence even if its gate passes.

A separate **final `PreparedCpuProver::prove` versus current upstream** experiment is still needed. It must time equivalent complete warm requests with the same fixtures, keys, worker budget and verification boundary, and report cold preparation, warm p50/p95, peak memory and amortization. The historical within-binary result cannot answer that question. The fixture archive and raw logs are published so reviewers can audit the existing percentage before that comparison exists.
