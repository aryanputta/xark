# Prepared quadratic wipe cost probe

This local, uncommitted instrumentation is based on fork branch `fix/prepared-quadratic-wipe` at `8fb975a3deaad301f05326c16c4e2f3ba5583f1d`. The exact patch is [instrumentation.patch.gz](instrumentation.patch.gz), gzip SHA256 `4c82b66c760f1a031dd6dcffff447be76502fd64d8559df5a2a54fa7ce5f59d2` (uncompressed SHA256 `60033651c77c930093c986e8530433c56e14537d9befe5a5007ae5dd329d63ca`). It counts initialized `OnceLock` entries, then times only `QuadraticScratch::clear_bn254()` with `Instant` before the diagnostic `eprintln!`. The counting scan occurs outside that interval. Instrumentation is restricted to synthetic fixtures and must not be promoted into production because entry counts are witness-derived metadata.

The optimized diagnostic binary SHA256 was `88685ebd25f7e3b5c1187a5e5cd6245ba066db990112`; the fixture manifest SHA256 was `0436bedbae33912331d7306b9c1406956be5695d43f85f5c750f19bbb9bcce41`. Four distinct synthetic requests per circuit each generated a complete proof accepted by Arkworks, while an altered public statement was rejected. See the raw [escrow stdout](escrow.stdout), [withdrawal stdout](withdrawal.stdout), [escrow timing](escrow.stderr), and [withdrawal timing](withdrawal.stderr).

| Circuit | Quadratic slots | Initialized entries | Clear time per request, microseconds |
| --- | ---: | ---: | --- |
| Escrow | 7,627 | 5,621 | 35, 34, 30, 38 |
| Withdrawal | 5,425 | 3,969 | 23, 23, 23, 39 |

This is an isolated cost probe on a shared Mac, not a qualified complete-proof benchmark. The clear call is tens of microseconds; the previous paired withdrawal slowdown signal was about 2.98% of roughly 90 ms, or milliseconds. The isolated clear cost alone does not explain that difference. Deallocation occurs after `Drop` and is outside this interval; compiler changes and host variance remain possibilities. The next controlled experiment is a same-binary host gate followed by paired baseline/candidate complete proofs on an idle Linux host. The production branch is unchanged by this probe.
