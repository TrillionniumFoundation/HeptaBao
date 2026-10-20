# R15 physical-host continuation evidence

## Verdict

R15 is **not qualified for full OpenBao 2.7.1 replacement or production cutover**. This evidence preserves both progress and failures.

Candidate: `47b96f44edf51c2b68f22ed83495bc70e84ae24d`  
Tree: `e9eb1a46bd09e57c59fa3140f5129a65f24f2fd8`  
Parent: `7a552330df821b358161628120a8b5d064f37367`  
Complete source manifest: 3556 files, SHA256 `a1538aa148090decdcedb739b5cb21cbb2889c4344089e7668ad68fedc4c8e6b`.

The original manifest-based source and the actual published Git commit were materialized and independently verified on both Mac and Main Linux. The source remained unchanged during execution.

## Actual results

| Gate | Physical host | Result |
| --- | --- | --- |
| Original supplemental38 | Mac | FAIL: 36/38 passed |
| Original supplemental39, r1 | Main Linux | Blocked before tests: offline dependency adler2 2.0.1 missing |
| Original supplemental39, r2 | Main Linux | FAIL: 37/39 passed |
| Independent publication-read HA2 | Mac | PASS: 2/2 |
| Independent quota refusal guard1 | Mac | FAIL: 0/1 complete cases; native setup returned 501 |

On both hosts the AppRole schema135 group passed 11/11, CIDR regression passed 3/3, and batch-token regression passed 22/22. Main also passed the original Linux-only defaults case (1/1). All original required tests remained selected. These are native Service regression results, not proof of live customer migration.

The two original HA quota cases advanced beyond the R14 refusal failure but failed when creating native quota definitions: `sys/quotas/rate-limit/ingress` and `sys/quotas/rate-limit/node-0` returned 501 instead of 204. The independent refusal guard similarly failed at native `sys/quotas/rate-limit/guard` setup. Its completed legacy portion does not qualify the entire case.

The failed r1 Linux execution is retained. The cache was refilled using `cargo fetch --locked --target x86_64-unknown-linux-gnu`; the actual Cargo.lock bytes remained unchanged. The r2 execution then used the original `--locked --offline`, default debug profile, jobs8 and 1800-second command deadline. Mac retained jobs2 and the same original deadline.

## Candidate changes and next correction

R15 promotes AppRole schema135 before ordinary record preflight, admits supported schema135 during native installation, and adds a strictly bound one-use standby quota refusal path with mandatory request/response audits and original ordinary terminal clock floors.

The remaining quota 501 is caused by missing native Auth route classification for the three existing quota handler domains. R16 candidate `289a7c80771ae39095be7aaae4e0f42cf009a726` adds only those owner classifications and an independent administration regression. Its runtime results are separate and are not inherited by this R15 evidence.

## Scope and retained blockers

R15 original58, focused20, official271 full34, X230 artifact execution, LAN98 and real-consumer six-phase canaries were not executed. No current R15 result is substituted with an earlier candidate result. The R14 Main original58 failure (54/58), including historical restore and archive cases, remains an independent unresolved prerequisite.

The R14 evidence is retained at commit `afcc2c3338b692170478c8cd6a478f8465e99424`, under `qa/evidence/20261020-r14/`. Earlier R11 write13 and R12 write15 outcomes were not replayed. Original denominators and request, election, read, migration and test deadlines were not relaxed.

No production client was switched, no production gateway was restarted, and no old OpenBao service, binary or backup was deleted. Existing gateway inspection and signed-probe evidence does not count as a completed HeptaBao consumer cutover.

## Files

`INDEX.json` records each complete retrieved file's SHA256, byte count and original physical-host path. The accompanying files include both failed and passing test logs, complete summaries, source materialization receipts and the Linux cache-recovery receipt/log. Credentials and private canary working state are not part of this evidence bundle.
