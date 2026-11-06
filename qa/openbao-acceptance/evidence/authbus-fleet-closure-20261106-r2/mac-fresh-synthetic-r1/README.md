# Fresh Mac synthetic r1: retained failure and completed isolated cleanup

This package preserves one failed synthetic startup campaign and its separate, known-successful cleanup. It grants no production or real AuthBus admission and does not change the old R2 business failure.

## Product and scope

The independent 0500 server copy is canonical commit 4bde9aee03fcd27c59e13607e529b1cee594b249, tree f08493a23f8ea0637073651231865ea9607b790e; 92359328 bytes, SHA256 5f75acb9822defded2ed21f2f0ed1c21895c5e7d8d8d595e9f1c4ee9b9eaa85c. The shared canonical 0700 artifact was not modified. This fixture was uninitialized and used a newly generated local TLS certificate. No current credential store, J3160 secret source, real AuthBus consumer, production service, or backup was read or changed. No private key value or digest is included.

The files retaining ".private" names are original synthetic control files and wrapper diagnostics, not real credentials. The original names are retained for exact evidence linkage. Source/readback RPCs include independent file versions and hashes; they are not claimed as one atomic filesystem snapshot.

## Authoritative jobs

| Purpose | Durable Mac job | Terminal |
|---|---|---|
| Create-only preparation | 1a1b15b3518-fc05-77f3 | succeeded 0; original lost reply reconciled with reused=true and retried_launch=false |
| 30 mock gates and no-signal preflight | 1a1b160c7c9-fc05-7821 | succeeded 0; 30/30 |
| First fresh two-generation campaign | 1a1b162f30c-fc05-7833 | failed 1; 24533-byte complete stdout |
| First independent read-only reconciliation | 1a1b167bf27-fc05-7867 | failed 1; preserved stderr; no QA mutator |
| Second read-only reconciliation and diagnostic health | 1a1b16b55a9-fc05-788b | succeeded 0 |
| Cleanup preparation, gates and no-signal preflight | 1a1b1777d28-fc05-78f2 | succeeded 0; 26/26 Mac gates |
| Approved once-only cleanup | 1a1b17c0429-fc05-7911 | succeeded 0; 32719-byte complete stdout |
| Two independent absence observations | 1a1b17e917f-fc05-7925 | succeeded 0; 1127-byte complete stdout |

All listed final statuses are retained. No timeout is relabeled as success. Full paginated stdout and original remote files are retained; byte cursors and byte hex are preserved in process-read records.

## Observed startup and failure

The wrapper reached ready after 0.996273 seconds, observed admission after 1.440728 seconds, and reached the final pre-exec marker after 1.578205 seconds. The manager observed the exact PID/birth transition into the pinned HeptaBao server. T5 opens, imports, anchors, diskutil, configuration and binary pins completed. This new run reproduced no TCC denial; it does not retrospectively explain the old R2 Python stall.

The first immediate health connection was refused before TLS or HTTP, with request_count=0. The old probe connected only once. A later separate diagnostic completed verified TLS 1.3 and the complete expected HTTP 501 body (329 bytes, initialized=false, sealed=true, request_count=1). That later health result does not repair the original failed campaign.

Failure cleanup stopped before any service signal or bootout because direct /bin/ps custody expected effective UID501. The actual system binary is UID0/GID0 (wheel), mode04755, 170432 bytes, SHA256 3bbba882e30d91fc4ff6e6844ca7c59fef4351b9a3fea35dca55708d6d487d1c. The second independent observer captured its own PS child as UID0 with libproc EPERM, then reaped it and observed ESRCH. The original unknown PS helper PID19659 was independently ESRCH with no related rows. The first failed reconciliation did not preserve its new observer child PID; that missing identity is not invented or claimed independently closed.

The failed campaign ledger contains only bootstrap complete0: TERM0/KILL0/bootout0. It completed one operation, no second generation, and did not achieve registration or lineage closure.

## Separate recovery-only cleanup

The reviewed recovery binds all nine failed campaign journals, all 17 command receipts, authoritative failed status/full stdout, original plist/argv, full PID19545 birth (1793977415.045274), UID501, the retained server inode/hash, and the actual fixed system PS pin. It uses the previously reviewed bounded foreground observation runner, not a newly qualified general privileged WNOWAIT helper.

The new recovery had its own 60-second total deadline, a real 20.045846-second current-owner observation, no callable TERM dispatch, at most one KILL and one bootout, create-only intents, and identity checks before and after each action. It completed in 20.235292 seconds: TERM0, KILL1, bootout1, both commands known complete0, 154 helper commands known, no new unknown. All eight cleanup journals were independently read back.

Two subsequent independent rounds each observed exact GUI-label absent exit113, original PID native ESRCH, and no PID/PPID/PGID-related rows among 716 metadata rows. Generic system-domain service_status was not used as GUI proof. No data files were deleted.

## Remaining qualification

A source-bound, fixed-argv exception for the actual setuid /bin/ps helper and bounded connection-refused readiness within the original 15-second TLS deadline remain to be qualified in a new fixture and new two-generation campaign. This package is not a successful two-generation test, actual AuthBus credential migration, HA qualification, fleet cutover, or authorization to remove old OpenBao.
