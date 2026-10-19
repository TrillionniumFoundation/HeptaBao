# Native V6 snapshot clock R4 and actual host continuation — 2026-10-19

## Candidate purpose

The preceding `0f1c996136aae94e99c2b709a5797ffea479f6cd` candidate produced the same **53/55** native fixture result on the physical Mac, main Linux host and X230. The original import assertion expected a pre-projection public number representation; the exact storage checks remained successful. The subsequent `36ee52ace6351dc92bea5accadabee32e5803c17` diagnostic candidate passed import 8/8 on the Mac and exposed the remaining restore response: `Token API precise observation floor cannot decrease`.

R4 preserves the admitted live Auth/Engine clock floors through the same native V6 atomic restore transaction. It authenticates the original archive and typed graph, derives a source-bound root and checkpoint, retains original KV payload references, and commits the replacement owner/root/cursor/epoch/ledger through the existing FileIntent/backend CAS. The original Actor, source frontier, unknown-outcome fencing and time budgets remain in force. The independent reviewer identified and the author fixed an `allow_rollback=false` guard that must compare the original archive generation, before the new checkpoint generation is projected.

The existing witness test now observes the actual committed floor before any outer terminal clock/audit write and after real cold unseal. The original 55 selectors and per-command 1800-second budget are unchanged. The author overlay contains 12 files; an actual Mac rustfmt-only layer formats 11 of them. Rustfmt is not a compile or a runtime pass. This commit starts from reviewed source and does not claim that R4 has already passed.

## Actual evidence preserved with this candidate

| Lane | Executed source | Result and scope |
| --- | --- | --- |
| Main Linux native fixtures | `0f1c9961` | 53/55; actual server test compilation and binary build succeeded. Main binary SHA256 `a45ebe3e4d7b845ca5392431bdae9ba8348e16d2fe88489c3347049a07a7b8d2`. |
| Mac diagnostic | `36ee52ac` | 12/13: import 8/8, witness 4/5. The original 400 clock-floor failure is retained. |
| X230 native execution | `0f1c9961` | 53/55, 06:01:52–06:05:26 UTC. Actual transferred Linux libtest/server artifacts executed on X230; no compilation occurred there. Source, capsule and system dependency identities remained unchanged. Actual local TLS server health and owned-process stop passed. |
| Linux/macOS CI | `0f1c9961` | Both 53/55, with original complete job logs retained. |
| AuthBus native cold fixture | `0f1c9961` binary and exact frozen AuthBus R1 packet | Controller 120/120; distinct actual Node SDK workers 59/59, 57/57 and 57/57. Real native AppRole/TLS/KV2/Policy/renew/revoke, native SIGKILL/cold reopen, SDK SQLite and OAuth manager executed. Four OAuth identities and HTTPS provider are synthetic controlled fixtures. External provider, production credentials, OpenAI facade and traffic cutover remain unproven in this lane. |
| Mac/ROG/Pocket4 LAN | `0f1c9961` binaries and separately hashed driver overlay | 36/98, failed at the first Mac exact historical read after ROG native activation. Six directional Python mTLS probes and three API leaf pins passed. Mac native TCP logged `HostUnreachable` before TLS. All three owned fixture processes stopped. Large payload writes, failover, quorum loss and cold repair were not reached. |

The first X230 transfer copied and verified the complete capsule but its initial executor launch had a Python SyntaxError before execution. That receipt is retained. A separate corrected launch executed the already copied artifacts exactly once; neither the failed launch receipt nor the tests were rewritten.

The Linux artifact handoff verifies producer logs, binary identities, source tree, original test selectors, actual ELF/loader dependencies, before/after custody and a real TLS server start. It does not relabel an execution host as a compilation host. The main host uses eight compiler jobs based on its observed 48 logical CPUs and unrestricted memory cgroup; fixture test threads and deadlines are unchanged.

## Remaining required proof

Run the R4 candidate on the physical Mac and Linux, then execute its exact Linux artifacts on X230. Verify the native-Service-only feature combination. Run the pinned official OpenBao 2.7.1 full34 migration controller with the original transfer/request budgets and independent raw storage witness, including real cold reopen and snapshot restore. Diagnose the Mac native TCP failure and complete the unchanged three-host LAN98 profile. Complete actual provider dispatch and each real-client credential migration, restart and rollback before traffic cutover. Reconcile all client and backup paths before deleting old OpenBao services, binaries or regenerable intermediates.

No production traffic was cut over by this candidate. No old OpenBao service, binary, credential source, Raft state or recovery archive was deleted. These are conditional later gates whose prerequisites remain incomplete.
