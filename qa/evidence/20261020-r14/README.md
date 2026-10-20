# R14 continuation evidence — replacement remains unqualified

Candidate: `7a552330df821b358161628120a8b5d064f37367`  
Source tree: `398e1eaaa5978627df849c63321cf0b0c8d5c7fa`  
Complete source closure: **3556 files**. Manifest SHA256: `7bf1c8c4d34fc527142990af9364c1b3ed6d7daa257de1ade1533dccc86ccafc`.

These are actual host receipts and complete selected failure logs. The original denominators, native per-command 1800-second budget, request deadlines, compiler profiles, and source checks remain unchanged. No R12 or R13 pass is counted as an R14 pass.

## Actual results

| Gate | Result | Evidence |
|---|---|---|
| Mac original native 58 | **58/58 PASS**, 42 commands, runtime exit 0 | [summary](mac-native58-summary.json) |
| Mac original focused 20 | **20/20 PASS**, 40 commands, runtime exit 0 | [summary](mac-focused20-summary.json) |
| Mac new publication-read 2 | **2/2 PASS**, independent from the 58 and 20 | [summary](mac-publication-read-two-summary.json) |
| Main new publication-read 2 | **2/2 PASS**, independent from original 58 | [summary](main-publication-read-two-summary.json) |
| Mac official OpenBao 2.7.1 full34 migration/recovery | **31/31 PASS**, actual official process, 17 × 2 MiB versions, native-large lane | [summary](mac-official271-full34-summary.json), [controller](mac-official271-full34-controller.json) |
| Main original native 58 | **FAIL: 54 passed, 4 failed**, all 18 groups attempted, 42 commands, runtime exit 1 | [summary](main-native58-summary.json) |
| Mac AppRole/quota supplemental 38 | **FAIL: 14 passed, 24 failed** | [summary](mac-supplemental38/summary.json) |
| Mac existing gateway r3 inspect and signed read probe | **PASS under named r3 scope-equivalence contract** | [inspect](mac-gateway-r3-inspect/controller.public.json), [probe](mac-gateway-r3-probe/controller.public.json) |
| R14 X230 original 58 / full34 | **NOT RUN**; qualified Main capsule admission was not met | No inherited qualification |
| R14 physical Mac–ROG–Pocket4 LAN98 | **NOT RUN** | R12 LAN98 failure remains authoritative for R12 |
| R14 HeptaBao six-phase real gateway credential canary | **NOT RUN** | Sources staged and audited; known product blockers stopped advancement |

The Mac full34 check retained the original HTTP **15 seconds**, migration **360 seconds**, complete actual Git source binding, source and binary unchanged checks, and all 31 storage/API/restore checks. Its success is scoped to this candidate on this host; it does not qualify HA or all OpenBao functionality.

## Preserved failures and identified defects

The Main historical group had three failures: a forwarded history read returned 503, activation exceeded the original 15-second request while installing local objects, and historical snapshot admission returned 403. The 34 MiB archive unit case returned `Gate`. See [complete historical log](main-historical-service.log) and [archive log](main-archive-34mib.log). Concurrent I/O pressure was observed separately; that observation does not recategorize these failures as passes or prove an environmental cause.

The supplemental failure breakdown is AppRole135 **8/11**, quota catch-up **0/1**, quota lifecycle **0/1**, unchanged CIDR regression **3/3**, and unchanged batch regression **3/22**. The three service-level AppRole135 failures and 19 batch failures occurred on real role writes returning 503. Source review identified missing AppRole135 schema promotion before record-plan preflight. HA installation independently retained a maximum state schema of 134 and rejected valid 135 roots. The quota catch-up case exposed a standby pre-authentication quota refusal being replaced by a failed terminal Token API clock publication. These are defects requiring a new candidate and unchanged regression gates.

R13's earlier compiler failure is retained under [r13-preserved](r13-preserved/). R14's one-line use of the public root predicate repaired that compilation problem; it did not erase the R13 failure.

## Gateway evidence boundary

The r3 gateway receipts prove existing owner-local source/device custody, signed wrong-token rejection, and a protected signed read using the configured existing credential. The named r3 scope contract checks effective grant equivalence and preserves the prior r2 exact-list failure. No cache, pairing, approval, SDK configuration, or production gateway changes were made. These receipts are **not** evidence of a HeptaBao-backed consumer, production restart, production rollback, or traffic cutover.

## Build identities and disposition

Mac server: **75438080 bytes**, SHA256 `e7358b90f808c1f55816752d5f65226f7374559b658cc7dcfbcc9b76988f7a5a`.  
Main server: **803320640 bytes**, SHA256 `8e8be58d2f8e5f96fcbf148a1f92625242bd1cb4033ba6019e739970539de1a9`. Its build succeeded, but its original 58-test host qualification failed.

No qualified Main→X230 capsule was manufactured from the failed Main gate. No R14 LAN mutation or six-phase credential run was started. No production traffic was switched, no production gateway was restarted, and no OpenBao service, binary, backup, or recovery material was deleted. The R11 write13 and R12 write15 transactions with completed publication and final 503 were not replayed.

**Full OpenBao 2.7.1 replacement remains unproven.** Repairs and further physical validation continue from this immutable evidence set.
