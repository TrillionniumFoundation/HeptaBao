# HeptaBao replacement evidence — 2026-11-06 r8

## Decision

**HOLD: the evidence does not authorize replacing OpenBao 2.7.1. Formal KV2 has not passed.** Work remains ordered as **KV2 → actual multi-host HA → AuthBus → per-host cutover → old-asset cleanup**. The actual r3 current-data projection passed 8/8 checks with independent complete-row reconciliation; the ordinary service remains uninitialized behind the observed Mac TCC blocker. No real traffic was switched and no old OpenBao or HeptaBao service/binary was deleted.

This checkpoint extends immutable r7 commit `f2f0d8e7d70794cd6bf8d425f7c24873d4e08fd1`. It preserves successful preparation, actual failed attempts, code-only diagnostics, exact stopped-candidate repair, original failed CI logs, and a minimal source fix as distinct evidence. See [GATE_STATUS.public.json](GATE_STATUS.public.json), [ACTUAL_JOB_INDEX.public.json](ACTUAL_JOB_INDEX.public.json), and [EVIDENCE_BOUNDARIES.md](EVIDENCE_BOUNDARIES.md).

## What is established

### Real current data is protected; service migration is still unproved

The inherited r7 capture/restore and independent readback used the complete declared current source corpus: five agent stores, nine SQLite families, six present databases and three absent families, five auth-store rows and four auth-state rows. Database logical size was **3,278,327,808 bytes**; the complete declared recovery content was **3,278,398,048 bytes**. The independent readback passed **11/11 checks**, including all 790 encrypted chunks, all declared present files and absent paths, complete hashes, and cold SQLite checks.

This establishes recovery integrity of that captured generation. It does not establish a writer fence, simultaneous cross-database snapshot, current live freshness, provider-side credential validity, client startup, or independent machine-loss recovery of all key material. It does not recreate unavailable historical OpenBao KV2 versions. The old 34 MiB isolation evidence remains a separate, limited result.

### The Mac ordinary service layout and TLS were actually created

The actual layout/TLS producer created the new service hierarchy, copied the pinned normal server and seed binaries, generated a local P-256 CA and server certificate, and wrote the fixed config and LaunchAgent material. The installed server and seed are normal binaries from source commit `4bde9aee03fcd27c59e13607e529b1cee594b249`; the later CI-only fix was not deployed to them.

Private TLS keys remain on the Mac internal volume with restrictive modes. The leaf certificate covers localhost and 127.0.0.1 and is for server authentication. Certificate construction and file identity checks do not prove a functioning TLS endpoint. See [mac-layout-tls](mac-layout-tls/).

### The first managed start actually failed before initialization

Job `1a1b27bfa3f-fc05-7e3a` ended with **exit 1**, complete durable output, no timeout or cancellation, and **zero init requests**. The single launchctl bootstrap returned 0, but readiness made 140 failed connection observations. No root token, unseal shares, or init nonce was created by that attempt. The controller's preassigned phase label is not proof that an endpoint existed.

The exact launchd query showed the new candidate in `spawn scheduled`, with no active PID and last exit **78 / EX_CONFIG**. An expanded actual macOS log read preserved **20 kernel lines** reporting that `sandboxd` rejected `xpcproxy` access for **SystemPolicyRemovableVolumes** at the candidate's T5 stdout-log path. This is the observed OS permission blocker; it is not diagnosed as a TLS, database, or init-protocol failure. See [manager-init-failure](manager-init-failure/), [manager-failure-diagnostics](manager-failure-diagnostics/), and [mac-tcc-diagnosis](mac-tcc-diagnosis/).

### A separate Python binding error was repaired while stopped

The intended launchd executable resolves to the original Homebrew base Python, while the first generated guard binding had recorded the controller venv's ordinary copied executable. Identical executable bytes did not make those path/identity roles equivalent. A strict read-only reconciliation exposed this mismatch.

The exact new `gui/501/org.heptabao.kv2` candidate was booted out; the subsequent exact query produced the expected native exit 113 and no-such-service stderr. The repair then re-admitted the stopped, empty, uninitialized candidate, preserved both the original current binding and initial archive, atomically replaced only `files.python`, fsynced, and read back the full binding. Root and an independent reviewer checked the actual terminal/output and original native file metadata. All 51 owned FDs were retired. No bootstrap, init, plist/config/guard change, or old-asset cleanup occurred in the repair.

The installed plist remains present with RunAtLoad/KeepAlive. Bootout proves absence at the observed points, not persistent disable. Future legitimate launch requires a new admission; replaying the original create-only entry would be incorrect. See [manager-readonly-reconciliation](manager-readonly-reconciliation/) and [stopped-binding-repair](stopped-binding-repair/).

## Current-data projection attempts

The projection is designed to read only the independently verified restored generation and create a new current credential baseline. Through the actual r2 failure, no qualified projection had been produced. It does not read live source configuration, contact providers or J3160, run the product, or assert historical OpenBao KV2 versions.

| Generation | Actual result | Established failure boundary |
|---|---|---|
| r1 | exit 1; 0/8 checks; zero SQLite connections | Original restrictive audit rejected a cold stdlib `__future__` import before generation/database access. A separate actual Mac code-only diagnostic confirmed the exact denied module class. |
| r2 | exit 1; 2/8 checks; zero SQLite connections; 40/40 FDs retired | Independent readback closure and restored database identities passed. Before SQLite connect, `Path.as_uri()` lazily loaded `urllib.request`; a separate actual Mac code-only diagnostic confirmed the same original audit refusal. |
| r3 | exit 0; 8/8 checks; six SQLite connections and 66 FDs retired | Strict POSIX URI encoding uses the already loaded encoder. All five agents and both tables reconcile to the original complete-row commitments. No audit denial, product, child, network or provider call occurred. |

The diagnostics succeeded by observing expected refusals. They are not successful projections or product acceptance. Each failed generation and its actual complete output is preserved. Audit rules and the original 52-second work/60-second runtime bounds were not relaxed.

Actual r3 projection job `1a1b2b773d7-fc05-7f73` completed in **2.711796 seconds**, with complete durable terminal/output. It produced a private **30,631-byte** baseline plus an **8,367-byte** binding. All nine current rows were included: five auth-store and four auth-state rows, across five agents; all nine database-family states remained accounted for (six present/nonempty, three absent).

Root independently read the complete output, binding and original **12,523-byte** capture manifest, compared native full hashes/versions/modes/owner/link count, rejected duplicate/nonfinite JSON, and independently recomputed every agent's two-table row commitment and explicitly bound each source row to its expected opaque KV key without importing the producer or protocol implementation and without reopening SQLite. The original credential JSON string cells and provenance fields remain bound by those complete commitments. The final [independent row-to-key supplement](projection-r3-independent-supplement/) retains the first checker and closes its initially missing per-row routing relation. Private content and private fingerprints are excluded from public evidence. See [projection-r3-actual](projection-r3-actual/), with prior [r2 actual failure](projection-r2-actual/) and [r3 prepared code](projection-r3-prepared/).

This is an accepted current baseline **input projection**, not a running KV2 storage service, imported historical OpenBao history, or source freshness/writer-fence proof. No business mount or KV2 value was created through the product API.

The projection scope is exactly all rows of `auth_profile_store` and `auth_profile_state` for the five captured agents. Other database content was fully hashed and preserved as recovery input, not mapped wholesale into KV2. The 3.28 GB recovery corpus is therefore **not** a 3.28 GB successful KV2 workload; the accepted credential projection is 30,631 bytes and actual product API writes remain zero. Its runtime is not an OpenBao performance comparison.

## Full CI found two concrete failures

Workflow **42260689756**, on source tree `7f4b75930e8491a3110d8c7f8f894cfc0cfc1fdb`, completed with failure. Both matrix lanes actually used the same source tree.

| Lane | Actual outcome | Failure |
|---|---|---|
| merge, job 128048873935 | server libtest 3751 passed, 1 failed, 8 ignored; workspace step exit 101 | `native_ha_large_kv2_full34_pre_activation_mount_lagging_v5_follower_kill_restore_cold` expected historical snapshot restore HTTP 200 and received 503. |
| head, job 128048874677 | server libtest 3752 passed, 0 failed, 8 ignored; later Clippy step exit 101 | `clippy::items_after_test_module` in `service_snapshot_v6_ha_restore.rs`. |
| verdict, job 128141481423 | exit 1 | Correctly refused the unsuccessful qualification matrix. |

The failing historical restore returned after **2,107,497 microseconds**, with **12,892,502,113 ns** left on its original 15-second request budget. This was not exhaustion of that deadline. The explicit later leader-stop and cold-rejoin steps were never reached. `root_attempted=false` does not prove that earlier Begin/Stage records were absent or that no persistent change occurred.

Read-only source tracing narrows the exact unprefixed `HaError::OutcomeUnknown` to quorum collection or the Root-before-publication witness check. The log cannot choose which branch or determine peer/transport/local-read/internal cause. The empty phase list reflects an observation gap and does not prove no phase ran. No data-loss, real-host HA failure, or root-cause fix is asserted.

The distinct Clippy issue received a mechanical item-order fix at commit **`f0e4694e5637415d394916b7590e7deec81e9d71`**, tree `76ca6224c9597ab9109e121adf19113ad12509f0`. The full original test observer, production prefix, and production suffix are preserved byte for byte; separator LFs are explicitly relocated. Root recomputed the whole expected Git tree, a second reviewer checked the exact reconstruction, and the original PR branch was advanced with an expected-head lease. No local Rust/Clippy execution was possible. The original HA failure remains unresolved.

Draft [PR 163](https://github.com/TrillionniumFoundation/HeptaBao/pull/163) remains unmerged. The new full workflow **42293086208** was observed in progress; trust-boundary workflow **42293086260** passed. The trust result is not full qualification. See [ci-observer-fix-and-restore-trace](ci-observer-fix-and-restore-trace/) and [the complete failed CI evidence package](ci42260689756-complete-failure/).

## Machine and migration boundary

| Machine | Actual evidence available | Not established |
|---|---|---|
| Mac / T5 | Complete captured-generation recovery/readback; r3 complete-row projection; normal layout/TLS; failed managed start; exact stopped binding repair | Initialized normal KV2 service, real credential API acceptance, cold service restore, real traffic cutover |
| ROG | Prior limited isolated product and diagnostic results; newly prepared empty private custody receiver | Transferred/verified share or normal-service archive, real multi-host voter acceptance, clients migrated |
| Pocket4 | Native reachability and newly prepared empty private custody receiver | Transferred/verified share or archive, real voter acceptance, clients migrated |
| X230 | Historical isolated OpenBao 2.7.1 dev reference | Complete actual OpenBao capability/history census, same-corpus formal comparison, host migration |

Empty receiver directories are not copied keys or independent backups. Existing normal/diagnostic tests and SDK subsets are not a complete client census. No dependent client, sync boundary, writer fence, or per-host rollback has received migration approval in this checkpoint.

## Next admissible actions

1. Consume the accepted, independently reconciled r3 current-data projection as the input to the later ordinary KV2 acceptance; retain r1/r2 failures and the original capture unchanged.
2. Obtain legitimate Mac authorization for the actual managed-service identity to access the T5 removable volume. No TCC database edit, protection disable, background SSH service, or path move is used to evade the denial. The exact identity must be resolved in the Mac's authorized UI or managed policy; no unobserved Settings app entry is assumed.
3. Implement/review a new existing-candidate resume admission using the repaired binding and a new private attempt directory, then perform exactly one managed start and first init. The [reviewed implementation plan](resume-plan/IMPLEMENTATION_PLAN.md) is prepared; the new entry is not implemented or ready for dispatch. The original create-only manager/init request must not be replayed.
4. Finish formal ordinary KV2: actual credential baseline/API reads and writes, complete versions/export, independent retained remote encrypted backup, cold restart, restore/tamper checks, rollback, and the same protocol/corpus OpenBao comparison.
5. Only after KV2 passes, run real Mac/ROG/Pocket4 HA. Continue to AuthBus, per-host client/sync validation and cutover, and finally cleanup in that order.

All failed observations remain part of the evidence. No single selected-test pass, diagnostic success, static patch, or prepared script clears a downstream gate.
