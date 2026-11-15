# Native V6 snapshot clock inheritance — R4

## Status and exact source

This candidate is **not compiled or executed** in the agent workspace. There is no local Rust toolchain. All implementation and review here are local; the parent owns GitHub persistence and actual Mac/Linux/X230 execution.

Base: `36ee52ace6351dc92bea5accadabee32e5803c17`, tree `ef9a9c4783d39deec49d39c16edee3767823a3ae`. The eight existing files in the overlay were checked byte-for-byte against that tree's Git blob identities; the four new paths are absent from the base tree. The witness test is based on `ab1b480cefd7fa4accb743a316a129c0b10d6de5`, preserving the actual-response diagnostic added in 36ee.

Frozen payload: `native-v6-snapshot-clock-r4-overlay.json`, 813862 bytes, SHA256 `9b8176206bad0be0389d3530aee1c79df2107fe013376a35b46f61e4df9a2d58`.

Frozen unified diff: `native-v6-snapshot-clock-r4.patch`, 44422 bytes, SHA256 `6fab7a98baa3f2dc30179f1f06314d1ab19abd30eda086fd781a71b1e0729dd6`.

## Actual failure addressed

The earlier Mac 0f1c run executed 55 cases: 53 passed and two failed. The separate 36ee diagnostic run executed 13 cases: import 8/8 passed, witness 4/5 passed. Its actual snapshot restore returned HTTP 400 with `Token API precise observation floor cannot decrease`.

The saved snapshot carries the earlier authenticated Auth clock. Real ordinary admission and later requests legitimately advance the live precise Token API floor. The old single-node native restore authenticated the entire archived graph and then required that older Auth clock to be a successor of the current clock. Its rejection was correct for the values supplied to the validator; the missing operation was a legal, persisted clock-only projection of that authenticated archive.

The original failure files are not edited. Exact paths, lengths and SHA256 values are in `source-and-evidence.json`. No earlier failure is reclassified as a pass.

## Product changes and invariants

1. The server first authenticates the original archive pack, native root, original source cursor and complete typed graph exactly as before. The original Actor, root namespace, physical seal, activation, live State identity and request deadline remain active. HA continues down its existing separate path.

2. The already existing Auth and Engine clock inheritance helpers copy only monotone time fields. Their custody/format checks remain active. The entire existing `validate_snapshot_protected_floor` chain still runs against the live State. Its schema, namespace, SDK registration/retirement, revocation, provider, reader-floor and other protected-owner checks are not removed or replaced. The original incoming schema is checked before assigning a new replay epoch.

3. A private typed projection retains the complete original KV1/KV2 graph references, address material and all root fields except the new replay epoch and the two clock-bearing owners. It serializes the typed owners, independently verifies that every non-Auth/Engine root field and owner is byte-identical to the original authenticated root, and fully reopens the derived graph with the actual original archive as the fallback object source. It does not render public JSON or re-encode any KV payload.

4. The derived generation is `max(live_generation, archive_generation) + 1`; the derived replay epoch is `max(live_epoch, archive_epoch) + 1`. Overflow rejects. The original active cursor is advanced with its existing checks and still binds the retained migration source. No old generation or archived replay acknowledgement is attached to the changed root.

5. The durable derivation keeps the exact original `PreparedRestore` instance and frontier. Its source check covers live and archived roots, generations and epochs; the sealed derivation marker also commits the exact changed resource names and value digests. The helper has no publication side effects. All fallible work completes before it replaces the in-memory prepared handle.

6. An owner object already present in the archive is read from that archive and compared exactly. If the projected owner is instead already registered in the live source, the helper opens the actual registered immutable pin, verifies its physical profile, reads its real ciphertext under the same gate, authenticates it with the slot AAD and compares the plaintext. It preserves that exact ciphertext and slot. It does not randomly re-encrypt the same immutable address and does not repair corrupted registered files. New owner ciphertexts are allowed only for previously absent owner resources. Existing object count, per-object, cumulative ciphertext, opaque-owner and sealed-file bounds remain active.

7. The root, cursor, new owner slots, sealed snapshot, fresh replay ledger and checkpoint journal enter the same existing `restore_prepared` FileIntent/backend CAS transaction. There is no second durable write to repair a floor after restore. Object publication and exact pinned-ciphertext comparison remain in the existing restore loop. Unknown publication outcomes keep their existing fences and require reopening; there is no automatic mutation retry.

8. `PreparedV6Restore::size()` retains the authenticated **source archive** facts. Response `source_generation` and `source_replay_epoch` identify those facts; `restored_generation` and `replay_epoch` identify the actually installed new checkpoint. `rollback` means the archived logical source predates the previous live generation. The low-level `allow_rollback=false` check uses source generation before staging, so deriving a newer checkpoint cannot bypass that policy. This last guard was a concrete independent review finding and is included in R4.

9. The Auth module, Engine module and control-group helper each enable their existing clock helper under either the native Service fixture feature or the original experimental HA feature. This avoids accidentally compiling only when the HA feature also happens to be enabled. No new public route is added.

## Meaningful regression changes, with the same 55-case cohort

No test function is deleted, renamed or added. No original request deadline is raised. The existing negative-zero, exact canonical hash, soft-delete, destroyed-version, metadata, actual payload AEAD read and ordinary API projection assertions remain.

The existing function `service::native_kv2_storage_witness::tests::native_kv2_storage_witness_service_import_cold_and_snapshot_keep_exact_payloads` additionally captures the actual admitted Auth floor after ordinary entry. A `cfg(test)` observer receives only `&Service` after the real canonical restore transaction succeeds and before the outer terminal clock/audit work. It verifies the stored typed root selects the admitted Auth bytes, that the floor already exists in that same commit, and that the generation/epoch are fresh. This prevents a later terminal clock write from masking a missing atomic restore-time floor.

After normal API completion, the test drops the Service and runs the actual cold Service unseal path, paused before its outer terminal clock write. It checks the exact persisted generation, epoch, Auth digest and precise floor. It then reopens through the original public request helper and retains the original actual history/witness/negative-zero checks. The private cold observation is storage evidence, not an API success receipt.

The existing function `service::native_kv2_storage_witness::tests::native_kv2_storage_witness_service_rejects_scope_parameters_and_terminal_owner_change` additionally creates an actual native snapshot before Token API precision custody exists, issues a real token afterward, and attempts to restore that older snapshot. The request must return 400, retain its current owner, and preserve the live data and token across an actual cold reopen. This proves copying a time field cannot invent an archived format/custody label. All its previous unauthorized, no-sudo, malformed-parameter and after-audit owner veto assertions remain.

The third Service witness function retains the original real six-second token expiry and fifteen-second request budget unchanged.

## Actual next execution

The immediate selected regression group is `native_kv2_storage_witness_` (five existing cases), followed by the existing snapshot and import groups and the same complete 55-case cohort on the exact integrated source. The actual binary build remains required. A native-Service-only feature compilation is also needed to prove the three broadened cfg declarations without relying on experimental HA being enabled.

The derived graph has one additional full validation pass under the same original deadline. R4 does not claim its performance fits the physical 34 MiB/LAN workflow until the parent actually runs it. Existing raw failures, source manifests and per-platform receipts must remain separate from new execution evidence.

Passing these scoped regressions would establish this recovery behavior only. It would not by itself prove production credentials, multi-machine HA failover, traffic cutover, old-service removal, or full OpenBao 2.7.1 replacement.
