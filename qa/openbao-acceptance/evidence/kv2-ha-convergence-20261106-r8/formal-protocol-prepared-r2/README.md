# Normal KV2 protocol and recovery module — integration draft

This directory contains executable protocol code and seven narrow refusal guards. It has **not** run against a service, a real credential projection, a TLS endpoint, or an archive. The local guard results establish only the tested refusal boundaries. They do not grant formal storage, HA, AuthBus, client cutover, rollback, or cleanup authority.

## Ownership and required inputs

`formal_kv2_protocol.py` owns protocol operations, private evidence, complete row/history checks and recovery. `formal_kv2_wire.py` is its single-request TLS child. The separate lifecycle adapter owns launchd, initialization, three-way share custody, the acknowledged preactivation seed, cold restart and the fresh restore target. No server launcher or live SQLite reader is included here.

The integration controller must pin these files, the frozen `lifecycle_contract.py` and `lifecycle_observations.py`, the a257 pure helper files listed in `HELPER_PINS`, and the 669e original-process custody helper. The controller must admit actual normal server/seed binaries from the completed build receipt, validate the actual source/configuration/plist/TLS/custody inputs, install the original process owner and a sticky deadline handler, and retain its actual Runtime terminal and full private child-custody receipt. These external observations cannot be replaced with constructed dataclasses or a `passed` Boolean.

The module accepts the existing **independently verified restored SQLite generation**, not live databases. `ProjectionSource` binds the complete readback result, authoritative terminal, final stdout, private closure, restored capture manifest and a new private allrows projection. `ReadbackGenerationAdapter` reconciles the existing eleven readback obligations and final handle closure; it does not repeat the multi-gigabyte copy or read the live source. Projection validation recomputes every configured agent's complete two-table row commitment and both row counts. There is no hardcoded five-agent or primary-row filter.

The private projection schema is `heptabao.current-sqlite-allrows-to-kv2.private.v1`, with `capture_sha256` and `rows`. Every row has exactly `record_id`, `agent_slot`, `table`, `row_fields`, `kv_mount`, and `kv_key`. The exact tables/columns are:

| Table | Complete columns |
| --- | --- |
| `auth_profile_store` | `store_key`, `store_json`, `updated_at` |
| `auth_profile_state` | `state_key`, `state_json`, `updated_at` |

Agent slots follow the actual capture manifest's agent database order. Missing/empty agent databases have no rows. SQL cells retain the capture producer's encoding, including JSON text as text. Each business row becomes a new KV2 **version 1**, written once with CAS 0. The row's source time and restored-generation commitment remain provenance fields; they are not forged as OpenBao version timestamps. No prior OpenBao history or deletion/destruction history is claimed. The separate canary mount creates actual versions 1–3, soft-deletes version 1, destroys version 2 and tests data/metadata CAS.

## Two independent, predeclared phases

| Phase | Entry | Successful status | Source writes |
| --- | --- | --- | --- |
| Snapshot | `ProtocolRun.snapshot_ready()` | `awaiting_remote_backup_custody` | One activation, one CAS0 per business row, fixed canary sequence |
| Recovery | `ProtocolRun.resume_recovery(ResumeInputs(...))` | `passed_protocol_only` | None; only read APIs and the read-only raw-witness POST |

Each entry receives a separately predeclared `Deadline(original_entry, work_end, total_end, phase)`. It cannot reset that phase's clock. HTTP requests have a single absolute 15-second budget, including their original owned child. There is no automatic mutation retry. No phase waits for an external MCP transfer. The outer controller must provide the fixed overall phase budgets before launch and must fail the whole phase on any timer/custody/final-persistence failure.

### Snapshot phase

After admitting the actual restored generation, exact endpoint and seed, the module checks pristine default mounts, activates ordinary `native_v6_file`, writes all business rows once, and runs the canary sequence. It verifies all API versions, key/configuration metadata, complete raw-storage witnesses and current lossless exports. It cold-restarts the manager-owned source and repeats the full history checks, downloads the current native snapshot, verifies its complete canonical gzip/tar/member/checksum/HBV6PK01 structure, then verifies the source is unchanged and still owned by the long-lived manager.

It writes `snapshot-continuation.private.json` with create-only semantics, file fsync and directory fsync. This binds source/plan/code identity, every executed operation's original intent and result, every business payload and version, complete current exports, the current snapshot, and the actual persistent manager handoff. A mutation's intent file and directory entry are persisted **before dispatch**. Public output contains only fixed status/obligation names, counts and scope flags.

No restore target is created in this phase. `normal_kv2_protocol_completed`, `formal_service_qualified`, and `independent_remote_archive_custody_verified` remain false. The outer controller completes its actual short-child cleanup and retains the full custody receipt; its successful authoritative terminal is an additional requirement for any later recovery entry.

### Remote archive custody — performed by the parent between phases

The actual layout places service data on T5 and TLS/root/share 1 on the Mac Data volume; shares 2 and 3 have separate ROG/Pocket4 custody. Requiring a Mac backup directory to differ from both the data and key filesystems is impossible on this two-filesystem layout. The previous synthetic DR's three-local-role filesystem guard is **not silently reused**.

The module instead names the Data directory `archive_staging_dir`. It must be private, disjoint from source/keys/evidence and on a different filesystem from source data. Co-location with the Data filesystem containing share 1 grants no independent-backup qualification. Different `st_dev` values alone do not prove a physical failure domain.

`RemoteBackupBinding` requires the parent-reviewed actual remote host, destination, owner, two native file_info originals, the independently returned complete local archive file, and the archive-only transfer originals. The parent performs a create-only upload to ROG, independent native file_info before/after, fixed-version full chunk readback, and a separate create-only Mac readback file. Requests must preserve actual host/path/expected_version and all responses/chunks. Share-transfer evidence is separate from the archive envelope.

The module parses actual native metadata (`mode` is an integer), requires 0600/one link/expected owner, exact before/after identity/version/size/hash, verifies every supplied original pin, and compares every byte of the independent readback to the staged snapshot. The two local files must have different device/inode pairs. **Native JSON does not authenticate its own host**: the qualification combines the parent's independent original-tool authority review with the module's actual file/byte checks. A fabricated or unaudited JSON envelope is not sufficient.

### Recovery phase

Use a new evidence directory and a new predeclared phase deadline, while keeping the same source/seed/generation/staging/key binding. `ResumeInputs` supplies the exact continuation, phase-one public result, original authoritative Runtime terminal, complete original process-custody receipt, and `RemoteBackupBinding`. The original phase must have finished successfully; unknown or failed partial mutations have no resume path.

Before any restore mutation, the module checks the frozen code/plan and full prior operation ledger, the original one-time business CAS0/activation/snapshot denominator, the same retained source manager, the unchanged source's complete current history and the unchanged staged archive. It admits the completed remote readback and uses **that returned file** as the restore input. It cannot call the activation/import path or mutate the source canary.

The lifecycle adapter then provides a genuinely fresh, distinct manager/data directory staged from the original four-file bootstrap seed. API and raw witnesses first prove all current versions are missing. The module submits one bad sealed-checksum archive, requires rejection and unchanged state after cold restart, restores the valid archive once, verifies complete history before/after cold restart, proves soft-delete recovery and destroyed-version absence, persists a new canary version 4 across restart, and restores the original snapshot to roll back **that independent restore target only**. It finally proves the source remains unchanged, retires only the fresh target's manager, retains all target files and hands the original long-lived source back explicitly.

The source service and real traffic have **no rollback qualification** from this operation. HA, AuthBus, per-host cutover and cleanup remain separate later gates. Every failure or unknown outcome is retained and stops the phase; no automatic rerun, retry, deletion or replacement occurs.

## Lifecycle observation contract

`LifecycleObservations(helpers, expected_binary_sha256=..., raw_original_pins=...)` forwards restart/retirement checks to the exact frozen observation helper. The concrete lifecycle adapter must register every returned original private file in the live `path -> PrivatePin` mapping before returning an observation. The thin wrapper reads and matches those originals; it is not an authority oracle.

`seed()` requires actual 3/2 shares, acknowledgement, preactivation/no business writes, exact four files, the actual native seed-export receipt, original seed child completion and exclusive writer fence. A seed remains bootstrap only. `restore_target()` requires the actual native `stage` receipt with the same seed/manifest and the exact target directory. `handoff()` requires actual manager identity, strict TLS, unsealed threshold status, normal healthy non-HA state, exact launchd ownership and every short child's original completion. Long-lived servers are launchd children; the controller never claims it waitpid-reaped the server.

The named mapping shapes are in the class itself. Frozen peer validators remain unchanged. Manager/TLS/seal/private data references never appear in public output. A different actual launchd topology must be reviewed explicitly rather than represented by an invented compatible observation.

## Encryption and archive scope

At product source `9c68b95b152a468ab378b68730e9e3f04e6a7100`, `service_snapshot_v6.rs` stages native encrypted object backups using the current barrier and seals the checksum binding. `heptabao-durable-service/src/v6_object_backup.rs::export_v6_backup_to` verifies the graph and emits ciphertext records with an authenticated footer; physical size reflects unique encrypted objects and is not a lower bound on logical KV history. Restore verifies sealed sums and the same seal identity before publication. `service_native_cold_seed.rs` requires the configured threshold shares to unwrap the barrier key.

The archive therefore does not supply plaintext business rows or an unseal threshold by itself. That does not make local staging an independent backup. Current exact source citations and the File-to-Raft full-history export/import boundary are in the separately retained `ACTIVE_FILE_TO_RAFT_BRIDGE.md` audit. Ordinary HBV6PK01 snapshots are not admitted by `recover-ha` as HA archives.

## Validation and remaining integration

`guard-evidence/guard-r3.public.json` binds the current code and the actual seven local guard results: unknown mutation stops, known denial stops, wrong endpoint/restore/business destruction is never dispatched, recovery cannot reactivate/reimport/write source, missing dynamic agent/state/nonprimary rows fail, missing destroyed/soft-deleted history fails, and raw witnesses retain the actual mount/key/version identity. These are small boundary checks, not a mocked full acceptance workflow. Earlier guard outputs are retained; the first six-test output is explicitly a transcription from its completed tool result, not a reconstructed OS stream.

The remaining actual integration work is the outer fixed controller plus the concrete lifecycle adapter, private projection producer, completed remote transfer envelope and safe final evidence projection. It must run actual TLS/manager/restore operations and independently reconcile their real terminal and private/public outputs before making any stronger claim. The module itself has no standalone command-line launcher.


## Revision 2: original wire log descriptors

The original revision-1 source and evidence remain unchanged. Revision 2 changes only `OwnedWire`; all other protocol classes/functions and top-level assignments are structurally identical, including the twelve pure definitions and four constants selected by the allrows projection controller. The current projection stage therefore retains its original exact f937 input. No source file used by that staged projection was silently replaced. A later actual protocol controller must explicitly pin this new source; it must not pretend the projection executed the network wire.

The fixed 669e process owner now holds its existing `protected` scope from the start of log-file creation through the original bounded request and cleanup. Its signal handler still records `failed` and `interrupted` immediately. A pending interruption prevents dispatch or consumption of a successful reply. No timer is reset and the original HTTP absolute deadline remains at most fifteen seconds; cancellation during communication may defer its exception until this existing bounded operation reaches cleanup. The outer controller must route its deadline to that same owner mechanism and still independently gate its sticky deadline and authoritative terminal. This does not authorize a non-cooperating signal handler that raises through the protected scope.

Each original stdout/stderr descriptor is recorded immediately after birth and before its first `fstat`. Cleanup records sync and one close attempt, and does not retry an ambiguous close on a potentially reused numeric descriptor. A separate private handle receipt records that exact scope. It is not a receipt for all process-wide file descriptors or for the leaf's internal TLS socket. The existing original-child custody, wait-once and no-live-descendant checks remain necessary. Cleanup failure marks the owner failed; it cannot replace the original exception or make a failed/unknown request succeed.

The local original log in `guards-r1` records ten successful tests: the seven previous protocol refusal guards plus three focused log-descriptor guards. The latter use the real fixed custody owner and ordinary short Python children, actual self-SIGTERM delivery at each log-file birth and during cleanup, first-fstat failure, and actual numeric descriptor reuse after an ambiguous close. These tests execute no product binary, TLS connection, provider call or real credential. Actual formal-service, backup, HA and cutover gates remain unqualified.
