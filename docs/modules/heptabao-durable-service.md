# heptabao-durable-service

Current source binding: [docs/modules/CURRENT_SOURCE_BINDING.md](CURRENT_SOURCE_BINDING.md). Runtime integration: [docs/modules/CURRENT_RUNTIME_MAP.md](CURRENT_RUNTIME_MAP.md).

Current plan: `HEPTABAO-PLAN-2026-09-07-V2.1`. Shared cross-cutting rules are defined in `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This crate owns the restart-safe single-node mutation boundary: durable intent, Barrier-protected state publication, commit evidence, replay ledger publication, then acknowledgement. It does not authenticate callers, implement policy, provide TLS, claim HA, or select a production KMS/HSM. This crate supplies the durable storage component of the single-node server candidate; it does not by itself qualify that server for production.

## Public API and ownership

### Current API contract and integration boundary

`DurableService<B: Barrier>` owns the exclusive Linux directory guard, injected barrier, current snapshot, non-evicting request ledger and recovery classifications. `create_new(root, barrier, max_retained_requests)` requires an absolute safe empty/new root; `reopen` requires existing compatible files and performs recovery before returning. The capacity is 1–1,000,000 retained mutations. `WriterLocked`, `UnsupportedProfile`, `LegacySchema`, corruption and barrier failures must be handled without initializing over existing state. `Barrier::seal/open(&self, context, bytes)` must authenticate the supplied associated data and protect plaintext; the crate supplies the interface, not its production cryptography.

`PutRequest::new` and `DeleteRequest::new` consume an already authenticated principal, namespace, request ID, relative storage resource and nonzero authorization digest. Principal/request IDs are 1–256 ASCII alphanumeric or `-_.:` bytes. Namespace (at most 1024 bytes) and resource (at most 4096 bytes) are nonempty slash-separated paths without leading/trailing slash or traversal segments; segment characters are ASCII alphanumeric or `-_.`. `Secret::new` owns 1 byte through 1 MiB and uses `zeroize` on drop. These representations differ from `heptabao-domain::CanonicalPath` and require deliberate conversion.

`put`/`delete` consume the envelope and return `MutationOutcome::Committed` or an exact retained `Duplicate`, both with generation and recovery reference. The replay key is `(principal, namespace, request_id)`; resource, operation, authorization digest and value digest are part of its immutable binding. Changed bindings return `RequestBindingConflict`. A delete of an absent resource still commits a mutation identity/generation. `*_with_failpoint` exposes the same path with explicit test injection after intent, snapshot publication or commit journal. A failure after the first append attempt returns `ServiceError::OutcomeUnknown { recovery_reference }` and fences the live instance.

`get(namespace, resource)` returns an owned cloned `Option<Secret>`. `list(namespace, prefix)` returns sorted immediate child names, with `/` suffixes for directories and empty prefix selecting the namespace root. Both reject access while recovery is required; neither authenticates or authorizes. `reconcile(reference)` is a read-only lookup returning Committed, Aborted or Unknown, not a method to resolve or unfreeze a writer. Drop the fenced owner and `reopen` after fixing the storage cause, then query the preserved reference. A missing reference is Unknown, never evidence of non-entry.

`compact()` replaces the journal with an authenticated checkpoint while retaining the full replay ledger and generation; it recovers journal space, not request capacity. `export_backup()` returns the committed snapshot, full ledger and checkpoint in an encrypted bundle with no barrier key. `restore_backup(bytes, allow_rollback)` authenticates and checks the bundle before replacement; an older generation requires explicit `allow_rollback=true`. Replacement is atomic per file, not across all three files: interruption can leave a mixed set that is rejected on reopen. An I/O error from maintenance may leave `recovery_required()` true even when it is not the mutation-specific `OutcomeUnknown` variant. Operators must preserve the original coherent backup and fence traffic through restore and recovery.

This crate **is directly integrated** into `heptabao-server`: `service.rs` owns `Option<DurableService<AeadBarrier>>`, creates/reopens it during lifecycle operations and invokes its storage/maintenance methods. `/v1/sys/storage/raft/compact` calls `compact`; snapshot GET calls `export_backup`; snapshot/snapshot-force POST/PUT call `restore_backup` with rollback enabled only for force. The server rejects direct local restore while HA is enabled. The bundle is HeptaBao's format, not OpenBao Raft snapshot compatibility; native authentication, audit and HA ordering remain the server's responsibility.

### Historical V1.4.7 lexical snapshot

The following generated block is retained unchanged for historical verification. Its declarations and line numbers are not the current API contract; use the explanation above and the [current source binding](CURRENT_SOURCE_BINDING.md).

<!-- BEGIN GENERATED V1.4.7 PUBLIC API TRUTH; DO NOT EDIT -->
Source-bound lexical inventory: `crates/heptabao-durable-service`; Cargo SHA-256 `c421ca0c1a3e5535c845e32b38868481956ee8bd96ebf5229335223653e232ad`.

| Kind | Name | Source | Declaration |
|---|---|---|---|
| `struct` | `BarrierError` | `crates/heptabao-durable-service/src/lib.rs:40` | `pub struct BarrierError;` |
| `trait` | `Barrier` | `crates/heptabao-durable-service/src/lib.rs:54` | `pub trait Barrier {` |
| `struct` | `Secret` | `crates/heptabao-durable-service/src/lib.rs:60` | `pub struct Secret(Vec<u8>);` |
| `fn` | `new` | `crates/heptabao-durable-service/src/lib.rs:69` | `pub fn new(bytes: Vec<u8>) -> Result<Self, ServiceError> {` |
| `fn` | `expose` | `crates/heptabao-durable-service/src/lib.rs:77` | `pub fn expose(&self) -> &[u8] {` |
| `struct` | `PutRequest` | `crates/heptabao-durable-service/src/lib.rs:92` | `pub struct PutRequest {` |
| `fn` | `new` | `crates/heptabao-durable-service/src/lib.rs:102` | `pub fn new(` |
| `struct` | `DeleteRequest` | `crates/heptabao-durable-service/src/lib.rs:149` | `pub struct DeleteRequest {` |
| `fn` | `new` | `crates/heptabao-durable-service/src/lib.rs:158` | `pub fn new(` |
| `enum` | `Failpoint` | `crates/heptabao-durable-service/src/lib.rs:202` | `pub enum Failpoint {` |
| `enum` | `MutationOutcome` | `crates/heptabao-durable-service/src/lib.rs:210` | `pub enum MutationOutcome {` |
| `enum` | `ReconciliationStatus` | `crates/heptabao-durable-service/src/lib.rs:222` | `pub enum ReconciliationStatus {` |
| `struct` | `CompactionOutcome` | `crates/heptabao-durable-service/src/lib.rs:229` | `pub struct CompactionOutcome {` |
| `struct` | `RestoreOutcome` | `crates/heptabao-durable-service/src/lib.rs:237` | `pub struct RestoreOutcome {` |
| `enum` | `ServiceError` | `crates/heptabao-durable-service/src/lib.rs:244` | `pub enum ServiceError {` |
| `struct` | `DurableService` | `crates/heptabao-durable-service/src/lib.rs:404` | `pub struct DurableService<B: Barrier> {` |
| `fn` | `create_new` | `crates/heptabao-durable-service/src/lib.rs:441` | `pub fn create_new(` |
| `fn` | `reopen` | `crates/heptabao-durable-service/src/lib.rs:487` | `pub fn reopen(` |
| `fn` | `put` | `crates/heptabao-durable-service/src/lib.rs:517` | `pub fn put(&mut self, request: PutRequest) -> Result<MutationOutcome, ServiceError> {` |
| `fn` | `put_with_failpoint` | `crates/heptabao-durable-service/src/lib.rs:521` | `pub fn put_with_failpoint(` |
| `fn` | `delete` | `crates/heptabao-durable-service/src/lib.rs:546` | `pub fn delete(&mut self, request: DeleteRequest) -> Result<MutationOutcome, ServiceError> {` |
| `fn` | `delete_with_failpoint` | `crates/heptabao-durable-service/src/lib.rs:550` | `pub fn delete_with_failpoint(` |
| `fn` | `get` | `crates/heptabao-durable-service/src/lib.rs:570` | `pub fn get(&self, namespace: &str, resource: &str) -> Result<Option<Secret>, ServiceError> {` |
| `fn` | `list` | `crates/heptabao-durable-service/src/lib.rs:582` | `pub fn list(&self, namespace: &str, prefix: &str) -> Result<Vec<String>, ServiceError> {` |
| `const` | `fn` | `crates/heptabao-durable-service/src/lib.rs:612` | `pub const fn recovery_required(&self) -> bool {` |
| `fn` | `reconcile` | `crates/heptabao-durable-service/src/lib.rs:617` | `pub fn reconcile(&self, recovery_reference: &str) -> ReconciliationStatus {` |
| `const` | `fn` | `crates/heptabao-durable-service/src/lib.rs:625` | `pub const fn generation(&self) -> u64 {` |
| `fn` | `retained_request_count` | `crates/heptabao-durable-service/src/lib.rs:630` | `pub fn retained_request_count(&self) -> usize {` |
| `fn` | `compact` | `crates/heptabao-durable-service/src/lib.rs:640` | `pub fn compact(&mut self) -> Result<CompactionOutcome, ServiceError> {` |
| `fn` | `export_backup` | `crates/heptabao-durable-service/src/lib.rs:671` | `pub fn export_backup(&self) -> Result<Vec<u8>, ServiceError> {` |
| `fn` | `restore_backup` | `crates/heptabao-durable-service/src/lib.rs:696` | `pub fn restore_backup(` |

This table is generated from the exact candidate source. It is a bounded lexical inventory, not a stability or compatibility promise.
<!-- END GENERATED V1.4.7 PUBLIC API TRUTH -->

## State and data model

The root contains `state.hbs`, append-only `journal.hbj` and replace-by-generation `ledger.hbl`. Linux `ExclusiveDirectory` holds a descriptor-backed process lock; there is no sentinel lock file to survive SIGKILL. Every file operation uses the guarded `/proc/self/fd` directory path. The HBS2/HBP2 snapshot stores each key as **two independently length-prefixed strings, namespace and resource**, and an exact last-commit marker. `(a, b/c)` and `(a/b, c)` are distinct through write, reopen, list and delete. Journal events are intent, commit, abort or a leading authenticated checkpoint with contiguous sequence numbers. Ledger records bind the replay key to the exact operation digest, committed generation and service-generated recovery reference.

## Invariants and authorization

The crate accepts only pre-authorized envelopes and treats the non-zero authorization digest as immutable evidence, not as an authorization engine. Request identity is scoped to authenticated principal, canonical namespace and request ID, then exact-bound to operation, resource, authorization digest and value digest. A conflicting reuse, capacity overflow, stale generation, duplicate decoded key or contradictory persisted record fails before a second effect.

## Failure, retry and reconciliation

Validation, complete Barrier sealing and resource admission happen before the first append attempt. Once that attempt begins, **every real I/O or later failure** returns `OutcomeUnknown` with the allocated recovery reference; never blind retry. The live instance freezes mutation, get and list with `RecoveryRequired` until reopened. A failed append does not advance the in-memory sequence. The outcome reference remains `Unknown` if no complete intent ever reached disk; `Aborted` is returned only when authenticated intent evidence supports it. Reopen authenticates all files and validates a single linear journal: contiguous record sequences, one pending intent maximum, contiguous committed generations, exact terminal markers and unique committed identities. The snapshot must equal the committed journal frontier or the one published pending intent. The authenticated ledger header and records must be a complete prefix with at most the one permitted publication lag; contradictory or valid-but-older snapshots fail closed. Only a physically incomplete final journal frame may be truncated to its authenticated prefix; complete invalid frames fail closed. Recovery then aborts an unpublished intent or completes its published commit and rebuilds the ledger. A committed exact replay returns `Duplicate` without another mutation.

## Concurrency and ordering

One service instance holds the Linux process-scoped exclusive directory fence. Kernel descriptor cleanup releases it on abrupt process death, without inspecting PIDs or deleting lock files. Unsupported operating systems, unavailable `/proc` descriptor paths or failed file locking are hard errors with no path-based fallback. The required total order is intent journal, sealed state publication, commit journal, replay ledger, acknowledgement. File and directory synchronization occur before publication is reported. Cancellation, transport loss and process termination after entry preserve uncertainty; later work is fenced until authoritative reopen or reconciliation establishes the outcome.

## Security and privacy

Security binding digests use domain-separated SHA-256 with explicit length prefixes. The digest is not a signature and does not provide confidentiality, key custody or independent authenticity. Every persisted payload crosses the injected Barrier with distinct associated-data context; production Barrier implementations must use reviewed AEAD and isolated keys. Request objects redact secret, principal, namespace, request, resource and authorization fields; the service redacts its root. `MutationOutcome` and `ServiceError::OutcomeUnknown` derive Debug and expose recovery-reference strings, so adapters must avoid logging them directly or placing them in telemetry labels. Stored snapshot values and returned `Secret` values use `zeroize` on drop, including replacements, deletions and aborted candidate maps. Serialized/decrypted snapshot plaintext and pre-entry mutation buffers use `Zeroizing`. These controls cover owned buffers; they do not assert locked memory or complete erasure of allocator/provider/compiler copies.

## Persistence and compatibility

The persisted schema is HBS2/HBP2, HBJ2 and HBL2/HBC2, with v2 associated-data/frame domains. HBS1 is explicitly rejected as `LegacySchema` before any rewrite: its slash-concatenated keys cannot be split safely without an external authoritative namespace inventory. There is no silent reinterpretation. Snapshot/ledger have zero trailing-byte tolerance; journal tolerates only an incomplete final append after the authenticated prefix and cross-file consistency checks pass. File sizes are bounded to 64 MiB, individual secrets to 1 MiB, namespace to 1024 bytes, resource to 4096 bytes and retained requests to the configured bound. Local storage paths are canonical slash-separated names without a leading slash; the transport adapter owns the external `/v1/` route prefix. Snapshot and ledger replacement use temporary write, file sync, atomic rename and parent-directory sync; journal append is framed and synced. There is no implicit legacy adoption or online migration. A new format requires a separately versioned migration protocol, original preservation, interruption recovery and rollback policy.

## Observability

Safe counters include committed, duplicate, rejected-before-entry, outcome-unknown, recovered-committed, recovered-aborted, capacity-exhausted, writer-locked and corrupt-root. Labels must exclude identities, paths, ciphertext, digests and recovery references. The operator-facing value is the classification and generation, while detailed storage errors stay inside a redacted diagnostic boundary.

## Operations

Create-new requires an empty validated root; reopen requires all authoritative files and completes recovery before traffic. Operators preserve the root before destructive action, never delete one apparently corrupt file as a repair, and use the recovery/rollback-anchor procedures for restore. The service pre-seals and reserves both the intent and terminal journal frames before accepting a mutation. It refuses admission if the journal would exceed 64 MiB or 1,000,000 records, or snapshot/ledger would exceed 64 MiB. Recovery retains enough reserved room for the terminal frame with the fixed-overhead Barrier profile. No replay identity or aborted recovery reference is evicted. Automatic compaction remains deliberately unimplemented: a capacity stop requires a separately designed, validated checkpoint/epoch migration; copying or deleting journal bytes is not a supported workaround.

## Tests and executable evidence

Current executable anchors (source assertions, not a claim that tests were rerun for this documentation edit):

- [`tests::put_restart_read_and_duplicate_are_durable`](../../crates/heptabao-durable-service/src/lib.rs) checks persisted value and duplicate suppression after reopen.
- [`tests::genuine_snapshot_and_ledger_io_faults_preserve_recovery_reference`](../../crates/heptabao-durable-service/src/lib.rs) checks actual EISDIR publication faults fence the writer and preserve committed/aborted readback.
- [`tests::journal_budget_reserves_terminal_record_before_entry`](../../crates/heptabao-durable-service/src/lib.rs) checks journal exhaustion rejects before any intent append.
- [`tests::compaction_checkpoints_complete_ledger_and_allows_future_commits`](../../crates/heptabao-durable-service/src/lib.rs) checks checkpoint shrinkage retains old duplicate protection and accepts later commits/reopen.
- [`tests::encrypted_backup_restores_exact_generation_and_requires_explicit_rollback`](../../crates/heptabao-durable-service/src/lib.rs) checks older restore refusal, explicit rollback, value and retained duplicate identity.
- [`tests::actual_sigkill_releases_writer_and_recovers_pending_publication`](../../crates/heptabao-durable-service/src/lib.rs) checks Linux SIGKILL releases the kernel-held writer lock and reopens a published pending mutation.
- [`tests::real_partial_write_efbig_tail_is_recovered`](../../crates/heptabao-durable-service/src/lib.rs) checks a real RLIMIT_FSIZE partial journal write and later recovery.

Run `cargo test -p heptabao-durable-service`. Tests cover restart, intent-only abort, published-state reconciliation, missing-ledger reconstruction, duplicate suppression, exact-operation conflict, capacity without eviction, tuple-key write/read/list/delete across restart, HBS1 refusal, rollback and ledger contradictions, writer fencing, plaintext absence and tamper rejection. Linux process tests actually SIGKILL a writer after publication and verify recovery and fencing. A separate child uses RLIMIT_FSIZE with ignored SIGXFSZ to cause a real partially successful journal write followed by EFBIG; reopening repairs its incomplete tail and accepts later mutations. EISDIR filesystem faults at snapshot and ledger publication verify conservative outcome classification; append-open failure verifies unchanged sequence and successful recovery. `tests/repository/test_durable_runtime_v2_1.py` and `tests/repository/test_security_hashing_v2_1.py` bind source, documentation, truth files, digest construction and read-only CI.

## Evolution and open boundaries

Repository closure still requires terminal exact-head and prospective-main-merge gates plus current independent review. SIGKILL and kernel file-size-limit tests are process/filesystem evidence, not power-loss or block-device qualification. Production acceptance still requires AEAD/KMS qualification, durable external anti-rollback anchors, power-loss/storage campaigns, qualification of the implemented checkpoint/compaction and backup/restore protocols, SLOs, HA or an explicit single-node support decision, legal disposition and release authority. A coherent rollback of all authenticated files is not detectable without an external monotonic anchor; the implemented checks detect cross-file inconsistency and partial rollback.

```text
qualification: false
compatibility_claim: false
production_authority: false
migration_authority: false
release_authority: false
authority_effect: NONE
```

## Machine-verified source truth

The V1.4.7 generated facts below are a preserved historical snapshot. Current dependency/integration statements are given above; historic declaration/test counts are not a current completion measure.

<!-- BEGIN GENERATED V1.4.7 MODULE FACTS; DO NOT EDIT -->
- Crate: `heptabao-durable-service`
- Crate path: `crates/heptabao-durable-service`
- Cargo manifest SHA-256: `c421ca0c1a3e5535c845e32b38868481956ee8bd96ebf5229335223653e232ad`
- Rust source files: `1`
- Public lexical declarations: `31`
- Discovered test functions: `21`
- Workspace-internal dependencies: `heptabao-filesystem-guard` (dependencies)
- Authoritative inventory: `planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml`
- Regeneration: `python scripts/render_plan_v1_4_7.py --write`
- Verification: `python scripts/render_plan_v1_4_7.py --check`
<!-- END GENERATED V1.4.7 MODULE FACTS -->
