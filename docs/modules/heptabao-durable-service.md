# heptabao-durable-service

Current plan: `HEPTABAO-PLAN-2026-09-07-V2.1`. Shared cross-cutting rules are defined in `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This crate owns the restart-safe single-node mutation boundary: durable intent, Barrier-protected state publication, commit evidence, replay ledger publication, then acknowledgement. It does not authenticate callers, implement policy, provide TLS, claim HA, or select a production KMS/HSM. This crate supplies the durable storage component of the single-node server candidate; it does not by itself qualify that server for production.

## Public API and ownership

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

The root contains `state.hbs`, append-only `journal.hbj` and replace-by-generation `ledger.hbl`. Linux `ExclusiveDirectory` holds a descriptor-backed process lock; there is no sentinel lock file to survive SIGKILL. Every file operation uses the guarded `/proc/self/fd` directory path. The HBS2/HBP2 snapshot stores each key as **two independently length-prefixed strings, namespace and resource**, and an exact last-commit marker. `(a, b/c)` and `(a/b, c)` are distinct through write, reopen, list and delete. Journal events are intent, commit or abort with contiguous sequence numbers. Ledger records bind the replay key to the exact operation digest, committed generation and service-generated recovery reference.

## Invariants and authorization

The crate accepts only pre-authorized envelopes and treats the non-zero authorization digest as immutable evidence, not as an authorization engine. Request identity is scoped to authenticated principal, canonical namespace and request ID, then exact-bound to operation, resource, authorization digest and value digest. A conflicting reuse, capacity overflow, stale generation, duplicate decoded key or contradictory persisted record fails before a second effect.

## Failure, retry and reconciliation

Validation, complete Barrier sealing and resource admission happen before the first append attempt. Once that attempt begins, **every real I/O or later failure** returns `OutcomeUnknown` with the allocated recovery reference; never blind retry. The live instance freezes mutation, get and list with `RecoveryRequired` until reopened. A failed append does not advance the in-memory sequence. The outcome reference remains `Unknown` if no complete intent ever reached disk; `Aborted` is returned only when authenticated intent evidence supports it. Reopen authenticates all files and validates a single linear journal: contiguous record sequences, one pending intent maximum, contiguous committed generations, exact terminal markers and unique committed identities. The snapshot must equal the committed journal frontier or the one published pending intent. The authenticated ledger header and records must be a complete prefix with at most the one permitted publication lag; contradictory or valid-but-older snapshots fail closed. Only a physically incomplete final journal frame may be truncated to its authenticated prefix; complete invalid frames fail closed. Recovery then aborts an unpublished intent or completes its published commit and rebuilds the ledger. A committed exact replay returns `Duplicate` without another mutation.

## Concurrency and ordering

One service instance holds the Linux process-scoped exclusive directory fence. Kernel descriptor cleanup releases it on abrupt process death, without inspecting PIDs or deleting lock files. Unsupported operating systems, unavailable `/proc` descriptor paths or failed file locking are hard errors with no path-based fallback. The required total order is intent journal, sealed state publication, commit journal, replay ledger, acknowledgement. File and directory synchronization occur before publication is reported. Cancellation, transport loss and process termination after entry preserve uncertainty; later work is fenced until authoritative reopen or reconciliation establishes the outcome.

## Security and privacy

Security binding digests use domain-separated SHA-256 with explicit length prefixes. The digest is not a signature and does not provide confidentiality, key custody or independent authenticity. Every persisted payload crosses the injected Barrier with distinct associated-data context; production Barrier implementations must use reviewed AEAD and isolated keys. Secret, principal, namespace, request, resource, root and recovery-reference surfaces are redacted from Debug and telemetry labels. Stored snapshot values and returned `Secret` values use `zeroize` on drop, including replacements, deletions and aborted candidate maps. Serialized/decrypted snapshot plaintext and pre-entry mutation buffers use `Zeroizing`. These controls cover owned buffers; they do not assert locked memory or complete erasure of allocator/provider/compiler copies.

## Persistence and compatibility

The persisted schema is HBS2/HBP2, HBJ2 and HBL2/HBC2, with v2 associated-data/frame domains. HBS1 is explicitly rejected as `LegacySchema` before any rewrite: its slash-concatenated keys cannot be split safely without an external authoritative namespace inventory. There is no silent reinterpretation. Snapshot/ledger have zero trailing-byte tolerance; journal tolerates only an incomplete final append after the authenticated prefix and cross-file consistency checks pass. File sizes are bounded to 64 MiB, individual secrets to 1 MiB, namespace to 1024 bytes, resource to 4096 bytes and retained requests to the configured bound. Local storage paths are canonical slash-separated names without a leading slash; the transport adapter owns the external `/v1/` route prefix. Snapshot and ledger replacement use temporary write, file sync, atomic rename and parent-directory sync; journal append is framed and synced. There is no implicit legacy adoption or online migration. A new format requires a separately versioned migration protocol, original preservation, interruption recovery and rollback policy.

## Observability

Safe counters include committed, duplicate, rejected-before-entry, outcome-unknown, recovered-committed, recovered-aborted, capacity-exhausted, writer-locked and corrupt-root. Labels must exclude identities, paths, ciphertext, digests and recovery references. The operator-facing value is the classification and generation, while detailed storage errors stay inside a redacted diagnostic boundary.

## Operations

Create-new requires an empty validated root; reopen requires all authoritative files and completes recovery before traffic. Operators preserve the root before destructive action, never delete one apparently corrupt file as a repair, and use the recovery/rollback-anchor procedures for restore. The service pre-seals and reserves both the intent and terminal journal frames before accepting a mutation. It refuses admission if the journal would exceed 64 MiB or 1,000,000 records, or snapshot/ledger would exceed 64 MiB. Recovery retains enough reserved room for the terminal frame with the fixed-overhead Barrier profile. No replay identity or aborted recovery reference is evicted. Automatic compaction remains deliberately unimplemented: a capacity stop requires a separately designed, validated checkpoint/epoch migration; copying or deleting journal bytes is not a supported workaround.

## Tests and executable evidence

Run `cargo test -p heptabao-durable-service`. Tests cover restart, intent-only abort, published-state reconciliation, missing-ledger reconstruction, duplicate suppression, exact-operation conflict, capacity without eviction, tuple-key write/read/list/delete across restart, HBS1 refusal, rollback and ledger contradictions, writer fencing, plaintext absence and tamper rejection. Linux process tests actually SIGKILL a writer after publication and verify recovery and fencing. A separate child uses RLIMIT_FSIZE with ignored SIGXFSZ to cause a real partially successful journal write followed by EFBIG; reopening repairs its incomplete tail and accepts later mutations. EISDIR filesystem faults at snapshot and ledger publication verify conservative outcome classification; append-open failure verifies unchanged sequence and successful recovery. `tests/repository/test_durable_runtime_v2_1.py` and `tests/repository/test_security_hashing_v2_1.py` bind source, documentation, truth files, digest construction and read-only CI.

## Evolution and open boundaries

Repository closure still requires terminal exact-head and prospective-main-merge gates plus current independent review. SIGKILL and kernel file-size-limit tests are process/filesystem evidence, not power-loss or block-device qualification. Production acceptance still requires AEAD/KMS qualification, durable external anti-rollback anchors, power-loss/storage campaigns, a checkpoint/compaction protocol and SLOs, HA or an explicit single-node support decision, legal disposition and release authority. A coherent rollback of all authenticated files is not detectable without an external monotonic anchor; the implemented checks detect cross-file inconsistency and partial rollback.

```text
qualification: false
compatibility_claim: false
production_authority: false
migration_authority: false
release_authority: false
authority_effect: NONE
```

## Machine-verified source truth

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
