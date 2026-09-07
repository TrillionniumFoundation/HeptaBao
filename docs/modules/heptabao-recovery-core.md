# `heptabao-recovery-core` developer guide

**Source baseline:** `3582fda50cd9b03ca39713814cdd8229462bbbd2`  
**Source tree:** `123c99b71c7e33169bef6033eaefb71e386ed6ca`  
**Owner role:** `recovery-storage-audit-security`  
**Maturity:** `ANCHORED_RECOVERY_FOUNDATION_IMPLEMENTED`  
**Authority effect:** `NONE`

## Purpose and non-goals

Creates, authenticates, decodes, verifies and stages bounded recovery archives tied to current rollback checkpoints.

This crate does not by itself grant qualification, compatibility, production, migration or release authority. It must not be used to infer behavior outside the currently declared profile.

## Maturity and authority boundary

The source is a bounded foundation component. Technical tests establish only the checked invariants on the exact source. Production provider selection, independent review and an authority grant are separate objects.

## Ownership and trust boundary

- Authoritative writer: an injected recovery target publisher after verification.
- Accountable owner role: `recovery-storage-audit-security`.
- Inputs from clients, storage, providers, plugins, clocks, filesystems and evidence stores are untrusted unless explicitly wrapped by a verified type.
- Callers may not bypass typed constructors or reinterpret an error as success.

## Dependency contract

Direct HeptaBao dependencies:
- `heptabao-barrier-api`
- `heptabao-journal-api`
- `heptabao-rollback-anchor`
- `heptabao-storage-api`

Reverse HeptaBao dependants:
- `none`

The allowed direction follows the system crate graph: provider-neutral types and APIs do not depend on adapters; governance and Oracle tooling do not enter the product authority path.

## Public API index

<!-- BEGIN GENERATED V1.4.7 PUBLIC API TRUTH; DO NOT EDIT -->
Source-bound lexical inventory: `crates/heptabao-recovery-core`; Cargo SHA-256 `951bd09462faa2e6936dcf86b5f9a95ebc4f67654a6712dc345b9842abd4ced6`.

| Kind | Name | Source | Declaration |
|---|---|---|---|
| `const` | `MAX_RECOVERY_ID_BYTES` | `crates/heptabao-recovery-core/src/lib.rs:29` | `pub const MAX_RECOVERY_ID_BYTES: usize = 128;` |
| `const` | `MAX_RECOVERY_AUTHENTICATOR_ID_BYTES` | `crates/heptabao-recovery-core/src/lib.rs:30` | `pub const MAX_RECOVERY_AUTHENTICATOR_ID_BYTES: usize = 128;` |
| `const` | `MAX_RECOVERY_STATE_BYTES` | `crates/heptabao-recovery-core/src/lib.rs:31` | `pub const MAX_RECOVERY_STATE_BYTES: usize = 16 * 1024 * 1024;` |
| `const` | `MAX_RECOVERY_RECORDS` | `crates/heptabao-recovery-core/src/lib.rs:32` | `pub const MAX_RECOVERY_RECORDS: usize = 100_000;` |
| `const` | `MAX_RECOVERY_PAYLOAD_BYTES` | `crates/heptabao-recovery-core/src/lib.rs:33` | `pub const MAX_RECOVERY_PAYLOAD_BYTES: usize = 64 * 1024 * 1024;` |
| `struct` | `RecoveryArchiveId` | `crates/heptabao-recovery-core/src/lib.rs:36` | `pub struct RecoveryArchiveId(String);` |
| `fn` | `new` | `crates/heptabao-recovery-core/src/lib.rs:39` | `pub fn new(value: String) -> Result<Self, RecoveryContractError> {` |
| `fn` | `as_str` | `crates/heptabao-recovery-core/src/lib.rs:46` | `pub fn as_str(&self) -> &str {` |
| `struct` | `RecoveryAuthenticatorId` | `crates/heptabao-recovery-core/src/lib.rs:58` | `pub struct RecoveryAuthenticatorId(String);` |
| `fn` | `new` | `crates/heptabao-recovery-core/src/lib.rs:61` | `pub fn new(value: String) -> Result<Self, RecoveryContractError> {` |
| `fn` | `as_str` | `crates/heptabao-recovery-core/src/lib.rs:68` | `pub fn as_str(&self) -> &str {` |
| `struct` | `RecoveryTag` | `crates/heptabao-recovery-core/src/lib.rs:93` | `pub struct RecoveryTag([u8; 32]);` |
| `fn` | `new` | `crates/heptabao-recovery-core/src/lib.rs:96` | `pub fn new(value: [u8; 32]) -> Result<Self, RecoveryContractError> {` |
| `const` | `fn` | `crates/heptabao-recovery-core/src/lib.rs:103` | `pub const fn bytes(self) -> [u8; 32] {` |
| `struct` | `RecoveryRecord` | `crates/heptabao-recovery-core/src/lib.rs:115` | `pub struct RecoveryRecord {` |
| `fn` | `from_journal_record` | `crates/heptabao-recovery-core/src/lib.rs:123` | `pub fn from_journal_record(record: JournalRecord) -> Self {` |
| `const` | `fn` | `crates/heptabao-recovery-core/src/lib.rs:132` | `pub const fn sequence(&self) -> JournalSequence {` |
| `const` | `fn` | `crates/heptabao-recovery-core/src/lib.rs:136` | `pub const fn previous_tag(&self) -> Option<JournalTag> {` |
| `const` | `fn` | `crates/heptabao-recovery-core/src/lib.rs:140` | `pub const fn tag(&self) -> JournalTag {` |
| `fn` | `payload` | `crates/heptabao-recovery-core/src/lib.rs:144` | `pub fn payload(&self) -> &[u8] {` |
| `fn` | `into_journal_record` | `crates/heptabao-recovery-core/src/lib.rs:148` | `pub fn into_journal_record(mut self) -> Result<JournalRecord, RecoveryContractError> {` |
| `type` | `RecoveryImageParts` | `crates/heptabao-recovery-core/src/lib.rs:178` | `pub type RecoveryImageParts = (` |
| `struct` | `RecoveryImage` | `crates/heptabao-recovery-core/src/lib.rs:188` | `pub struct RecoveryImage {` |
| `fn` | `new` | `crates/heptabao-recovery-core/src/lib.rs:198` | `pub fn new(` |
| `fn` | `archive_id` | `crates/heptabao-recovery-core/src/lib.rs:222` | `pub fn archive_id(&self) -> &RecoveryArchiveId {` |
| `const` | `fn` | `crates/heptabao-recovery-core/src/lib.rs:226` | `pub const fn authenticator_id(&self) -> &RecoveryAuthenticatorId {` |
| `const` | `fn` | `crates/heptabao-recovery-core/src/lib.rs:230` | `pub const fn observation(&self) -> &CheckpointObservation {` |
| `const` | `fn` | `crates/heptabao-recovery-core/src/lib.rs:234` | `pub const fn checkpoint(&self) -> &RecoveryCheckpoint {` |
| `fn` | `sealed_state` | `crates/heptabao-recovery-core/src/lib.rs:238` | `pub fn sealed_state(&self) -> &[u8] {` |
| `fn` | `records` | `crates/heptabao-recovery-core/src/lib.rs:242` | `pub fn records(&self) -> &[RecoveryRecord] {` |
| `struct` | `RecoveryArchive` | `crates/heptabao-recovery-core/src/lib.rs:281` | `pub struct RecoveryArchive {` |
| `fn` | `seal` | `crates/heptabao-recovery-core/src/lib.rs:287` | `pub fn seal<A: RecoveryAuthenticator>(` |
| `fn` | `capture` | `crates/heptabao-recovery-core/src/lib.rs:305` | `pub fn capture<S, J, A>(` |
| `fn` | `verify` | `crates/heptabao-recovery-core/src/lib.rs:355` | `pub fn verify<A: RecoveryAuthenticator>(` |
| `fn` | `encode` | `crates/heptabao-recovery-core/src/lib.rs:378` | `pub fn encode(&self) -> Result<Vec<u8>, RecoveryContractError> {` |
| `fn` | `decode` | `crates/heptabao-recovery-core/src/lib.rs:385` | `pub fn decode(bytes: &[u8]) -> Result<Self, RecoveryContractError> {` |
| `struct` | `VerifiedRecoveryImage` | `crates/heptabao-recovery-core/src/lib.rs:489` | `pub struct VerifiedRecoveryImage {` |
| `fn` | `archive_id` | `crates/heptabao-recovery-core/src/lib.rs:494` | `pub fn archive_id(&self) -> &RecoveryArchiveId {` |
| `const` | `fn` | `crates/heptabao-recovery-core/src/lib.rs:498` | `pub const fn authenticator_id(&self) -> &RecoveryAuthenticatorId {` |
| `const` | `fn` | `crates/heptabao-recovery-core/src/lib.rs:502` | `pub const fn observation(&self) -> &CheckpointObservation {` |
| `const` | `fn` | `crates/heptabao-recovery-core/src/lib.rs:506` | `pub const fn checkpoint(&self) -> &RecoveryCheckpoint {` |
| `struct` | `AuthorizedRecoveryImage` | `crates/heptabao-recovery-core/src/lib.rs:524` | `pub struct AuthorizedRecoveryImage {` |
| `fn` | `archive_id` | `crates/heptabao-recovery-core/src/lib.rs:530` | `pub fn archive_id(&self) -> &RecoveryArchiveId {` |
| `const` | `fn` | `crates/heptabao-recovery-core/src/lib.rs:534` | `pub const fn observation(&self) -> &CheckpointObservation {` |
| `const` | `fn` | `crates/heptabao-recovery-core/src/lib.rs:538` | `pub const fn checkpoint(&self) -> &RecoveryCheckpoint {` |
| `const` | `fn` | `crates/heptabao-recovery-core/src/lib.rs:542` | `pub const fn anchor_revision(&self) -> AnchorRevision {` |
| `fn` | `into_authorized_parts` | `crates/heptabao-recovery-core/src/lib.rs:546` | `pub fn into_authorized_parts(self) -> (RecoveryImageParts, AnchorRevision) {` |
| `trait` | `RecoveryAuthenticator` | `crates/heptabao-recovery-core/src/lib.rs:562` | `pub trait RecoveryAuthenticator: fmt::Debug + Send + Sync {` |
| `struct` | `RestoreReceipt` | `crates/heptabao-recovery-core/src/lib.rs:571` | `pub struct RestoreReceipt {` |
| `enum` | `PublishFailure` | `crates/heptabao-recovery-core/src/lib.rs:579` | `pub enum PublishFailure<E>` |
| `enum` | `StageFailure` | `crates/heptabao-recovery-core/src/lib.rs:607` | `pub enum StageFailure<E>` |
| `trait` | `RecoveryTarget` | `crates/heptabao-recovery-core/src/lib.rs:629` | `pub trait RecoveryTarget: fmt::Debug {` |
| `struct` | `RecoveryRestorer` | `crates/heptabao-recovery-core/src/lib.rs:648` | `pub struct RecoveryRestorer;` |
| `fn` | `restore` | `crates/heptabao-recovery-core/src/lib.rs:651` | `pub fn restore<T, A, R, P>(` |
| `type` | `RecoveryCaptureResult` | `crates/heptabao-recovery-core/src/lib.rs:736` | `pub type RecoveryCaptureResult<T, S, J, A> = Result<T, RecoveryCaptureError<S, J, A>>;` |
| `type` | `RecoveryVerifyResult` | `crates/heptabao-recovery-core/src/lib.rs:737` | `pub type RecoveryVerifyResult<T, A> = Result<T, RecoveryVerificationError<A>>;` |
| `type` | `RecoveryRestoreResult` | `crates/heptabao-recovery-core/src/lib.rs:738` | `pub type RecoveryRestoreResult<T, A, E, R, P> = Result<T, RecoveryRestoreError<A, E, R, P>>;` |
| `enum` | `RecoveryCaptureError` | `crates/heptabao-recovery-core/src/lib.rs:741` | `pub enum RecoveryCaptureError<S, J, A>` |
| `enum` | `RecoveryVerificationError` | `crates/heptabao-recovery-core/src/lib.rs:782` | `pub enum RecoveryVerificationError<A>` |
| `enum` | `RecoveryRestoreError` | `crates/heptabao-recovery-core/src/lib.rs:809` | `pub enum RecoveryRestoreError<A, E, R, P>` |
| `enum` | `RecoveryContractError` | `crates/heptabao-recovery-core/src/lib.rs:899` | `pub enum RecoveryContractError {` |

This table is generated from the exact candidate source. It is a bounded lexical inventory, not a stability or compatibility promise.
<!-- END GENERATED V1.4.7 PUBLIC API TRUTH -->

## State and invariants

- Archive binds state generation/digest, journal tail, key epoch, checkpoint and authenticator identities.
- Decoder rejects malformed, excessive, discontinuous, divergent, truncated and trailing input.
- Restore requires the exact externally verified current checkpoint.
- Target admission and staging are one atomic provider operation.
- Unknown publication outcome remains explicit.
- An outer anchor-fence error after closure entry is an outcome-unknown result even when the target returned an exact receipt.
- Anchor contract, anchor provider, checkpoint-authenticator and target errors remain distinct.

A code change that weakens one of these invariants requires a new plan revision rather than a silent compatibility interpretation.

## Failure and retry semantics

After unknown publication, inspect the target and exact receipt before any retry. Never overwrite a non-empty target blindly.

The restore error classes have different retry authority:

| Error class | Publication by this call | Retry rule |
|---|---|---|
| `CheckpointNotAnchored` | definitely not entered through the current fence | obtain a new authorized archive/checkpoint; do not reinterpret stale authority |
| `Anchor(error)` | fence failed before closure entry | diagnose provider; no publication is attributed to this invocation |
| `CheckpointAuthenticator(error)` | current checkpoint could not be authenticated | security hold; no publication |
| `Target(error)` from staging or proven-not-published path | provider-specific, bounded by the variant | follow target contract; never switch targets automatically |
| `PublishOutcomeUnknown(error)` | may have published | target readback required |
| `PublishReceiptMismatchOutcomeUnknown` | published effect may exist | exact target readback required |
| `AnchorFenceOutcomeUnknown(error)` | closure ran; target and fence completion may have occurred | reconcile both external anchor and target before retry |

Errors are part of the public contract. Unknown, blocked, stale, corrupt, unauthenticated and unauthorized outcomes remain distinct. Callers must not collapse them into a generic retryable transport failure.

## Persistent or wire formats

All durable or wire encodings are versioned, bounded and strict. Decoders reject truncation, impossible lengths, invalid identity/version and trailing bytes. Exact field layouts remain normative in the linked domain contract and source tests.

Format changes require an explicit version transition, backward/forward compatibility decision, hostile decoder tests and migration/rollback treatment.

## Concurrency and cancellation

The caller must preserve single-writer or immutable-reader ownership declared by the domain. Cancellation after an irreversible provider call or durable publication changes only the waiter; it does not revoke the completed authority or commit. Shared mutable state requires a documented fence, generation or epoch.

Cancellation or provider lease loss after entry into `with_current_fence` is classified as `AnchorFenceOutcomeUnknown`; cancellation must not turn an already-published restore into a pre-entry failure.

## Security and secret handling

- Secret-bearing bytes are not logged, formatted, cloned or serialized unless an explicit audited exposure method permits it.
- `Debug` output carries only opaque identity, lengths and safe state classes.
- Buffer overwrite is best effort and does not prove allocator, swap, crash-dump or side-channel resistance.
- No real token, unseal share, recovery key, private key or production snapshot belongs in source, tests, CI or diagnostics.

## Testing and evidence

Detected crate-local tests include:
- `archive_authenticator_identity_is_bound` (crates/heptabao-recovery-core/src/lib.rs)
- `capture_encode_decode_verify_and_restore_round_trip` (crates/heptabao-recovery-core/src/lib.rs)
- `restore_requires_the_exact_externally_verified_checkpoint` (crates/heptabao-recovery-core/src/lib.rs)
- `tamper_trailing_bytes_and_non_empty_target_fail_closed` (crates/heptabao-recovery-core/src/lib.rs)
- `unknown_target_publication_remains_explicit` (crates/heptabao-recovery-core/src/lib.rs)
- `anchor_fence_is_held_across_target_publication` (crates/heptabao-recovery-core/src/lib.rs)
- `wrong_receipt_after_publication_is_outcome_unknown` (crates/heptabao-recovery-core/src/lib.rs)
- `post_entry_anchor_fence_failure_is_outcome_unknown` (crates/heptabao-recovery-core/src/lib.rs)

The post-entry test uses a deterministic anchor that invokes the restore closure, leaves the target occupied with restored state and then returns `OutcomeUnknownAfterEntry`. The required API result is `AnchorFenceOutcomeUnknown`, proving the call cannot be safely retried from its return value alone.

Required local gate:

```text
cargo +1.98.0 fmt --all -- --check
cargo +1.98.0 test --locked --workspace --all-targets
cargo +1.98.0 clippy --locked --workspace --all-targets -- -D warnings
```

Domain changes also run plan mutation tests, current platform/Oracle regressions and frozen inherited-source replay. A green run is technical evidence only.

## Extension workflow

1. Bind the exact base commit/tree and read the current plan, blocker register and this guide.
2. Add or change typed contracts before concrete adapters.
3. Define state transition, error, retry and cancellation behavior.
4. Add positive, hostile and restart/replay tests.
5. Update this guide, traceability and normative manifest in the same change.
6. Run exact-head read-only CI; preserve failed evidence.
7. Obtain independent review for storage, cryptography, security or distributed-systems critical changes.

Any recovery target or anchor provider must document its linearization point, no-effect proof, outcome-unknown boundary, readback method and operator hold state before it may be composed into a higher profile.

## Operations and diagnostics

Recovery requires a two-person, source-bound procedure with archive digest, external anchor observation and post-restore verification.

Diagnostics must preserve stable distinctions among stale anchor, anchor contract failure, pre-entry provider failure, checkpoint authentication failure, target failure, publication uncertainty, receipt mismatch and post-entry fence uncertainty. After `AnchorFenceOutcomeUnknown`, freeze automation and retain the archive ID, checkpoint digest, anchor revision and safe target/anchor observations without logging sealed payload bytes or authentication tags.

## Known gaps

- No production archive authenticator or backup custody.
- No production remote anchor or target readback provider.
- No online upgrade/migration integration.
- No HA/replicated recovery.
- Destructive controller/filesystem qualification remains external.

## Traceability and maintenance

- Crate path: `crates/heptabao-recovery-core`
- Module guide: `docs/modules/heptabao-recovery-core.md`
- Historical module baseline: `3582fda50cd9b03ca39713814cdd8229462bbbd2` / `123c99b71c7e33169bef6033eaefb71e386ed6ca`
- V1.4.6 phase-aware fence source preflight: `8893cdaad4eec3c11f7b367c7bf0e57c20b6631a` / `5c551fa2665bc002113b39cec1b65afe02fe2b99`
- Validation: `scripts/validate_module_documentation_v1_4_4.py`, `scripts/validate_plan_v1_4_6.py`
- Coverage object: `planning/HEPTABAO_MODULE_DOCUMENTATION_COVERAGE_V1_4_4.yaml`

The owner updates this document whenever public API, dependency edges, persistent formats, security invariants, retry behavior, tests or known gaps change.

### V1.4.5 linear restore admission

Restore receives an `AnchorCoordinator`, not a detached verified token. It verifies the archive checkpoint against the live external anchor before target inspection and again immediately before creating the private `AuthorizedRecoveryImage` capability. Targets can stage only that capability, cannot receive a public verified image, and the receipt binds the current anchor revision. The verified image cannot be downgraded to a raw recovery image.

### V1.4.5 publication receipt uncertainty

A mismatched receipt returned after `publish` is classified as `PublishReceiptMismatchOutcomeUnknown`, because publication may already have occurred. It is never a safe retryable contract failure. Operators and target providers must perform authoritative readback and reconciliation before another restore attempt. Only `AuthorizedRecoveryImage` exposes consumable sealed state and journal records; archive-authenticated images do not.

## V1.4.6 atomic admission and fenced publish

`RecoveryTarget::stage_if_empty` replaces separate advisory emptiness and stage calls. The provider atomically verifies/claims an empty target and returns a staged token consumed by `publish`. `RecoveryRestorer` creates the `AuthorizedRecoveryImage`, stages and publishes it, and compares the complete receipt while the rollback provider's exact-current fence is held.

A provider-declared publication-unknown or mismatched post-publication receipt requires target readback. It is never a safe automatic retry.

## V1.4.6 outer-fence outcome preservation

`RecoveryRestorer` now maps only a real `AnchorContractError::CheckpointNotCurrent` to `CheckpointNotAnchored`. Other anchor contract errors, pre-entry anchor provider failures and checkpoint-authenticator failures retain separate typed variants. When the anchor reports `FenceOutcomeUnknown` after closure entry, restore returns `AnchorFenceOutcomeUnknown` regardless of an inner exact receipt. This prevents release, lease or post-operation failures from being relabelled as a safe stale-checkpoint result.

## Machine-verified source truth

<!-- BEGIN GENERATED V1.4.7 MODULE FACTS; DO NOT EDIT -->
- Crate: `heptabao-recovery-core`
- Crate path: `crates/heptabao-recovery-core`
- Cargo manifest SHA-256: `951bd09462faa2e6936dcf86b5f9a95ebc4f67654a6712dc345b9842abd4ced6`
- Rust source files: `1`
- Public lexical declarations: `61`
- Discovered test functions: `9`
- Workspace-internal dependencies: `heptabao-barrier-api` (dependencies), `heptabao-journal-api` (dependencies), `heptabao-rollback-anchor` (dependencies), `heptabao-storage-api` (dependencies)
- Authoritative inventory: `planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml`
- Regeneration: `python scripts/render_plan_v1_4_7.py --write`
- Verification: `python scripts/render_plan_v1_4_7.py --check`
<!-- END GENERATED V1.4.7 MODULE FACTS -->
