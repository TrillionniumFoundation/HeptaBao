# `heptabao-rollback-anchor` developer guide

**Source baseline:** `3582fda50cd9b03ca39713814cdd8229462bbbd2`  
**Source tree:** `123c99b71c7e33169bef6033eaefb71e386ed6ca`  
**Owner role:** `storage-cryptography-distributed-systems`  
**Maturity:** `PROVIDER_NEUTRAL_ANCHOR_FOUNDATION`  
**Authority effect:** `NONE`

## Purpose and non-goals

Defines authenticated external checkpoints and compare-and-swap advancement used to detect rollback and same-position divergence.

This crate does not by itself grant qualification, compatibility, production, migration or release authority. It must not be used to infer behavior outside the currently declared profile.

## Maturity and authority boundary

The source is a bounded foundation component. Technical tests establish only the checked invariants on the exact source. Production provider selection, independent review and an authority grant are separate objects.

## Ownership and trust boundary

- Authoritative writer: one external rollback-anchor provider.
- Accountable owner role: `storage-cryptography-distributed-systems`.
- Inputs from clients, storage, providers, plugins, clocks, filesystems and evidence stores are untrusted unless explicitly wrapped by a verified type.
- Callers may not bypass typed constructors or reinterpret an error as success.

## Dependency contract

Direct HeptaBao dependencies:
- `heptabao-barrier-api`
- `heptabao-journal-api`
- `heptabao-storage-api`

Reverse HeptaBao dependants:
- `heptabao-recovery-core`

The allowed direction follows the system crate graph: provider-neutral types and APIs do not depend on adapters; governance and Oracle tooling do not enter the product authority path.

## Public API index

<!-- BEGIN GENERATED V1.4.7 PUBLIC API TRUTH; DO NOT EDIT -->
Source-bound lexical inventory: `crates/heptabao-rollback-anchor`; Cargo SHA-256 `5d25fc4b2c0903ba3bd5f279255c1a82e7a1fc8d0acb7341811eeea964472d52`.

| Kind | Name | Source | Declaration |
|---|---|---|---|
| `const` | `MAX_ANCHOR_AUTHENTICATOR_ID_BYTES` | `crates/heptabao-rollback-anchor/src/lib.rs:18` | `pub const MAX_ANCHOR_AUTHENTICATOR_ID_BYTES: usize = 128;` |
| `struct` | `AnchorAuthenticatorId` | `crates/heptabao-rollback-anchor/src/lib.rs:21` | `pub struct AnchorAuthenticatorId(String);` |
| `fn` | `new` | `crates/heptabao-rollback-anchor/src/lib.rs:24` | `pub fn new(value: String) -> Result<Self, AnchorContractError> {` |
| `fn` | `as_str` | `crates/heptabao-rollback-anchor/src/lib.rs:31` | `pub fn as_str(&self) -> &str {` |
| `struct` | `AnchorRevision` | `crates/heptabao-rollback-anchor/src/lib.rs:56` | `pub struct AnchorRevision(u64);` |
| `const` | `INITIAL` | `crates/heptabao-rollback-anchor/src/lib.rs:59` | `pub const INITIAL: Self = Self(1);` |
| `const` | `fn` | `crates/heptabao-rollback-anchor/src/lib.rs:61` | `pub const fn new(value: u64) -> Result<Self, AnchorContractError> {` |
| `const` | `fn` | `crates/heptabao-rollback-anchor/src/lib.rs:68` | `pub const fn get(self) -> u64 {` |
| `const` | `fn` | `crates/heptabao-rollback-anchor/src/lib.rs:72` | `pub const fn checked_next(self) -> Result<Self, AnchorContractError> {` |
| `struct` | `CheckpointDigest` | `crates/heptabao-rollback-anchor/src/lib.rs:81` | `pub struct CheckpointDigest([u8; 32]);` |
| `fn` | `new` | `crates/heptabao-rollback-anchor/src/lib.rs:84` | `pub fn new(value: [u8; 32]) -> Result<Self, AnchorContractError> {` |
| `const` | `fn` | `crates/heptabao-rollback-anchor/src/lib.rs:91` | `pub const fn bytes(self) -> [u8; 32] {` |
| `struct` | `CheckpointObservation` | `crates/heptabao-rollback-anchor/src/lib.rs:103` | `pub struct CheckpointObservation {` |
| `fn` | `new` | `crates/heptabao-rollback-anchor/src/lib.rs:113` | `pub fn new(` |
| `const` | `fn` | `crates/heptabao-rollback-anchor/src/lib.rs:131` | `pub const fn store_domain(&self) -> &StoreDomain {` |
| `const` | `fn` | `crates/heptabao-rollback-anchor/src/lib.rs:135` | `pub const fn generation(&self) -> Generation {` |
| `const` | `fn` | `crates/heptabao-rollback-anchor/src/lib.rs:139` | `pub const fn state_digest(&self) -> StateDigest {` |
| `const` | `fn` | `crates/heptabao-rollback-anchor/src/lib.rs:143` | `pub const fn journal_domain(&self) -> &JournalDomain {` |
| `const` | `fn` | `crates/heptabao-rollback-anchor/src/lib.rs:147` | `pub const fn journal_tail(&self) -> Option<JournalTail> {` |
| `const` | `fn` | `crates/heptabao-rollback-anchor/src/lib.rs:151` | `pub const fn key_epoch(&self) -> KeyEpoch {` |
| `struct` | `RecoveryCheckpoint` | `crates/heptabao-rollback-anchor/src/lib.rs:161` | `pub struct RecoveryCheckpoint {` |
| `fn` | `from_parts` | `crates/heptabao-rollback-anchor/src/lib.rs:170` | `pub fn from_parts(` |
| `const` | `fn` | `crates/heptabao-rollback-anchor/src/lib.rs:192` | `pub const fn revision(&self) -> AnchorRevision {` |
| `const` | `fn` | `crates/heptabao-rollback-anchor/src/lib.rs:196` | `pub const fn previous_digest(&self) -> Option<CheckpointDigest> {` |
| `const` | `fn` | `crates/heptabao-rollback-anchor/src/lib.rs:200` | `pub const fn authenticator_id(&self) -> &AnchorAuthenticatorId {` |
| `const` | `fn` | `crates/heptabao-rollback-anchor/src/lib.rs:204` | `pub const fn observation(&self) -> &CheckpointObservation {` |
| `const` | `fn` | `crates/heptabao-rollback-anchor/src/lib.rs:208` | `pub const fn digest(&self) -> CheckpointDigest {` |
| `fn` | `canonical_preimage` | `crates/heptabao-rollback-anchor/src/lib.rs:212` | `pub fn canonical_preimage(` |
| `struct` | `VerifiedRecoveryCheckpoint` | `crates/heptabao-rollback-anchor/src/lib.rs:247` | `pub struct VerifiedRecoveryCheckpoint {` |
| `const` | `fn` | `crates/heptabao-rollback-anchor/src/lib.rs:252` | `pub const fn revision(&self) -> AnchorRevision {` |
| `const` | `fn` | `crates/heptabao-rollback-anchor/src/lib.rs:256` | `pub const fn digest(&self) -> CheckpointDigest {` |
| `const` | `fn` | `crates/heptabao-rollback-anchor/src/lib.rs:260` | `pub const fn observation(&self) -> &CheckpointObservation {` |
| `trait` | `CheckpointAuthenticator` | `crates/heptabao-rollback-anchor/src/lib.rs:265` | `pub trait CheckpointAuthenticator: fmt::Debug + Send + Sync {` |
| `enum` | `AnchorFenceError` | `crates/heptabao-rollback-anchor/src/lib.rs:274` | `pub enum AnchorFenceError<E>` |
| `trait` | `RollbackAnchor` | `crates/heptabao-rollback-anchor/src/lib.rs:323` | `pub trait RollbackAnchor: fmt::Debug + Send {` |
| `struct` | `AnchorAdvanceReceipt` | `crates/heptabao-rollback-anchor/src/lib.rs:353` | `pub struct AnchorAdvanceReceipt {` |
| `enum` | `ObservationDisposition` | `crates/heptabao-rollback-anchor/src/lib.rs:359` | `pub enum ObservationDisposition {` |
| `struct` | `AnchorCoordinator` | `crates/heptabao-rollback-anchor/src/lib.rs:365` | `pub struct AnchorCoordinator<A, P> {` |
| `const` | `fn` | `crates/heptabao-rollback-anchor/src/lib.rs:371` | `pub const fn new(anchor: A, authenticator: P) -> Self {` |
| `type` | `AnchorResult` | `crates/heptabao-rollback-anchor/src/lib.rs:393` | `pub type AnchorResult<T, A, P> = Result<T, AnchorCoordinatorError<A, P>>;` |
| `fn` | `classify` | `crates/heptabao-rollback-anchor/src/lib.rs:400` | `pub fn classify(` |
| `fn` | `advance` | `crates/heptabao-rollback-anchor/src/lib.rs:416` | `pub fn advance(` |
| `fn` | `with_current_fence` | `crates/heptabao-rollback-anchor/src/lib.rs:494` | `pub fn with_current_fence<T, F>(` |
| `fn` | `verify_owned` | `crates/heptabao-rollback-anchor/src/lib.rs:518` | `pub fn verify_owned(` |
| `fn` | `verify_current` | `crates/heptabao-rollback-anchor/src/lib.rs:525` | `pub fn verify_current(` |
| `fn` | `verify_checkpoint` | `crates/heptabao-rollback-anchor/src/lib.rs:547` | `pub fn verify_checkpoint(` |
| `enum` | `AnchorCoordinatorError` | `crates/heptabao-rollback-anchor/src/lib.rs:587` | `pub enum AnchorCoordinatorError<A, P>` |
| `enum` | `AnchorContractError` | `crates/heptabao-rollback-anchor/src/lib.rs:626` | `pub enum AnchorContractError {` |

This table is generated from the exact candidate source. It is a bounded lexical inventory, not a stability or compatibility promise.
<!-- END GENERATED V1.4.7 PUBLIC API TRUTH -->

## State and invariants

- Checkpoint preimage binds all storage, journal, key and authenticator observations.
- Previous checkpoint digest forms an authenticated chain.
- Historical but authentic checkpoints cannot authorize current recovery.
- Same-position divergence and key-epoch regression fail closed.
- Provider CAS receipts are reread and verified.
- A fence result that guarantees no closure entry is distinct from uncertainty after closure entry.
- Post-entry uncertainty is never converted to a stale-checkpoint or safe provider failure.

A code change that weakens one of these invariants requires a new plan revision rather than a silent compatibility interpretation.

## Failure and retry semantics

CAS conflict requires a fresh provider read and reconciliation. An unavailable provider must not be treated as an empty anchor.

`CheckpointNotCurrent` and `ProviderBeforeEntry` guarantee that the supplied operation was not invoked. `OutcomeUnknownAfterEntry` guarantees that the operation was invoked but does not prove whether authority remained valid through completion. The latter requires external-anchor and target readback before any retry.

Errors are part of the public contract. Unknown, blocked, stale, corrupt, unauthenticated and unauthorized outcomes remain distinct. Callers must not collapse them into a generic retryable transport failure.

## Persistent or wire formats

All durable or wire encodings are versioned, bounded and strict. Decoders reject truncation, impossible lengths, invalid identity/version and trailing bytes. Exact field layouts remain normative in the linked domain contract and source tests.

Format changes require an explicit version transition, backward/forward compatibility decision, hostile decoder tests and migration/rollback treatment.

## Concurrency and cancellation

The caller must preserve single-writer or immutable-reader ownership declared by the domain. Cancellation after an irreversible provider call or durable publication changes only the waiter; it does not revoke the completed authority or commit. Shared mutable state requires a documented fence, generation or epoch.

A remote provider must treat cancellation, lease loss, unlock failure and post-operation verification failure after closure entry as `OutcomeUnknownAfterEntry`, even when the inner operation returned success.

## Security and secret handling

- Secret-bearing bytes are not logged, formatted, cloned or serialized unless an explicit audited exposure method permits it.
- `Debug` output carries only opaque identity, lengths and safe state classes.
- Buffer overwrite is best effort and does not prove allocator, swap, crash-dump or side-channel resistance.
- No real token, unseal share, recovery key, private key or production snapshot belongs in source, tests, CI or diagnostics.

## Testing and evidence

Detected crate-local and dependent hostile tests include:
- `checkpoint_advances_and_exact_observation_is_detected` (crates/heptabao-rollback-anchor/src/lib.rs)
- `checkpoint_preimage_binds_every_observation_field` (crates/heptabao-rollback-anchor/src/lib.rs)
- `historical_but_authentic_checkpoint_cannot_authorize_restore` (crates/heptabao-rollback-anchor/src/lib.rs)
- `rollback_divergence_and_epoch_regression_fail_closed` (crates/heptabao-rollback-anchor/src/lib.rs)
- `current_checkpoint_fence_rejects_stale_checkpoint` (crates/heptabao-rollback-anchor/src/lib.rs)
- `anchor_fence_is_held_across_target_publication` (crates/heptabao-recovery-core/src/lib.rs)
- `post_entry_anchor_fence_failure_is_outcome_unknown` (crates/heptabao-recovery-core/src/lib.rs)

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

A new `RollbackAnchor` implementation must document exactly when closure entry occurs, prove that pre-entry variants cannot be returned afterward, and define the authoritative reconciliation path for every post-entry uncertainty.

## Operations and diagnostics

Monitor anchor freshness, provider identity revision and divergence alarms independently of the mutable storage root.

Diagnostics must identify `CheckpointNotCurrent`, `ProviderBeforeEntry`, `FenceOutcomeUnknown` and authenticator failures as distinct classes without logging checkpoint authentication material. An operator must freeze automatic retry after `FenceOutcomeUnknown` and preserve both anchor and target state for reconciliation.

## Known gaps

- No production remote append-only provider selected.
- Remote lease acquisition, renewal, fencing-token and release semantics are not implemented or qualified.
- Availability and disaster-recovery SLOs are not defined.
- Multi-region consistency has not been qualified.

## Traceability and maintenance

- Crate path: `crates/heptabao-rollback-anchor`
- Module guide: `docs/modules/heptabao-rollback-anchor.md`
- Historical module baseline: `3582fda50cd9b03ca39713814cdd8229462bbbd2` / `123c99b71c7e33169bef6033eaefb71e386ed6ca`
- V1.4.6 phase-aware fence source preflight: `8893cdaad4eec3c11f7b367c7bf0e57c20b6631a` / `5c551fa2665bc002113b39cec1b65afe02fe2b99`
- Validation: `scripts/validate_module_documentation_v1_4_4.py`, `scripts/validate_plan_v1_4_6.py`
- Coverage object: `planning/HEPTABAO_MODULE_DOCUMENTATION_COVERAGE_V1_4_4.yaml`

The owner updates this document whenever public API, dependency edges, persistent formats, security invariants, retry behavior, tests or known gaps change.

### V1.4.5 live-anchor verification

Verified checkpoint values are non-cloneable and cannot be downgraded into ordinary checkpoints. Raw anchor and authenticator providers are not extractable from the coordinator. `verify_current` always rereads the external anchor, requires exact checkpoint equality and authenticates the current object; a historical verification result is never sufficient for a later restore ceremony.

## V1.4.6 publication fence

`with_current_fence` authenticates the expected checkpoint through the coordinator, compares exact current state under the provider serialization primitive, and keeps that primitive held while the supplied publication closure executes. `compare_and_swap` must use the same primitive, so an anchor advance cannot interleave between admission and recovery publication. The closure is single invocation; a stale checkpoint never enters it.

## V1.4.6 phase-aware fence completion

`AnchorFenceError` now has three non-overlapping meanings:

- `CheckpointNotCurrent`: exact comparison failed and the closure was not invoked;
- `ProviderBeforeEntry(error)`: the provider failed before invocation;
- `OutcomeUnknownAfterEntry(error)`: invocation occurred, but the provider cannot prove valid, clean fence completion.

`AnchorCoordinatorError::FenceOutcomeUnknown` preserves the third state. It must not be downgraded to a normal provider error or stale-checkpoint contract result. The deterministic recovery hostile provider runs the publication closure, leaves the target populated and then returns `OutcomeUnknownAfterEntry`, proving that a completed effect remains operationally ambiguous until readback.

## Machine-verified source truth

<!-- BEGIN GENERATED V1.4.7 MODULE FACTS; DO NOT EDIT -->
- Crate: `heptabao-rollback-anchor`
- Crate path: `crates/heptabao-rollback-anchor`
- Cargo manifest SHA-256: `5d25fc4b2c0903ba3bd5f279255c1a82e7a1fc8d0acb7341811eeea964472d52`
- Rust source files: `1`
- Public lexical declarations: `48`
- Discovered test functions: `6`
- Workspace-internal dependencies: `heptabao-barrier-api` (dependencies), `heptabao-journal-api` (dependencies), `heptabao-storage-api` (dependencies)
- Authoritative inventory: `planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml`
- Regeneration: `python scripts/render_plan_v1_4_7.py --write`
- Verification: `python scripts/render_plan_v1_4_7.py --check`
<!-- END GENERATED V1.4.7 MODULE FACTS -->
