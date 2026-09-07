# `heptabao-storage-api` developer guide

**Source baseline:** `3582fda50cd9b03ca39713814cdd8229462bbbd2`  
**Source tree:** `123c99b71c7e33169bef6033eaefb71e386ed6ca`  
**Owner role:** `storage-core-api`  
**Maturity:** `PROVIDER_NEUTRAL_API_IMPLEMENTED`  
**Authority effect:** `NONE`

## Purpose and non-goals

Defines checked durable generations, explicit lifecycle, bounded opaque state, integrity identities and compare-and-swap store contracts.

This crate does not by itself grant qualification, compatibility, production, migration or release authority. It must not be used to infer behavior outside the currently declared profile.

## Maturity and authority boundary

The source is a bounded foundation component. Technical tests establish only the checked invariants on the exact source. Production provider selection, independent review and an authority grant are separate objects.

## Ownership and trust boundary

- Authoritative writer: one provider implementation selected by composition.
- Accountable owner role: `storage-core-api`.
- Inputs from clients, storage, providers, plugins, clocks, filesystems and evidence stores are untrusted unless explicitly wrapped by a verified type.
- Callers may not bypass typed constructors or reinterpret an error as success.

## Dependency contract

Direct HeptaBao dependencies:
- `none`

Reverse HeptaBao dependants:
- `heptabao-barrier-api`
- `heptabao-durable-core`
- `heptabao-journaled-core`
- `heptabao-operation-ledger`
- `heptabao-recovery-core`
- `heptabao-rollback-anchor`
- `heptabao-single-node-store`

The allowed direction follows the system crate graph: provider-neutral types and APIs do not depend on adapters; governance and Oracle tooling do not enter the product authority path.

## Public API index

<!-- BEGIN GENERATED V1.4.7 PUBLIC API TRUTH; DO NOT EDIT -->
Source-bound lexical inventory: `crates/heptabao-storage-api`; Cargo SHA-256 `7c31ca83f1253d29128905cce76400717e01de047bf52f388f9ba5f710c99ad3`.

| Kind | Name | Source | Declaration |
|---|---|---|---|
| `const` | `MAX_OPAQUE_STATE_BYTES` | `crates/heptabao-storage-api/src/lib.rs:13` | `pub const MAX_OPAQUE_STATE_BYTES: usize = 16 * 1024 * 1024;` |
| `const` | `MAX_STORE_DOMAIN_BYTES` | `crates/heptabao-storage-api/src/lib.rs:14` | `pub const MAX_STORE_DOMAIN_BYTES: usize = 128;` |
| `const` | `MAX_INTEGRITY_ALGORITHM_ID_BYTES` | `crates/heptabao-storage-api/src/lib.rs:15` | `pub const MAX_INTEGRITY_ALGORITHM_ID_BYTES: usize = 128;` |
| `struct` | `StoreDomain` | `crates/heptabao-storage-api/src/lib.rs:18` | `pub struct StoreDomain(String);` |
| `fn` | `new` | `crates/heptabao-storage-api/src/lib.rs:21` | `pub fn new(value: String) -> Result<Self, StorageContractError> {` |
| `fn` | `as_str` | `crates/heptabao-storage-api/src/lib.rs:46` | `pub fn as_str(&self) -> &str {` |
| `struct` | `IntegrityAlgorithmId` | `crates/heptabao-storage-api/src/lib.rs:52` | `pub struct IntegrityAlgorithmId(String);` |
| `fn` | `new` | `crates/heptabao-storage-api/src/lib.rs:55` | `pub fn new(value: String) -> Result<Self, StorageContractError> {` |
| `fn` | `as_str` | `crates/heptabao-storage-api/src/lib.rs:80` | `pub fn as_str(&self) -> &str {` |
| `struct` | `Generation` | `crates/heptabao-storage-api/src/lib.rs:86` | `pub struct Generation(u64);` |
| `const` | `INITIAL` | `crates/heptabao-storage-api/src/lib.rs:89` | `pub const INITIAL: Self = Self(1);` |
| `const` | `fn` | `crates/heptabao-storage-api/src/lib.rs:91` | `pub const fn new(value: u64) -> Result<Self, StorageContractError> {` |
| `const` | `fn` | `crates/heptabao-storage-api/src/lib.rs:98` | `pub const fn get(self) -> u64 {` |
| `const` | `fn` | `crates/heptabao-storage-api/src/lib.rs:102` | `pub const fn previous(self) -> Option<Self> {` |
| `const` | `fn` | `crates/heptabao-storage-api/src/lib.rs:109` | `pub const fn checked_next(self) -> Result<Self, StorageContractError> {` |
| `struct` | `StateDigest` | `crates/heptabao-storage-api/src/lib.rs:118` | `pub struct StateDigest([u8; 32]);` |
| `fn` | `new` | `crates/heptabao-storage-api/src/lib.rs:121` | `pub fn new(value: [u8; 32]) -> Result<Self, StorageContractError> {` |
| `const` | `fn` | `crates/heptabao-storage-api/src/lib.rs:128` | `pub const fn bytes(self) -> [u8; 32] {` |
| `struct` | `OpaqueState` | `crates/heptabao-storage-api/src/lib.rs:140` | `pub struct OpaqueState(Vec<u8>);` |
| `fn` | `new` | `crates/heptabao-storage-api/src/lib.rs:143` | `pub fn new(mut value: Vec<u8>) -> Result<Self, StorageContractError> {` |
| `fn` | `as_bytes` | `crates/heptabao-storage-api/src/lib.rs:151` | `pub fn as_bytes(&self) -> &[u8] {` |
| `fn` | `len` | `crates/heptabao-storage-api/src/lib.rs:155` | `pub fn len(&self) -> usize {` |
| `fn` | `is_empty` | `crates/heptabao-storage-api/src/lib.rs:159` | `pub fn is_empty(&self) -> bool {` |
| `fn` | `into_bytes` | `crates/heptabao-storage-api/src/lib.rs:163` | `pub fn into_bytes(mut self) -> Vec<u8> {` |
| `enum` | `StoreOpenMode` | `crates/heptabao-storage-api/src/lib.rs:185` | `pub enum StoreOpenMode {` |
| `struct` | `GenerationSnapshot` | `crates/heptabao-storage-api/src/lib.rs:192` | `pub struct GenerationSnapshot {` |
| `struct` | `CommitReceipt` | `crates/heptabao-storage-api/src/lib.rs:210` | `pub struct CommitReceipt {` |
| `struct` | `CommitIntent` | `crates/heptabao-storage-api/src/lib.rs:223` | `pub struct CommitIntent {` |
| `fn` | `new` | `crates/heptabao-storage-api/src/lib.rs:230` | `pub fn new(` |
| `const` | `fn` | `crates/heptabao-storage-api/src/lib.rs:249` | `pub const fn previous(self) -> Option<Generation> {` |
| `const` | `fn` | `crates/heptabao-storage-api/src/lib.rs:253` | `pub const fn committed(self) -> Generation {` |
| `const` | `fn` | `crates/heptabao-storage-api/src/lib.rs:257` | `pub const fn digest(self) -> StateDigest {` |
| `const` | `fn` | `crates/heptabao-storage-api/src/lib.rs:261` | `pub const fn receipt(self) -> CommitReceipt {` |
| `enum` | `CommitRecovery` | `crates/heptabao-storage-api/src/lib.rs:271` | `pub enum CommitRecovery {` |
| `trait` | `IntegrityProvider` | `crates/heptabao-storage-api/src/lib.rs:279` | `pub trait IntegrityProvider: fmt::Debug + Send + Sync {` |
| `trait` | `DurableGenerationStore` | `crates/heptabao-storage-api/src/lib.rs:292` | `pub trait DurableGenerationStore: fmt::Debug + Send {` |
| `enum` | `StorageContractError` | `crates/heptabao-storage-api/src/lib.rs:322` | `pub enum StorageContractError {` |

This table is generated from the exact candidate source. It is a bounded lexical inventory, not a stability or compatibility promise.
<!-- END GENERATED V1.4.7 PUBLIC API TRUTH -->

## State and invariants

- Generation zero is invalid and arithmetic is checked.
- Opaque state is bounded, non-clone and redacted.
- Domain and algorithm identities are canonical ASCII.
- Commit receipts bind generation and non-zero digest.
- Lifecycle intent is explicit.

A code change that weakens one of these invariants requires a new plan revision rather than a silent compatibility interpretation.

## Failure and retry semantics

Providers must distinguish conflict, known failure and unknown publication. Callers reconcile unknown results before retry.

Errors are part of the public contract. Unknown, blocked, stale, corrupt, unauthenticated and unauthorized outcomes remain distinct. Callers must not collapse them into a generic retryable transport failure.

## Persistent or wire formats

This crate does not own a durable or wire format; it consumes typed contracts from dependencies.

Format changes require an explicit version transition, backward/forward compatibility decision, hostile decoder tests and migration/rollback treatment.

## Concurrency and cancellation

The caller must preserve single-writer or immutable-reader ownership declared by the domain. Cancellation after an irreversible provider call or durable publication changes only the waiter; it does not revoke the completed authority or commit. Shared mutable state requires a documented fence, generation or epoch.

## Security and secret handling

- Secret-bearing bytes are not logged, formatted, cloned or serialized unless an explicit audited exposure method permits it.
- `Debug` output carries only opaque identity, lengths and safe state classes.
- Buffer overwrite is best effort and does not prove allocator, swap, crash-dump or side-channel resistance.
- No real token, unseal share, recovery key, private key or production snapshot belongs in source, tests, CI or diagnostics.

## Testing and evidence

Detected crate-local tests:
- `domains_and_algorithm_ids_are_canonical_ascii` (crates/heptabao-storage-api/src/lib.rs)
- `generation_is_non_zero_and_checked` (crates/heptabao-storage-api/src/lib.rs)
- `opaque_state_redacts_and_can_be_consumed_without_clone` (crates/heptabao-storage-api/src/lib.rs)
- `zero_digest_is_rejected` (crates/heptabao-storage-api/src/lib.rs)

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

## Operations and diagnostics

Provider diagnostics expose identity, generation and error classification without opaque state bytes.

Diagnostics use stable typed error classes and opaque correlation identities. Operators must preserve suspect state for investigation instead of deleting files or rewriting evidence to obtain a pass.

## Known gaps

- Provider conformance suite is not yet standalone.
- Production database backends are absent.
- Online migration/version negotiation is not defined.


## Traceability and maintenance

- Crate path: `crates/heptabao-storage-api`
- Module guide: `docs/modules/heptabao-storage-api.md`
- Source baseline: `3582fda50cd9b03ca39713814cdd8229462bbbd2` / `123c99b71c7e33169bef6033eaefb71e386ed6ca`
- Validation: `scripts/validate_module_documentation_v1_4_4.py`
- Coverage object: `planning/HEPTABAO_MODULE_DOCUMENTATION_COVERAGE_V1_4_4.yaml`

The owner updates this document whenever public API, dependency edges, persistent formats, security invariants, retry behavior, tests or known gaps change.

## V1.4.6 authoritative commit recovery

`CommitIntent` binds the previous generation, exact successor generation and
state digest used by `prepare_commit` and `recover_commit`. It is a
provider-recovery descriptor, not proof that a matching operation-ledger record
was persisted and not independent publication authority. Product composition
must derive its descriptor from replayed `IntentCommitted` state.

`recover_commit` must reread authoritative provider state. It may report exact
commit, exact non-commit, or conflict. It may complete one already durable
candidate only when provider authentication and every descriptor field match.
It must not accept caller-supplied opaque state during recovery.

## Machine-verified source truth

<!-- BEGIN GENERATED V1.4.7 MODULE FACTS; DO NOT EDIT -->
- Crate: `heptabao-storage-api`
- Crate path: `crates/heptabao-storage-api`
- Cargo manifest SHA-256: `7c31ca83f1253d29128905cce76400717e01de047bf52f388f9ba5f710c99ad3`
- Rust source files: `1`
- Public lexical declarations: `37`
- Discovered test functions: `5`
- Workspace-internal dependencies: none
- Authoritative inventory: `planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml`
- Regeneration: `python scripts/render_plan_v1_4_7.py --write`
- Verification: `python scripts/render_plan_v1_4_7.py --check`
<!-- END GENERATED V1.4.7 MODULE FACTS -->
