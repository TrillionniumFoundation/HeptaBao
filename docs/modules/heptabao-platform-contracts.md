# `heptabao-platform-contracts` developer guide

**Source baseline:** `3582fda50cd9b03ca39713814cdd8229462bbbd2`  
**Source tree:** `123c99b71c7e33169bef6033eaefb71e386ed6ca`  
**Owner role:** `platform-runtime-tls-distributed-systems`  
**Maturity:** `CONTRACT_AND_PROBE_FOUNDATION`  
**Authority effect:** `NONE`

## Purpose and non-goals

Defines provider-neutral runtime, TLS, Raft and artifact-provenance contracts used by isolated dependency probes.

This crate does not by itself grant qualification, compatibility, production, migration or release authority. It must not be used to infer behavior outside the currently declared profile.

## Maturity and authority boundary

The source is a bounded foundation component. Technical tests establish only the checked invariants on the exact source. Production provider selection, independent review and an authority grant are separate objects.

## Ownership and trust boundary

- Authoritative writer: none in product runtime.
- Accountable owner role: `platform-runtime-tls-distributed-systems`.
- Inputs from clients, storage, providers, plugins, clocks, filesystems and evidence stores are untrusted unless explicitly wrapped by a verified type.
- Callers may not bypass typed constructors or reinterpret an error as success.

## Dependency contract

Direct HeptaBao dependencies:
- `none`

Reverse HeptaBao dependants:
- `none`

The allowed direction follows the system crate graph: provider-neutral types and APIs do not depend on adapters; governance and Oracle tooling do not enter the product authority path.

## Public API index

<!-- BEGIN GENERATED V1.4.7 PUBLIC API TRUTH; DO NOT EDIT -->
Source-bound lexical inventory: `crates/heptabao-platform-contracts`; Cargo SHA-256 `58309ecbb712274000ca0b7bc575c9fade218355777c2e959ee6a8ddc9ec49b4`.

| Kind | Name | Source | Declaration |
|---|---|---|---|
| `enum` | `AuthorityEffect` | `crates/heptabao-platform-contracts/src/lib.rs:16` | `pub enum AuthorityEffect {` |
| `enum` | `EvidenceMaturity` | `crates/heptabao-platform-contracts/src/lib.rs:22` | `pub enum EvidenceMaturity {` |
| `struct` | `Digest32` | `crates/heptabao-platform-contracts/src/lib.rs:30` | `pub struct Digest32([u8; 32]);` |
| `fn` | `new` | `crates/heptabao-platform-contracts/src/lib.rs:33` | `pub fn new(bytes: [u8; 32]) -> Result<Self, ContractError> {` |
| `const` | `fn` | `crates/heptabao-platform-contracts/src/lib.rs:40` | `pub const fn bytes(self) -> [u8; 32] {` |
| `struct` | `ObjectId20` | `crates/heptabao-platform-contracts/src/lib.rs:47` | `pub struct ObjectId20([u8; 20]);` |
| `fn` | `new` | `crates/heptabao-platform-contracts/src/lib.rs:50` | `pub fn new(bytes: [u8; 20]) -> Result<Self, ContractError> {` |
| `const` | `fn` | `crates/heptabao-platform-contracts/src/lib.rs:57` | `pub const fn bytes(self) -> [u8; 20] {` |
| `struct` | `ArtifactBinding` | `crates/heptabao-platform-contracts/src/lib.rs:64` | `pub struct ArtifactBinding<'a> {` |
| `struct` | `ValidatedArtifact` | `crates/heptabao-platform-contracts/src/lib.rs:80` | `pub struct ValidatedArtifact {` |
| `fn` | `validate_artifact_binding` | `crates/heptabao-platform-contracts/src/lib.rs:86` | `pub fn validate_artifact_binding(` |
| `struct` | `MonotonicInstant` | `crates/heptabao-platform-contracts/src/lib.rs:134` | `pub struct MonotonicInstant(pub u64);` |
| `struct` | `TaskId` | `crates/heptabao-platform-contracts/src/lib.rs:138` | `pub struct TaskId(u64);` |
| `const` | `fn` | `crates/heptabao-platform-contracts/src/lib.rs:141` | `pub const fn new(value: u64) -> Result<Self, ContractError> {` |
| `const` | `fn` | `crates/heptabao-platform-contracts/src/lib.rs:148` | `pub const fn get(self) -> u64 {` |
| `enum` | `TaskClass` | `crates/heptabao-platform-contracts/src/lib.rs:155` | `pub enum TaskClass {` |
| `struct` | `TaskSpec` | `crates/heptabao-platform-contracts/src/lib.rs:164` | `pub struct TaskSpec {` |
| `fn` | `validate` | `crates/heptabao-platform-contracts/src/lib.rs:172` | `pub fn validate(self, now: MonotonicInstant) -> Result<(), ContractError> {` |
| `type` | `BoxTask` | `crates/heptabao-platform-contracts/src/lib.rs:188` | `pub type BoxTask = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;` |
| `trait` | `RuntimeAdapter` | `crates/heptabao-platform-contracts/src/lib.rs:191` | `pub trait RuntimeAdapter: Send + Sync {` |
| `enum` | `RuntimeError` | `crates/heptabao-platform-contracts/src/lib.rs:206` | `pub enum RuntimeError {` |
| `enum` | `TlsVersion` | `crates/heptabao-platform-contracts/src/lib.rs:217` | `pub enum TlsVersion {` |
| `enum` | `ClientAuthMode` | `crates/heptabao-platform-contracts/src/lib.rs:233` | `pub enum ClientAuthMode {` |
| `struct` | `TlsProfile` | `crates/heptabao-platform-contracts/src/lib.rs:241` | `pub struct TlsProfile {` |
| `const` | `fn` | `crates/heptabao-platform-contracts/src/lib.rs:253` | `pub const fn validate(self) -> Result<(), ContractError> {` |
| `struct` | `TlsConfigId` | `crates/heptabao-platform-contracts/src/lib.rs:277` | `pub struct TlsConfigId(pub Digest32);` |
| `struct` | `PrivateKeyHandle` | `crates/heptabao-platform-contracts/src/lib.rs:281` | `pub struct PrivateKeyHandle(pub Digest32);` |
| `struct` | `StagedTlsConfig` | `crates/heptabao-platform-contracts/src/lib.rs:285` | `pub struct StagedTlsConfig {` |
| `trait` | `TlsProvider` | `crates/heptabao-platform-contracts/src/lib.rs:292` | `pub trait TlsProvider: Send + Sync {` |
| `enum` | `TlsError` | `crates/heptabao-platform-contracts/src/lib.rs:300` | `pub enum TlsError {` |
| `struct` | `LogPosition` | `crates/heptabao-platform-contracts/src/lib.rs:311` | `pub struct LogPosition {` |
| `const` | `fn` | `crates/heptabao-platform-contracts/src/lib.rs:317` | `pub const fn validate(self) -> Result<(), ContractError> {` |
| `struct` | `ApplyCursor` | `crates/heptabao-platform-contracts/src/lib.rs:327` | `pub struct ApplyCursor {` |
| `const` | `fn` | `crates/heptabao-platform-contracts/src/lib.rs:332` | `pub const fn validate_next(self, next: LogPosition) -> Result<Self, ContractError> {` |
| `struct` | `SnapshotMeta` | `crates/heptabao-platform-contracts/src/lib.rs:364` | `pub struct SnapshotMeta {` |
| `const` | `fn` | `crates/heptabao-platform-contracts/src/lib.rs:372` | `pub const fn validate(self, cursor: ApplyCursor) -> Result<(), ContractError> {` |
| `trait` | `StateMachineAdapter` | `crates/heptabao-platform-contracts/src/lib.rs:390` | `pub trait StateMachineAdapter {` |
| `trait` | `ConsensusAdapter` | `crates/heptabao-platform-contracts/src/lib.rs:404` | `pub trait ConsensusAdapter: Send + Sync {` |
| `enum` | `RaftError` | `crates/heptabao-platform-contracts/src/lib.rs:412` | `pub enum RaftError {` |
| `enum` | `ContractError` | `crates/heptabao-platform-contracts/src/lib.rs:424` | `pub enum ContractError {` |

This table is generated from the exact candidate source. It is a bounded lexical inventory, not a stability or compatibility promise.
<!-- END GENERATED V1.4.7 PUBLIC API TRUTH -->

## State and invariants

- Critical tasks require cancellation and future deadlines.
- Raft apply order is contiguous and monotonic.
- Snapshots cannot regress applied state.
- Registry checksum mismatch and unsafe TLS policy fail closed.
- Independent reproduction has no authority effect.

A code change that weakens one of these invariants requires a new plan revision rather than a silent compatibility interpretation.

## Failure and retry semantics

Probe retries preserve the original failed evidence and bind a new run identity, runner and exact source.

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
- `critical_task_requires_cancellation_and_future_deadline` (crates/heptabao-platform-contracts/src/lib.rs)
- `independent_reproduction_still_has_no_authority` (crates/heptabao-platform-contracts/src/lib.rs)
- `raft_apply_is_contiguous_and_term_monotonic` (crates/heptabao-platform-contracts/src/lib.rs)
- `registry_checksum_mismatch_is_rejected` (crates/heptabao-platform-contracts/src/lib.rs)
- `registry_metadata_has_no_authority` (crates/heptabao-platform-contracts/src/lib.rs)
- `snapshot_cannot_regress_applied_state` (crates/heptabao-platform-contracts/src/lib.rs)
- `unsafe_ticket_policy_is_rejected` (crates/heptabao-platform-contracts/src/lib.rs)

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

Use isolated probe workspaces and never import candidate-specific types into product domain APIs.

Diagnostics use stable typed error classes and opaque correlation identities. Operators must preserve suspect state for investigation instead of deleting files or rewriting evidence to obtain a pass.

## Known gaps

- Candidates are not production-selected.
- Cross-platform and independent reproductions remain incomplete.
- Provider operational runbooks are absent.


## Traceability and maintenance

- Crate path: `crates/heptabao-platform-contracts`
- Module guide: `docs/modules/heptabao-platform-contracts.md`
- Source baseline: `3582fda50cd9b03ca39713814cdd8229462bbbd2` / `123c99b71c7e33169bef6033eaefb71e386ed6ca`
- Validation: `scripts/validate_module_documentation_v1_4_4.py`
- Coverage object: `planning/HEPTABAO_MODULE_DOCUMENTATION_COVERAGE_V1_4_4.yaml`

The owner updates this document whenever public API, dependency edges, persistent formats, security invariants, retry behavior, tests or known gaps change.

## Machine-verified source truth

<!-- BEGIN GENERATED V1.4.7 MODULE FACTS; DO NOT EDIT -->
- Crate: `heptabao-platform-contracts`
- Crate path: `crates/heptabao-platform-contracts`
- Cargo manifest SHA-256: `58309ecbb712274000ca0b7bc575c9fade218355777c2e959ee6a8ddc9ec49b4`
- Rust source files: `1`
- Public lexical declarations: `40`
- Discovered test functions: `7`
- Workspace-internal dependencies: none
- Authoritative inventory: `planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml`
- Regeneration: `python scripts/render_plan_v1_4_7.py --write`
- Verification: `python scripts/render_plan_v1_4_7.py --check`
<!-- END GENERATED V1.4.7 MODULE FACTS -->
