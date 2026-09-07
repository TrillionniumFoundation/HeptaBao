# `heptabao-journal-api` developer guide

**Source baseline:** `3582fda50cd9b03ca39713814cdd8229462bbbd2`  
**Source tree:** `123c99b71c7e33169bef6033eaefb71e386ed6ca`  
**Owner role:** `audit-journal-core-security`  
**Maturity:** `PROVIDER_NEUTRAL_API_IMPLEMENTED`  
**Authority effect:** `NONE`

## Purpose and non-goals

Defines provider-neutral authenticated append/replay contracts, checked sequence numbers and bounded non-clone journal payloads.

This crate does not by itself grant qualification, compatibility, production, migration or release authority. It must not be used to infer behavior outside the currently declared profile.

## Maturity and authority boundary

The source is a bounded foundation component. Technical tests establish only the checked invariants on the exact source. Production provider selection, independent review and an authority grant are separate objects.

## Ownership and trust boundary

- Authoritative writer: one configured journal implementation.
- Accountable owner role: `audit-journal-core-security`.
- Inputs from clients, storage, providers, plugins, clocks, filesystems and evidence stores are untrusted unless explicitly wrapped by a verified type.
- Callers may not bypass typed constructors or reinterpret an error as success.

## Dependency contract

Direct HeptaBao dependencies:
- `none`

Reverse HeptaBao dependants:
- `heptabao-journaled-core`
- `heptabao-key-lifecycle`
- `heptabao-operation-ledger`
- `heptabao-recovery-core`
- `heptabao-rollback-anchor`
- `heptabao-single-node-journal`

The allowed direction follows the system crate graph: provider-neutral types and APIs do not depend on adapters; governance and Oracle tooling do not enter the product authority path.

## Public API index

<!-- BEGIN GENERATED V1.4.7 PUBLIC API TRUTH; DO NOT EDIT -->
Source-bound lexical inventory: `crates/heptabao-journal-api`; Cargo SHA-256 `ff34ae29a8c1c7148b47e50437c32e7f873ea22cd911f5ad71401df39ebb5dec`.

| Kind | Name | Source | Declaration |
|---|---|---|---|
| `const` | `MAX_JOURNAL_PAYLOAD_BYTES` | `crates/heptabao-journal-api/src/lib.rs:14` | `pub const MAX_JOURNAL_PAYLOAD_BYTES: usize = 1024 * 1024;` |
| `const` | `MAX_JOURNAL_DOMAIN_BYTES` | `crates/heptabao-journal-api/src/lib.rs:15` | `pub const MAX_JOURNAL_DOMAIN_BYTES: usize = 128;` |
| `const` | `MAX_AUTHENTICATOR_ID_BYTES` | `crates/heptabao-journal-api/src/lib.rs:16` | `pub const MAX_AUTHENTICATOR_ID_BYTES: usize = 128;` |
| `struct` | `JournalDomain` | `crates/heptabao-journal-api/src/lib.rs:19` | `pub struct JournalDomain(String);` |
| `fn` | `new` | `crates/heptabao-journal-api/src/lib.rs:22` | `pub fn new(value: String) -> Result<Self, JournalContractError> {` |
| `fn` | `as_str` | `crates/heptabao-journal-api/src/lib.rs:29` | `pub fn as_str(&self) -> &str {` |
| `struct` | `AuthenticatorId` | `crates/heptabao-journal-api/src/lib.rs:35` | `pub struct AuthenticatorId(String);` |
| `fn` | `new` | `crates/heptabao-journal-api/src/lib.rs:38` | `pub fn new(value: String) -> Result<Self, JournalContractError> {` |
| `fn` | `as_str` | `crates/heptabao-journal-api/src/lib.rs:45` | `pub fn as_str(&self) -> &str {` |
| `struct` | `JournalSequence` | `crates/heptabao-journal-api/src/lib.rs:70` | `pub struct JournalSequence(u64);` |
| `const` | `INITIAL` | `crates/heptabao-journal-api/src/lib.rs:73` | `pub const INITIAL: Self = Self(1);` |
| `const` | `fn` | `crates/heptabao-journal-api/src/lib.rs:75` | `pub const fn new(value: u64) -> Result<Self, JournalContractError> {` |
| `const` | `fn` | `crates/heptabao-journal-api/src/lib.rs:82` | `pub const fn get(self) -> u64 {` |
| `const` | `fn` | `crates/heptabao-journal-api/src/lib.rs:86` | `pub const fn checked_next(self) -> Result<Self, JournalContractError> {` |
| `struct` | `JournalTag` | `crates/heptabao-journal-api/src/lib.rs:95` | `pub struct JournalTag([u8; 32]);` |
| `fn` | `new` | `crates/heptabao-journal-api/src/lib.rs:98` | `pub fn new(value: [u8; 32]) -> Result<Self, JournalContractError> {` |
| `const` | `fn` | `crates/heptabao-journal-api/src/lib.rs:105` | `pub const fn bytes(self) -> [u8; 32] {` |
| `struct` | `JournalPayload` | `crates/heptabao-journal-api/src/lib.rs:117` | `pub struct JournalPayload(Vec<u8>);` |
| `fn` | `new` | `crates/heptabao-journal-api/src/lib.rs:120` | `pub fn new(mut value: Vec<u8>) -> Result<Self, JournalContractError> {` |
| `fn` | `as_bytes` | `crates/heptabao-journal-api/src/lib.rs:128` | `pub fn as_bytes(&self) -> &[u8] {` |
| `fn` | `len` | `crates/heptabao-journal-api/src/lib.rs:132` | `pub fn len(&self) -> usize {` |
| `fn` | `is_empty` | `crates/heptabao-journal-api/src/lib.rs:136` | `pub fn is_empty(&self) -> bool {` |
| `fn` | `into_bytes` | `crates/heptabao-journal-api/src/lib.rs:140` | `pub fn into_bytes(mut self) -> Vec<u8> {` |
| `struct` | `JournalRecord` | `crates/heptabao-journal-api/src/lib.rs:162` | `pub struct JournalRecord {` |
| `struct` | `JournalTail` | `crates/heptabao-journal-api/src/lib.rs:182` | `pub struct JournalTail {` |
| `struct` | `AppendReceipt` | `crates/heptabao-journal-api/src/lib.rs:188` | `pub struct AppendReceipt {` |
| `enum` | `JournalOpenMode` | `crates/heptabao-journal-api/src/lib.rs:194` | `pub enum JournalOpenMode {` |
| `enum` | `AppendFailureDisposition` | `crates/heptabao-journal-api/src/lib.rs:204` | `pub enum AppendFailureDisposition {` |
| `trait` | `JournalAuthenticator` | `crates/heptabao-journal-api/src/lib.rs:209` | `pub trait JournalAuthenticator: fmt::Debug + Send + Sync {` |
| `trait` | `DurableJournal` | `crates/heptabao-journal-api/src/lib.rs:223` | `pub trait DurableJournal: fmt::Debug + Send {` |
| `enum` | `JournalContractError` | `crates/heptabao-journal-api/src/lib.rs:255` | `pub enum JournalContractError {` |

This table is generated from the exact candidate source. It is a bounded lexical inventory, not a stability or compatibility promise.
<!-- END GENERATED V1.4.7 PUBLIC API TRUTH -->

## State and invariants

- Sequence numbers are non-zero and checked.
- Authentication tags and domain identities are canonical.
- Payloads are bounded, non-clone and redacted.
- Append and replay share the same chain invariants.

A code change that weakens one of these invariants requires a new plan revision rather than a silent compatibility interpretation.

## Failure and retry semantics

An unknown append result requires replay/reconciliation; callers must not append a duplicate event blindly.

Errors are part of the public contract. Unknown, blocked, stale, corrupt, unauthenticated and unauthorized outcomes remain distinct. Callers must not collapse them into a generic retryable transport failure.

## Persistent or wire formats

All durable or wire encodings are versioned, bounded and strict. Decoders reject truncation, impossible lengths, invalid identity/version and trailing bytes. Exact field layouts remain normative in the linked domain contract and source tests.

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
- `domain_and_authenticator_identity_are_canonical` (crates/heptabao-journal-api/src/lib.rs)
- `payload_debug_is_redacted_and_consumable_without_clone` (crates/heptabao-journal-api/src/lib.rs)
- `sequence_is_checked_and_non_zero` (crates/heptabao-journal-api/src/lib.rs)
- `zero_tag_is_rejected` (crates/heptabao-journal-api/src/lib.rs)

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

Expose tail sequence/tag and corruption class only; payload bytes remain confidential.

Diagnostics use stable typed error classes and opaque correlation identities. Operators must preserve suspect state for investigation instead of deleting files or rewriting evidence to obtain a pass.

## Known gaps

- No production authentication provider selected.
- Retention and compaction contracts are incomplete.
- Replicated audit is not implemented.


## Traceability and maintenance

- Crate path: `crates/heptabao-journal-api`
- Module guide: `docs/modules/heptabao-journal-api.md`
- Source baseline: `3582fda50cd9b03ca39713814cdd8229462bbbd2` / `123c99b71c7e33169bef6033eaefb71e386ed6ca`
- Validation: `scripts/validate_module_documentation_v1_4_4.py`
- Coverage object: `planning/HEPTABAO_MODULE_DOCUMENTATION_COVERAGE_V1_4_4.yaml`

The owner updates this document whenever public API, dependency edges, persistent formats, security invariants, retry behavior, tests or known gaps change.


### V1.4.5 append-outcome classification

A failed `DurableJournal::append` is not assumed to be a known non-write. Providers
must classify the error through `classify_append_failure`. The default is
`OutcomeUnknown`; only a provider with affirmative evidence that neither the record
nor tail was published may return `DefinitelyNotAppended`. Callers must fence writes
on the unknown disposition until a fresh open performs authenticated replay.

## V1.4.6 authoritative replay contract

`recover_authoritative` is the only provider-neutral path for clearing an
append-unknown ledger fence. It must refresh cached provider state, authenticate
the committed prefix and reconcile any provider-defined exact-next durable
artifact before returning records. The default append-failure disposition
remains `OutcomeUnknown`; optimistic error-name classification is forbidden.

## Machine-verified source truth

<!-- BEGIN GENERATED V1.4.7 MODULE FACTS; DO NOT EDIT -->
- Crate: `heptabao-journal-api`
- Crate path: `crates/heptabao-journal-api`
- Cargo manifest SHA-256: `ff34ae29a8c1c7148b47e50437c32e7f873ea22cd911f5ad71401df39ebb5dec`
- Rust source files: `1`
- Public lexical declarations: `31`
- Discovered test functions: `4`
- Workspace-internal dependencies: none
- Authoritative inventory: `planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml`
- Regeneration: `python scripts/render_plan_v1_4_7.py --write`
- Verification: `python scripts/render_plan_v1_4_7.py --check`
<!-- END GENERATED V1.4.7 MODULE FACTS -->
