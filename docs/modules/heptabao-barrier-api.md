# `heptabao-barrier-api` developer guide

**Source baseline:** `3582fda50cd9b03ca39713814cdd8229462bbbd2`  
**Source tree:** `123c99b71c7e33169bef6033eaefb71e386ed6ca`  
**Owner role:** `cryptography-barrier-core-security`  
**Maturity:** `PROVIDER_NEUTRAL_API_IMPLEMENTED`  
**Authority effect:** `NONE`

## Purpose and non-goals

Defines the sealed-envelope format, associated-data construction and provider boundary used to prevent plaintext from crossing the durable-store interface.

This crate does not by itself grant qualification, compatibility, production, migration or release authority. It must not be used to infer behavior outside the currently declared profile.

## Maturity and authority boundary

The source is a bounded foundation component. Technical tests establish only the checked invariants on the exact source. Production provider selection, independent review and an authority grant are separate objects.

## Ownership and trust boundary

- Authoritative writer: barrier provider selected by the future server composition root.
- Accountable owner role: `cryptography-barrier-core-security`.
- Inputs from clients, storage, providers, plugins, clocks, filesystems and evidence stores are untrusted unless explicitly wrapped by a verified type.
- Callers may not bypass typed constructors or reinterpret an error as success.

## Dependency contract

Direct HeptaBao dependencies:
- `heptabao-storage-api`

Reverse HeptaBao dependants:
- `heptabao-durable-core`
- `heptabao-journaled-core`
- `heptabao-key-lifecycle`
- `heptabao-recovery-core`
- `heptabao-rollback-anchor`

The allowed direction follows the system crate graph: provider-neutral types and APIs do not depend on adapters; governance and Oracle tooling do not enter the product authority path.

## Public API index

<!-- BEGIN GENERATED V1.4.7 PUBLIC API TRUTH; DO NOT EDIT -->
Source-bound lexical inventory: `crates/heptabao-barrier-api`; Cargo SHA-256 `60cebd8c3e417f4ed40548c425eadec9ba70671cd6a4399c14f0817ab6a4d7e3`.

| Kind | Name | Source | Declaration |
|---|---|---|---|
| `const` | `SEALED_ENVELOPE_VERSION` | `crates/heptabao-barrier-api/src/lib.rs:16` | `pub const SEALED_ENVELOPE_VERSION: u16 = 1;` |
| `const` | `MAX_BARRIER_FIELD_BYTES` | `crates/heptabao-barrier-api/src/lib.rs:17` | `pub const MAX_BARRIER_FIELD_BYTES: usize = 16 * 1024 * 1024;` |
| `const` | `MAX_ASSOCIATED_DATA_BYTES` | `crates/heptabao-barrier-api/src/lib.rs:18` | `pub const MAX_ASSOCIATED_DATA_BYTES: usize = 64 * 1024;` |
| `struct` | `KeyEpoch` | `crates/heptabao-barrier-api/src/lib.rs:23` | `pub struct KeyEpoch(u64);` |
| `const` | `INITIAL` | `crates/heptabao-barrier-api/src/lib.rs:26` | `pub const INITIAL: Self = Self(1);` |
| `const` | `fn` | `crates/heptabao-barrier-api/src/lib.rs:28` | `pub const fn new(value: u64) -> Result<Self, BarrierContractError> {` |
| `const` | `fn` | `crates/heptabao-barrier-api/src/lib.rs:35` | `pub const fn get(self) -> u64 {` |
| `const` | `fn` | `crates/heptabao-barrier-api/src/lib.rs:39` | `pub const fn checked_next(self) -> Result<Self, BarrierContractError> {` |
| `enum` | `BarrierPurpose` | `crates/heptabao-barrier-api/src/lib.rs:48` | `pub enum BarrierPurpose {` |
| `struct` | `BarrierContext` | `crates/heptabao-barrier-api/src/lib.rs:66` | `pub struct BarrierContext {` |
| `fn` | `new` | `crates/heptabao-barrier-api/src/lib.rs:75` | `pub fn new(` |
| `fn` | `domain` | `crates/heptabao-barrier-api/src/lib.rs:95` | `pub fn domain(&self) -> &StoreDomain {` |
| `const` | `fn` | `crates/heptabao-barrier-api/src/lib.rs:99` | `pub const fn generation(&self) -> Generation {` |
| `const` | `fn` | `crates/heptabao-barrier-api/src/lib.rs:103` | `pub const fn key_epoch(&self) -> KeyEpoch {` |
| `const` | `fn` | `crates/heptabao-barrier-api/src/lib.rs:107` | `pub const fn purpose(&self) -> BarrierPurpose {` |
| `fn` | `canonical_associated_data` | `crates/heptabao-barrier-api/src/lib.rs:111` | `pub fn canonical_associated_data(&self) -> Result<Vec<u8>, BarrierContractError> {` |
| `struct` | `SecretState` | `crates/heptabao-barrier-api/src/lib.rs:146` | `pub struct SecretState(Vec<u8>);` |
| `fn` | `new` | `crates/heptabao-barrier-api/src/lib.rs:149` | `pub fn new(mut value: Vec<u8>) -> Result<Self, BarrierContractError> {` |
| `fn` | `as_bytes` | `crates/heptabao-barrier-api/src/lib.rs:157` | `pub fn as_bytes(&self) -> &[u8] {` |
| `fn` | `len` | `crates/heptabao-barrier-api/src/lib.rs:161` | `pub fn len(&self) -> usize {` |
| `fn` | `is_empty` | `crates/heptabao-barrier-api/src/lib.rs:165` | `pub fn is_empty(&self) -> bool {` |
| `fn` | `into_bytes` | `crates/heptabao-barrier-api/src/lib.rs:169` | `pub fn into_bytes(mut self) -> Vec<u8> {` |
| `struct` | `SealedEnvelope` | `crates/heptabao-barrier-api/src/lib.rs:191` | `pub struct SealedEnvelope {` |
| `fn` | `new` | `crates/heptabao-barrier-api/src/lib.rs:200` | `pub fn new(` |
| `const` | `fn` | `crates/heptabao-barrier-api/src/lib.rs:234` | `pub const fn version(&self) -> u16 {` |
| `const` | `fn` | `crates/heptabao-barrier-api/src/lib.rs:238` | `pub const fn key_epoch(&self) -> KeyEpoch {` |
| `fn` | `nonce` | `crates/heptabao-barrier-api/src/lib.rs:242` | `pub fn nonce(&self) -> &[u8] {` |
| `fn` | `ciphertext` | `crates/heptabao-barrier-api/src/lib.rs:246` | `pub fn ciphertext(&self) -> &[u8] {` |
| `fn` | `authentication_tag` | `crates/heptabao-barrier-api/src/lib.rs:250` | `pub fn authentication_tag(&self) -> &[u8] {` |
| `fn` | `encode` | `crates/heptabao-barrier-api/src/lib.rs:254` | `pub fn encode(&self) -> Result<Vec<u8>, BarrierContractError> {` |
| `fn` | `decode` | `crates/heptabao-barrier-api/src/lib.rs:275` | `pub fn decode(mut encoded: Vec<u8>) -> Result<Self, BarrierContractError> {` |
| `trait` | `BarrierProvider` | `crates/heptabao-barrier-api/src/lib.rs:304` | `pub trait BarrierProvider: fmt::Debug + Send + Sync {` |
| `enum` | `BarrierContractError` | `crates/heptabao-barrier-api/src/lib.rs:323` | `pub enum BarrierContractError {` |

This table is generated from the exact candidate source. It is a bounded lexical inventory, not a stability or compatibility promise.
<!-- END GENERATED V1.4.7 PUBLIC API TRUTH -->

## State and invariants

- Associated data binds domain, generation, key epoch, purpose and caller data.
- Envelope decoding rejects truncation, invalid version and trailing bytes.
- Key material is never embedded in the envelope.
- Secret and envelope Debug output is redacted.

A code change that weakens one of these invariants requires a new plan revision rather than a silent compatibility interpretation.

## Failure and retry semantics

Provider calls occur only after stale-generation rejection. Unknown provider outcomes must not be converted into a successful durable commit.

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
- `context_binds_domain_generation_epoch_purpose_and_caller_data` (crates/heptabao-barrier-api/src/lib.rs)
- `envelope_round_trips_strictly` (crates/heptabao-barrier-api/src/lib.rs)
- `secret_and_envelope_debug_output_is_redacted` (crates/heptabao-barrier-api/src/lib.rs)
- `truncated_and_trailing_envelopes_fail_closed` (crates/heptabao-barrier-api/src/lib.rs)

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

A production provider must expose key identity and epoch diagnostics without exposing key bytes and must support rotation/revocation observability.

Diagnostics use stable typed error classes and opaque correlation identities. Operators must preserve suspect state for investigation instead of deleting files or rewriting evidence to obtain a pass.

## Known gaps

- No production AEAD/KMS/HSM provider is selected.
- Nonce-generation and key-custody ceremonies require independent review.
- Locked-memory, dump and side-channel controls are not qualified.


## Traceability and maintenance

- Crate path: `crates/heptabao-barrier-api`
- Module guide: `docs/modules/heptabao-barrier-api.md`
- Source baseline: `3582fda50cd9b03ca39713814cdd8229462bbbd2` / `123c99b71c7e33169bef6033eaefb71e386ed6ca`
- Validation: `scripts/validate_module_documentation_v1_4_4.py`
- Coverage object: `planning/HEPTABAO_MODULE_DOCUMENTATION_COVERAGE_V1_4_4.yaml`

The owner updates this document whenever public API, dependency edges, persistent formats, security invariants, retry behavior, tests or known gaps change.

## Machine-verified source truth

<!-- BEGIN GENERATED V1.4.7 MODULE FACTS; DO NOT EDIT -->
- Crate: `heptabao-barrier-api`
- Crate path: `crates/heptabao-barrier-api`
- Cargo manifest SHA-256: `60cebd8c3e417f4ed40548c425eadec9ba70671cd6a4399c14f0817ab6a4d7e3`
- Rust source files: `1`
- Public lexical declarations: `33`
- Discovered test functions: `4`
- Workspace-internal dependencies: `heptabao-storage-api` (dependencies)
- Authoritative inventory: `planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml`
- Regeneration: `python scripts/render_plan_v1_4_7.py --write`
- Verification: `python scripts/render_plan_v1_4_7.py --check`
<!-- END GENERATED V1.4.7 MODULE FACTS -->
