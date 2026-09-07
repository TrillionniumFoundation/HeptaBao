# `heptabao-durable-core` developer guide

**Source baseline:** `3582fda50cd9b03ca39713814cdd8229462bbbd2`  
**Source tree:** `123c99b71c7e33169bef6033eaefb71e386ed6ca`  
**Owner role:** `core-storage-barrier`  
**Maturity:** `SINGLE_NODE_FOUNDATION_IMPLEMENTED`  
**Authority effect:** `NONE`

## Purpose and non-goals

Composes barrier sealing with a durable generation store and verifies exact generation receipts before acknowledging mutation.

This crate does not by itself grant qualification, compatibility, production, migration or release authority. It must not be used to infer behavior outside the currently declared profile.

## Maturity and authority boundary

The source is a bounded foundation component. Technical tests establish only the checked invariants on the exact source. Production provider selection, independent review and an authority grant are separate objects.

## Ownership and trust boundary

- Authoritative writer: the configured durable generation store.
- Accountable owner role: `core-storage-barrier`.
- Inputs from clients, storage, providers, plugins, clocks, filesystems and evidence stores are untrusted unless explicitly wrapped by a verified type.
- Callers may not bypass typed constructors or reinterpret an error as success.

## Dependency contract

Direct HeptaBao dependencies:
- `heptabao-barrier-api`
- `heptabao-storage-api`

Reverse HeptaBao dependants:
- `heptabao-journaled-core`

The allowed direction follows the system crate graph: provider-neutral types and APIs do not depend on adapters; governance and Oracle tooling do not enter the product authority path.

## Public API index

<!-- BEGIN GENERATED V1.4.7 PUBLIC API TRUTH; DO NOT EDIT -->
Source-bound lexical inventory: `crates/heptabao-durable-core`; Cargo SHA-256 `b47355056fc09de553586bc31dd34dc9b5d5a24294c12a6ec9e316ade064902f`.

| Kind | Name | Source | Declaration |
|---|---|---|---|
| `struct` | `DurableStateEngine` | `crates/heptabao-durable-core/src/lib.rs:24` | `pub struct DurableStateEngine<S, B> {` |
| `const` | `fn` | `crates/heptabao-durable-core/src/lib.rs:30` | `pub const fn new(store: S, barrier: B) -> Self {` |
| `const` | `fn` | `crates/heptabao-durable-core/src/lib.rs:34` | `pub const fn store(&self) -> &S {` |
| `const` | `fn` | `crates/heptabao-durable-core/src/lib.rs:38` | `pub const fn barrier(&self) -> &B {` |
| `struct` | `PreparedDurableMutation` | `crates/heptabao-durable-core/src/lib.rs:57` | `pub struct PreparedDurableMutation {` |
| `const` | `fn` | `crates/heptabao-durable-core/src/lib.rs:63` | `pub const fn intent(&self) -> CommitIntent {` |
| `fn` | `prepare_persist` | `crates/heptabao-durable-core/src/lib.rs:84` | `pub fn prepare_persist(` |
| `fn` | `commit_prepared` | `crates/heptabao-durable-core/src/lib.rs:139` | `pub fn commit_prepared(` |
| `fn` | `recover_commit` | `crates/heptabao-durable-core/src/lib.rs:153` | `pub fn recover_commit(` |
| `fn` | `persist` | `crates/heptabao-durable-core/src/lib.rs:162` | `pub fn persist(` |
| `fn` | `load_current` | `crates/heptabao-durable-core/src/lib.rs:172` | `pub fn load_current(` |
| `struct` | `LoadedSecretState` | `crates/heptabao-durable-core/src/lib.rs:209` | `pub struct LoadedSecretState {` |
| `enum` | `DurableCoreError` | `crates/heptabao-durable-core/src/lib.rs:229` | `pub enum DurableCoreError<S, B>` |

This table is generated from the exact candidate source. It is a bounded lexical inventory, not a stability or compatibility promise.
<!-- END GENERATED V1.4.7 PUBLIC API TRUTH -->

## State and invariants

- Stale expected generation is rejected before provider work.
- Plaintext is sealed before storage commit.
- Returned receipt must match the requested next generation and persisted digest.
- Possible publication without durable proof remains an explicit unknown outcome.

A code change that weakens one of these invariants requires a new plan revision rather than a silent compatibility interpretation.

## Failure and retry semantics

Blind retry after CommitOutcomeUnknown is forbidden; callers must reload and reconcile the authoritative generation first.

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
- `associated_data_mismatch_fails_authentication` (crates/heptabao-durable-core/src/lib.rs)
- `plaintext_is_sealed_before_storage_and_round_trips` (crates/heptabao-durable-core/src/lib.rs)
- `stale_expected_generation_is_rejected_before_sealing` (crates/heptabao-durable-core/src/lib.rs)

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

Correlate provider and storage receipts through opaque operation identity; do not emit plaintext, nonce or ciphertext payloads to logs.

Diagnostics use stable typed error classes and opaque correlation identities. Operators must preserve suspect state for investigation instead of deleting files or rewriting evidence to obtain a pass.

## Known gaps

- Not wired into the P0 server.
- No production provider selection.
- No HA or replicated transaction integration.


## Traceability and maintenance

- Crate path: `crates/heptabao-durable-core`
- Module guide: `docs/modules/heptabao-durable-core.md`
- Source baseline: `3582fda50cd9b03ca39713814cdd8229462bbbd2` / `123c99b71c7e33169bef6033eaefb71e386ed6ca`
- Validation: `scripts/validate_module_documentation_v1_4_4.py`
- Coverage object: `planning/HEPTABAO_MODULE_DOCUMENTATION_COVERAGE_V1_4_4.yaml`

The owner updates this document whenever public API, dependency edges, persistent formats, security invariants, retry behavior, tests or known gaps change.


### V1.4.5 capability closure

The production-facing engine no longer returns a mutable store reference and cannot
be decomposed into raw store and barrier providers. Read-only inspection remains
available for exact reconciliation. This keeps barrier-before-storage sequencing an
API capability boundary rather than a caller convention.

## V1.4.6 prepared mutation semantics

`prepare_persist` seals plaintext first and obtains the exact provider commit
descriptor without publishing state. `PreparedDurableMutation` owns both that
descriptor and the sealed candidate and is consumed by `commit_prepared`.
The descriptor exposed for journaling is metadata; only the journaled
composition supplies the intent-before-effect authority sequence.

## Machine-verified source truth

<!-- BEGIN GENERATED V1.4.7 MODULE FACTS; DO NOT EDIT -->
- Crate: `heptabao-durable-core`
- Crate path: `crates/heptabao-durable-core`
- Cargo manifest SHA-256: `b47355056fc09de553586bc31dd34dc9b5d5a24294c12a6ec9e316ade064902f`
- Rust source files: `1`
- Public lexical declarations: `13`
- Discovered test functions: `4`
- Workspace-internal dependencies: `heptabao-barrier-api` (dependencies), `heptabao-storage-api` (dependencies)
- Authoritative inventory: `planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml`
- Regeneration: `python scripts/render_plan_v1_4_7.py --write`
- Verification: `python scripts/render_plan_v1_4_7.py --check`
<!-- END GENERATED V1.4.7 MODULE FACTS -->
