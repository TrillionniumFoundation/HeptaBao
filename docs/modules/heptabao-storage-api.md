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

- `const INITIAL` (crates/heptabao-storage-api/src/lib.rs)
- `const MAX_INTEGRITY_ALGORITHM_ID_BYTES` (crates/heptabao-storage-api/src/lib.rs)
- `const MAX_OPAQUE_STATE_BYTES` (crates/heptabao-storage-api/src/lib.rs)
- `const MAX_STORE_DOMAIN_BYTES` (crates/heptabao-storage-api/src/lib.rs)
- `const fn` (crates/heptabao-storage-api/src/lib.rs)
- `enum StorageContractError` (crates/heptabao-storage-api/src/lib.rs)
- `enum StoreOpenMode` (crates/heptabao-storage-api/src/lib.rs)
- `fn as_bytes` (crates/heptabao-storage-api/src/lib.rs)
- `fn as_str` (crates/heptabao-storage-api/src/lib.rs)
- `fn into_bytes` (crates/heptabao-storage-api/src/lib.rs)
- `fn is_empty` (crates/heptabao-storage-api/src/lib.rs)
- `fn len` (crates/heptabao-storage-api/src/lib.rs)
- `fn new` (crates/heptabao-storage-api/src/lib.rs)
- `struct CommitReceipt` (crates/heptabao-storage-api/src/lib.rs)
- `struct GenerationSnapshot` (crates/heptabao-storage-api/src/lib.rs)
- `struct Generation` (crates/heptabao-storage-api/src/lib.rs)
- `struct IntegrityAlgorithmId` (crates/heptabao-storage-api/src/lib.rs)
- `struct OpaqueState` (crates/heptabao-storage-api/src/lib.rs)
- `struct StateDigest` (crates/heptabao-storage-api/src/lib.rs)
- `struct StoreDomain` (crates/heptabao-storage-api/src/lib.rs)
- `trait DurableGenerationStore` (crates/heptabao-storage-api/src/lib.rs)
- `trait IntegrityProvider` (crates/heptabao-storage-api/src/lib.rs)

This index is generated from explicit `pub` declarations and is not a replacement for rustdoc. New public items require an invariant, error semantics, tests and an entry in this guide.

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
