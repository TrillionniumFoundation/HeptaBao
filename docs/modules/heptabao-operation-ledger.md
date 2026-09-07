# `heptabao-operation-ledger` developer guide

**Source baseline:** `3582fda50cd9b03ca39713814cdd8229462bbbd2`  
**Source tree:** `123c99b71c7e33169bef6033eaefb71e386ed6ca`  
**Owner role:** `core-audit-reconciliation`  
**Maturity:** `DURABLE_STATE_MACHINE_FOUNDATION_IMPLEMENTED`  
**Authority effect:** `NONE`

## Purpose and non-goals

Records immutable operation identity and a closed transition graph used to prevent duplicate mutation and drive deterministic reconciliation.

This crate does not by itself grant qualification, compatibility, production, migration or release authority. It must not be used to infer behavior outside the currently declared profile.

## Maturity and authority boundary

The source is a bounded foundation component. Technical tests establish only the checked invariants on the exact source. Production provider selection, independent review and an authority grant are separate objects.

## Ownership and trust boundary

- Authoritative writer: one operation-ledger journal writer.
- Accountable owner role: `core-audit-reconciliation`.
- Inputs from clients, storage, providers, plugins, clocks, filesystems and evidence stores are untrusted unless explicitly wrapped by a verified type.
- Callers may not bypass typed constructors or reinterpret an error as success.

## Dependency contract

Direct HeptaBao dependencies:
- `heptabao-journal-api`
- `heptabao-storage-api`

Reverse HeptaBao dependants:
- `heptabao-journaled-core`

The allowed direction follows the system crate graph: provider-neutral types and APIs do not depend on adapters; governance and Oracle tooling do not enter the product authority path.

## Public API index

- `const MAX_DETAIL_CODE_BYTES` (crates/heptabao-operation-ledger/src/lib.rs)
- `const MAX_OPERATION_ID_BYTES` (crates/heptabao-operation-ledger/src/lib.rs)
- `const fn` (crates/heptabao-operation-ledger/src/lib.rs)
- `enum OperationClass` (crates/heptabao-operation-ledger/src/lib.rs)
- `enum OperationContractError` (crates/heptabao-operation-ledger/src/lib.rs)
- `enum OperationLedgerError` (crates/heptabao-operation-ledger/src/lib.rs)
- `enum OperationPhase` (crates/heptabao-operation-ledger/src/lib.rs)
- `enum RetryDirective` (crates/heptabao-operation-ledger/src/lib.rs)
- `fn accepted` (crates/heptabao-operation-ledger/src/lib.rs)
- `fn as_str` (crates/heptabao-operation-ledger/src/lib.rs)
- `fn blocking_phase` (crates/heptabao-operation-ledger/src/lib.rs)
- `fn current` (crates/heptabao-operation-ledger/src/lib.rs)
- `fn decode` (crates/heptabao-operation-ledger/src/lib.rs)
- `fn detail_code` (crates/heptabao-operation-ledger/src/lib.rs)
- `fn encode` (crates/heptabao-operation-ledger/src/lib.rs)
- `fn into_journal` (crates/heptabao-operation-ledger/src/lib.rs)
- `fn new` (crates/heptabao-operation-ledger/src/lib.rs)
- `fn next` (crates/heptabao-operation-ledger/src/lib.rs)
- `fn open` (crates/heptabao-operation-ledger/src/lib.rs)
- `fn operation_count` (crates/heptabao-operation-ledger/src/lib.rs)
- `fn operation_id` (crates/heptabao-operation-ledger/src/lib.rs)
- `fn record` (crates/heptabao-operation-ledger/src/lib.rs)
- `fn retry_directive` (crates/heptabao-operation-ledger/src/lib.rs)
- `struct OperationDigest` (crates/heptabao-operation-ledger/src/lib.rs)
- `struct OperationEvent` (crates/heptabao-operation-ledger/src/lib.rs)
- `struct OperationId` (crates/heptabao-operation-ledger/src/lib.rs)
- `struct OperationLedger` (crates/heptabao-operation-ledger/src/lib.rs)
- `struct StableDetailCode` (crates/heptabao-operation-ledger/src/lib.rs)

This index is generated from explicit `pub` declarations and is not a replacement for rustdoc. New public items require an invariant, error semantics, tests and an entry in this guide.

## State and invariants

- Operation, request and effect-class identity are immutable.
- Only declared transitions are accepted.
- Restart replay reconstructs unresolved operations exactly.
- Unknown external effects are reconcile-only.
- Illegal duplicate acceptance fails closed.

A code change that weakens one of these invariants requires a new plan revision rather than a silent compatibility interpretation.

## Failure and retry semantics

The ledger returns a typed retry directive; callers must not infer retry safety from transport status alone.

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
- `duplicate_acceptance_and_illegal_transition_fail_closed` (crates/heptabao-operation-ledger/src/lib.rs)
- `encoded_event_rejects_trailing_bytes` (crates/heptabao-operation-ledger/src/lib.rs)
- `external_unknown_effect_is_reconcile_only` (crates/heptabao-operation-ledger/src/lib.rs)
- `legal_mutation_chain_replays_and_requires_lookup_after_commit` (crates/heptabao-operation-ledger/src/lib.rs)

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

Manual hold and reconciliation actions require an auditable operator identity and the exact authoritative snapshot reference.

Diagnostics use stable typed error classes and opaque correlation identities. Operators must preserve suspect state for investigation instead of deleting files or rewriting evidence to obtain a pass.

## Known gaps

- No administrative reconciliation API.
- No retention/compaction policy.
- No HA writer ownership.


## Traceability and maintenance

- Crate path: `crates/heptabao-operation-ledger`
- Module guide: `docs/modules/heptabao-operation-ledger.md`
- Source baseline: `3582fda50cd9b03ca39713814cdd8229462bbbd2` / `123c99b71c7e33169bef6033eaefb71e386ed6ca`
- Validation: `scripts/validate_module_documentation_v1_4_4.py`
- Coverage object: `planning/HEPTABAO_MODULE_DOCUMENTATION_COVERAGE_V1_4_4.yaml`

The owner updates this document whenever public API, dependency edges, persistent formats, security invariants, retry behavior, tests or known gaps change.


### V1.4.5 poisoned write state

The ledger exposes `LedgerWriteState`. Any append failure classified as
`OutcomeUnknown` transitions the in-memory instance to `ReplayRequired`; every
subsequent `record` fails without invoking the provider. Recovery requires dropping
the instance and constructing a new ledger with `OperationLedger::open`, which
replays the authenticated journal. Durable mutations may not transition directly
from `IntentCommitted` to `Reconciled`; exact storage evidence is required for the
`StateCommitted` transition.

## V1.4.6 persisted-then-error evidence

The append-unknown hostile provider now stores the encoded event before
returning the injected error. The ledger enters `ReplayRequired`, rejects the
next write before provider access, calls authoritative journal recovery, and
reconstructs the persisted operation. The recovered duplicate `Accepted` event
is rejected rather than silently appended again.
