# `heptabao-journaled-core` developer guide

**Source baseline:** `3582fda50cd9b03ca39713814cdd8229462bbbd2`  
**Source tree:** `123c99b71c7e33169bef6033eaefb71e386ed6ca`  
**Owner role:** `core-audit-storage`  
**Maturity:** `SINGLE_NODE_JOURNALED_FOUNDATION_IMPLEMENTED`  
**Authority effect:** `NONE`

## Purpose and non-goals

Coordinates durable operation-ledger transitions with barrier and storage mutation, including response-audit and delivery outcomes.

This crate does not by itself grant qualification, compatibility, production, migration or release authority. It must not be used to infer behavior outside the currently declared profile.

## Maturity and authority boundary

The source is a bounded foundation component. Technical tests establish only the checked invariants on the exact source. Production provider selection, independent review and an authority grant are separate objects.

## Ownership and trust boundary

- Authoritative writer: operation ledger plus durable state store under one process owner.
- Accountable owner role: `core-audit-storage`.
- Inputs from clients, storage, providers, plugins, clocks, filesystems and evidence stores are untrusted unless explicitly wrapped by a verified type.
- Callers may not bypass typed constructors or reinterpret an error as success.

## Dependency contract

Direct HeptaBao dependencies:
- `heptabao-barrier-api`
- `heptabao-durable-core`
- `heptabao-journal-api`
- `heptabao-operation-ledger`
- `heptabao-storage-api`

Reverse HeptaBao dependants:
- `none`

The allowed direction follows the system crate graph: provider-neutral types and APIs do not depend on adapters; governance and Oracle tooling do not enter the product authority path.

## Public API index

- `const fn` (crates/heptabao-journaled-core/src/lib.rs)
- `enum JournaledCoreError` (crates/heptabao-journaled-core/src/lib.rs)
- `fn into_parts` (crates/heptabao-journaled-core/src/lib.rs)
- `fn persist_mutation` (crates/heptabao-journaled-core/src/lib.rs)
- `fn reconcile_committed_state` (crates/heptabao-journaled-core/src/lib.rs)
- `fn reconcile` (crates/heptabao-journaled-core/src/lib.rs)
- `fn record_delivery` (crates/heptabao-journaled-core/src/lib.rs)
- `fn record_rejected_before_dispatch` (crates/heptabao-journaled-core/src/lib.rs)
- `fn record_response_audit_failure_after_commit` (crates/heptabao-journaled-core/src/lib.rs)
- `fn record_response_audited` (crates/heptabao-journaled-core/src/lib.rs)
- `struct JournaledCommitReceipt` (crates/heptabao-journaled-core/src/lib.rs)
- `struct JournaledDurableCore` (crates/heptabao-journaled-core/src/lib.rs)
- `type JournaledCoreResult` (crates/heptabao-journaled-core/src/lib.rs)

This index is generated from explicit `pub` declarations and is not a replacement for rustdoc. New public items require an invariant, error semantics, tests and an entry in this guide.

## State and invariants

- Accepted and IntentCommitted precede state mutation.
- StateCommitted binds the exact generation receipt.
- Duplicate operation identity never mutates twice.
- Post-commit audit failure preserves the committed result and recovery reference.
- Unresolved operations fence later generations until reconciliation.

A code change that weakens one of these invariants requires a new plan revision rather than a silent compatibility interpretation.

## Failure and retry semantics

Retry directives are typed: lookup, reconcile, manual hold or new operation. Creation retry after an unknown external effect is forbidden.

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
- `accepted_pre_dispatch_failure_can_be_durably_rejected` (crates/heptabao-journaled-core/src/lib.rs)
- `intent_precedes_state_commit_and_duplicate_never_mutates_again` (crates/heptabao-journaled-core/src/lib.rs)
- `postcommit_ledger_failure_returns_committed_generation` (crates/heptabao-journaled-core/src/lib.rs)
- `response_audit_and_delivery_are_durable_ledger_transitions` (crates/heptabao-journaled-core/src/lib.rs)
- `unresolved_operation_fences_new_generation_until_reconciled` (crates/heptabao-journaled-core/src/lib.rs)

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

Operators reconcile from the authoritative snapshot and immutable ledger; never edit ledger files manually.

Diagnostics use stable typed error classes and opaque correlation identities. Operators must preserve suspect state for investigation instead of deleting files or rewriting evidence to obtain a pass.

## Known gaps

- Not wired into the network server.
- External-effect provider adapters are absent.
- Replicated ledger/audit recovery is absent.


## Traceability and maintenance

- Crate path: `crates/heptabao-journaled-core`
- Module guide: `docs/modules/heptabao-journaled-core.md`
- Source baseline: `3582fda50cd9b03ca39713814cdd8229462bbbd2` / `123c99b71c7e33169bef6033eaefb71e386ed6ca`
- Validation: `scripts/validate_module_documentation_v1_4_4.py`
- Coverage object: `planning/HEPTABAO_MODULE_DOCUMENTATION_COVERAGE_V1_4_4.yaml`

The owner updates this document whenever public API, dependency edges, persistent formats, security invariants, retry behavior, tests or known gaps change.


### V1.4.5 reconciliation closure

The composition cannot be decomposed into independently writable state and ledger
objects. Generic reconciliation rejects a durable mutation at `IntentCommitted`.
Only `reconcile_committed_state`, after rereading authoritative storage and matching
both generation and digest, can advance such an operation. An append-unknown ledger
error poisons all later journal writes until reopen and replay.

## V1.4.6 interrupted commit recovery

The composition records `Accepted` and exact `IntentCommitted` evidence before
calling the state provider. Recovery derives the descriptor from the replayed
operation, invokes authoritative store classification, and records either
`StateCommitted` or `AbortedBeforeStateCommit`. Divergent provider state remains
fenced. Generic `Reconciled` is still forbidden for durable mutation intent.
The file-provider integration suite covers failures before/after storage and
journal publication boundaries.
