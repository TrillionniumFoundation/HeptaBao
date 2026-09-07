# `heptabao-oracle-observer` developer guide

**Source baseline:** `3582fda50cd9b03ca39713814cdd8229462bbbd2`  
**Source tree:** `123c99b71c7e33169bef6033eaefb71e386ed6ca`  
**Owner role:** `compatibility-clean-room-security`  
**Maturity:** `OBSERVATION_FOUNDATION_UNQUALIFIED`  
**Authority effect:** `NONE`

## Purpose and non-goals

Represents sanitized compatibility observations and validates declared side-effect deltas without making Oracle material a runtime dependency.

This crate does not by itself grant qualification, compatibility, production, migration or release authority. It must not be used to infer behavior outside the currently declared profile.

## Maturity and authority boundary

The source is a bounded foundation component. Technical tests establish only the checked invariants on the exact source. Production provider selection, independent review and an authority grant are separate objects.

## Ownership and trust boundary

- Authoritative writer: restricted Oracle laboratory only.
- Accountable owner role: `compatibility-clean-room-security`.
- Inputs from clients, storage, providers, plugins, clocks, filesystems and evidence stores are untrusted unless explicitly wrapped by a verified type.
- Callers may not bypass typed constructors or reinterpret an error as success.

## Dependency contract

Direct HeptaBao dependencies:
- `none`

Reverse HeptaBao dependants:
- `none`

The allowed direction follows the system crate graph: provider-neutral types and APIs do not depend on adapters; governance and Oracle tooling do not enter the product authority path.

## Public API index

- `const fn` (crates/heptabao-oracle-observer/src/lib.rs)
- `enum AuthorityEffect` (crates/heptabao-oracle-observer/src/lib.rs)
- `enum CaptureKind` (crates/heptabao-oracle-observer/src/lib.rs)
- `enum ObservationError` (crates/heptabao-oracle-observer/src/lib.rs)
- `struct ObservationContext` (crates/heptabao-oracle-observer/src/lib.rs)
- `struct SideEffectDelta` (crates/heptabao-oracle-observer/src/lib.rs)
- `struct SideEffectPolicy` (crates/heptabao-oracle-observer/src/lib.rs)
- `struct SideEffectSnapshot` (crates/heptabao-oracle-observer/src/lib.rs)

This index is generated from explicit `pub` declarations and is not a replacement for rustdoc. New public items require an invariant, error semantics, tests and an entry in this guide.

## State and invariants

- Synthetic and black-box captures are distinct.
- Black-box evidence requires raw digest and verified transfer.
- Secret markers and undeclared security side effects are rejected.
- Oracle data never grants authority.

A code change that weakens one of these invariants requires a new plan revision rather than a silent compatibility interpretation.

## Failure and retry semantics

A rejected capture must be recaptured and re-sanitized under the restricted workflow; implementation code must not repair Oracle evidence.

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
- `black_box_oracle_requires_verified_artifact` (crates/heptabao-oracle-observer/src/lib.rs)
- `empty_delta_is_empty` (crates/heptabao-oracle-observer/src/lib.rs)
- `health_observation_allows_audit_only` (crates/heptabao-oracle-observer/src/lib.rs)
- `secret_material_is_rejected` (crates/heptabao-oracle-observer/src/lib.rs)
- `synthetic_contract_has_no_authority` (crates/heptabao-oracle-observer/src/lib.rs)
- `undeclared_token_mutation_is_rejected` (crates/heptabao-oracle-observer/src/lib.rs)

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

Retain raw material only in the restricted evidence store and transfer only deterministic sanitized outputs with signed provenance.

Diagnostics use stable typed error classes and opaque correlation identities. Operators must preserve suspect state for investigation instead of deleting files or rewriting evidence to obtain a pass.

## Known gaps

- No repository-verifiable restricted fixture transfer.
- Compatibility coverage is incomplete.
- Independent clean-room role separation remains external.


## Traceability and maintenance

- Crate path: `crates/heptabao-oracle-observer`
- Module guide: `docs/modules/heptabao-oracle-observer.md`
- Source baseline: `3582fda50cd9b03ca39713814cdd8229462bbbd2` / `123c99b71c7e33169bef6033eaefb71e386ed6ca`
- Validation: `scripts/validate_module_documentation_v1_4_4.py`
- Coverage object: `planning/HEPTABAO_MODULE_DOCUMENTATION_COVERAGE_V1_4_4.yaml`

The owner updates this document whenever public API, dependency edges, persistent formats, security invariants, retry behavior, tests or known gaps change.
