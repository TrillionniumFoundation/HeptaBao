# `heptabao-platform-bakeoff` developer guide

**Source baseline:** `3582fda50cd9b03ca39713814cdd8229462bbbd2`  
**Source tree:** `123c99b71c7e33169bef6033eaefb71e386ed6ca`  
**Owner role:** `platform-qualification-security`  
**Maturity:** `BAKEOFF_TOOLING_FOUNDATION`  
**Authority effect:** `NONE`

## Purpose and non-goals

Evaluates dependency candidates against explicit evidence and scoring rules while preventing selection from granting production authority.

This crate does not by itself grant qualification, compatibility, production, migration or release authority. It must not be used to infer behavior outside the currently declared profile.

## Maturity and authority boundary

The source is a bounded foundation component. Technical tests establish only the checked invariants on the exact source. Production provider selection, independent review and an authority grant are separate objects.

## Ownership and trust boundary

- Authoritative writer: candidate evidence index only.
- Accountable owner role: `platform-qualification-security`.
- Inputs from clients, storage, providers, plugins, clocks, filesystems and evidence stores are untrusted unless explicitly wrapped by a verified type.
- Callers may not bypass typed constructors or reinterpret an error as success.

## Dependency contract

Direct HeptaBao dependencies:
- `none`

Reverse HeptaBao dependants:
- `none`

The allowed direction follows the system crate graph: provider-neutral types and APIs do not depend on adapters; governance and Oracle tooling do not enter the product authority path.

## Public API index

- `const MAX_SCORE` (crates/heptabao-platform-bakeoff/src/lib.rs)
- `const PROTOTYPE_SELECTION_MINIMUM` (crates/heptabao-platform-bakeoff/src/lib.rs)
- `const fn` (crates/heptabao-platform-bakeoff/src/lib.rs)
- `enum AuthorityEffect` (crates/heptabao-platform-bakeoff/src/lib.rs)
- `enum BakeoffError` (crates/heptabao-platform-bakeoff/src/lib.rs)
- `enum CandidateState` (crates/heptabao-platform-bakeoff/src/lib.rs)
- `enum Capability` (crates/heptabao-platform-bakeoff/src/lib.rs)
- `struct CandidateEvidence` (crates/heptabao-platform-bakeoff/src/lib.rs)
- `struct Candidate` (crates/heptabao-platform-bakeoff/src/lib.rs)
- `struct PrototypeSelection` (crates/heptabao-platform-bakeoff/src/lib.rs)
- `struct ScoreCard` (crates/heptabao-platform-bakeoff/src/lib.rs)

This index is generated from explicit `pub` declarations and is not a replacement for rustdoc. New public items require an invariant, error semantics, tests and an entry in this guide.

## State and invariants

- Identified or incompletely scored candidates are not selectable.
- Pending license or unclassified findings block selection.
- Prototype selection has no authority effect.
- Candidate identity, version, feature graph and source are exact.

A code change that weakens one of these invariants requires a new plan revision rather than a silent compatibility interpretation.

## Failure and retry semantics

A candidate may be rescored only with a new evidence object bound to the same exact source or an explicitly new candidate revision.

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
- `complete_candidate_can_be_selected_for_prototype_only` (crates/heptabao-platform-bakeoff/src/lib.rs)
- `identified_candidate_is_not_selectable` (crates/heptabao-platform-bakeoff/src/lib.rs)
- `low_score_is_not_selectable` (crates/heptabao-platform-bakeoff/src/lib.rs)
- `pending_license_rejects_selection` (crates/heptabao-platform-bakeoff/src/lib.rs)
- `unclassified_finding_rejects_selection` (crates/heptabao-platform-bakeoff/src/lib.rs)
- `validated_candidate_has_no_authority` (crates/heptabao-platform-bakeoff/src/lib.rs)

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

Preserve failed and blocked evidence; never overwrite a historical comparison with a later pass.

Diagnostics use stable typed error classes and opaque correlation identities. Operators must preserve suspect state for investigation instead of deleting files or rewriting evidence to obtain a pass.

## Known gaps

- Production selections remain empty.
- Independent license/security review is external.
- Real provider integration benchmarks are incomplete.


## Traceability and maintenance

- Crate path: `crates/heptabao-platform-bakeoff`
- Module guide: `docs/modules/heptabao-platform-bakeoff.md`
- Source baseline: `3582fda50cd9b03ca39713814cdd8229462bbbd2` / `123c99b71c7e33169bef6033eaefb71e386ed6ca`
- Validation: `scripts/validate_module_documentation_v1_4_4.py`
- Coverage object: `planning/HEPTABAO_MODULE_DOCUMENTATION_COVERAGE_V1_4_4.yaml`

The owner updates this document whenever public API, dependency edges, persistent formats, security invariants, retry behavior, tests or known gaps change.
