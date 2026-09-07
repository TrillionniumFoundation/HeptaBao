# `heptabao-governance` developer guide

**Source baseline:** `3582fda50cd9b03ca39713814cdd8229462bbbd2`  
**Source tree:** `123c99b71c7e33169bef6033eaefb71e386ed6ca`  
**Owner role:** `program-governance-security`  
**Maturity:** `GOVERNANCE_SENTINEL_IMPLEMENTED`  
**Authority effect:** `NONE`

## Purpose and non-goals

Implements fail-closed validation of qualification evidence and preserves the separation between technical evidence, compatibility claims and scoped authority grants.

This crate does not by itself grant qualification, compatibility, production, migration or release authority. It must not be used to infer behavior outside the currently declared profile.

## Maturity and authority boundary

The source is a bounded foundation component. Technical tests establish only the checked invariants on the exact source. Production provider selection, independent review and an authority grant are separate objects.

## Ownership and trust boundary

- Authoritative writer: none in runtime; signed governance objects are externally produced.
- Accountable owner role: `program-governance-security`.
- Inputs from clients, storage, providers, plugins, clocks, filesystems and evidence stores are untrusted unless explicitly wrapped by a verified type.
- Callers may not bypass typed constructors or reinterpret an error as success.

## Dependency contract

Direct HeptaBao dependencies:
- `none`

Reverse HeptaBao dependants:
- `none`

The allowed direction follows the system crate graph: provider-neutral types and APIs do not depend on adapters; governance and Oracle tooling do not enter the product authority path.

## Public API index

- `const H00_AUTHORITY` (crates/heptabao-governance/src/lib.rs)
- `const fn` (crates/heptabao-governance/src/lib.rs)
- `enum AuthorityEffect` (crates/heptabao-governance/src/lib.rs)
- `enum QualificationError` (crates/heptabao-governance/src/lib.rs)
- `struct FindingSummary` (crates/heptabao-governance/src/lib.rs)
- `struct PlanningAuthority` (crates/heptabao-governance/src/lib.rs)
- `struct QualificationFacts` (crates/heptabao-governance/src/lib.rs)
- `struct TestSummary` (crates/heptabao-governance/src/lib.rs)

This index is generated from explicit `pub` declarations and is not a replacement for rustdoc. New public items require an invariant, error semantics, tests and an entry in this guide.

## State and invariants

- Failed, unknown or missing tests reject qualification.
- Critical, High or unclassified findings reject qualification.
- Qualification never grants operational authority.
- Revocation has precedence over a previously valid receipt.

A code change that weakens one of these invariants requires a new plan revision rather than a silent compatibility interpretation.

## Failure and retry semantics

A rejected evidence graph requires a new complete and current graph; mutating a rejected object in place is not a valid retry.

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
- `every_h00_authority_flag_is_false` (crates/heptabao-governance/src/lib.rs)
- `failed_tests_reject_qualification` (crates/heptabao-governance/src/lib.rs)
- `high_finding_rejects_qualification` (crates/heptabao-governance/src/lib.rs)
- `qualification_never_grants_authority` (crates/heptabao-governance/src/lib.rs)
- `revoked_receipt_rejects_qualification` (crates/heptabao-governance/src/lib.rs)
- `unknown_tests_reject_qualification` (crates/heptabao-governance/src/lib.rs)

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

Verification must bind signatures, scope, source, expiry and revocation state and retain the rejected reason set.

Diagnostics use stable typed error classes and opaque correlation identities. Operators must preserve suspect state for investigation instead of deleting files or rewriting evidence to obtain a pass.

## Known gaps

- External signer/trust-root infrastructure is not provisioned.
- Independent reviewer receipts remain external.
- Repository rulesets are not automatically configured by this crate.


## Traceability and maintenance

- Crate path: `crates/heptabao-governance`
- Module guide: `docs/modules/heptabao-governance.md`
- Source baseline: `3582fda50cd9b03ca39713814cdd8229462bbbd2` / `123c99b71c7e33169bef6033eaefb71e386ed6ca`
- Validation: `scripts/validate_module_documentation_v1_4_4.py`
- Coverage object: `planning/HEPTABAO_MODULE_DOCUMENTATION_COVERAGE_V1_4_4.yaml`

The owner updates this document whenever public API, dependency edges, persistent formats, security invariants, retry behavior, tests or known gaps change.
