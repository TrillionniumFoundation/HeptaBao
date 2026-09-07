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

- `const INITIAL` (crates/heptabao-barrier-api/src/lib.rs)
- `const MAX_ASSOCIATED_DATA_BYTES` (crates/heptabao-barrier-api/src/lib.rs)
- `const MAX_BARRIER_FIELD_BYTES` (crates/heptabao-barrier-api/src/lib.rs)
- `const SEALED_ENVELOPE_VERSION` (crates/heptabao-barrier-api/src/lib.rs)
- `const fn` (crates/heptabao-barrier-api/src/lib.rs)
- `enum BarrierContractError` (crates/heptabao-barrier-api/src/lib.rs)
- `enum BarrierPurpose` (crates/heptabao-barrier-api/src/lib.rs)
- `fn as_bytes` (crates/heptabao-barrier-api/src/lib.rs)
- `fn authentication_tag` (crates/heptabao-barrier-api/src/lib.rs)
- `fn canonical_associated_data` (crates/heptabao-barrier-api/src/lib.rs)
- `fn ciphertext` (crates/heptabao-barrier-api/src/lib.rs)
- `fn decode` (crates/heptabao-barrier-api/src/lib.rs)
- `fn domain` (crates/heptabao-barrier-api/src/lib.rs)
- `fn encode` (crates/heptabao-barrier-api/src/lib.rs)
- `fn into_bytes` (crates/heptabao-barrier-api/src/lib.rs)
- `fn is_empty` (crates/heptabao-barrier-api/src/lib.rs)
- `fn len` (crates/heptabao-barrier-api/src/lib.rs)
- `fn new` (crates/heptabao-barrier-api/src/lib.rs)
- `fn nonce` (crates/heptabao-barrier-api/src/lib.rs)
- `struct BarrierContext` (crates/heptabao-barrier-api/src/lib.rs)
- `struct KeyEpoch` (crates/heptabao-barrier-api/src/lib.rs)
- `struct SealedEnvelope` (crates/heptabao-barrier-api/src/lib.rs)
- `struct SecretState` (crates/heptabao-barrier-api/src/lib.rs)
- `trait BarrierProvider` (crates/heptabao-barrier-api/src/lib.rs)

This index is generated from explicit `pub` declarations and is not a replacement for rustdoc. New public items require an invariant, error semantics, tests and an entry in this guide.

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
