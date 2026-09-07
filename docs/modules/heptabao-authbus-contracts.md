# `heptabao-authbus-contracts` developer guide

**Source baseline:** `3582fda50cd9b03ca39713814cdd8229462bbbd2`  
**Source tree:** `123c99b71c7e33169bef6033eaefb71e386ed6ca`  
**Owner role:** `identity-authentication-security`  
**Maturity:** `FOUNDATION_IMPLEMENTED_NOT_PRODUCTION_AUTHORITY`  
**Authority effect:** `NONE`

## Purpose and non-goals

Defines provider-neutral authentication assertions, request binding, replay rejection and bounded assertion verification. It authenticates a caller but deliberately does not authorize an operation.

This crate does not by itself grant qualification, compatibility, production, migration or release authority. It must not be used to infer behavior outside the currently declared profile.

## Maturity and authority boundary

The source is a bounded foundation component. Technical tests establish only the checked invariants on the exact source. Production provider selection, independent review and an authority grant are separate objects.

## Ownership and trust boundary

- Authoritative writer: none; verification is read-only and replay authority is injected.
- Accountable owner role: `identity-authentication-security`.
- Inputs from clients, storage, providers, plugins, clocks, filesystems and evidence stores are untrusted unless explicitly wrapped by a verified type.
- Callers may not bypass typed constructors or reinterpret an error as success.

## Dependency contract

Direct HeptaBao dependencies:
- `heptabao-protocol`

Reverse HeptaBao dependants:
- `none`

The allowed direction follows the system crate graph: provider-neutral types and APIs do not depend on adapters; governance and Oracle tooling do not enter the product authority path.

## Public API index

- `const MAX_ASSERTION_TTL_SECONDS` (crates/heptabao-authbus-contracts/src/lib.rs)
- `const MAX_CLOCK_SKEW_SECONDS` (crates/heptabao-authbus-contracts/src/lib.rs)
- `const MAX_IDENTITY_BYTES` (crates/heptabao-authbus-contracts/src/lib.rs)
- `const MAX_IN_MEMORY_REPLAY_ENTRIES` (crates/heptabao-authbus-contracts/src/lib.rs)
- `const MAX_SIGNATURE_BYTES` (crates/heptabao-authbus-contracts/src/lib.rs)
- `enum AuthbusError` (crates/heptabao-authbus-contracts/src/lib.rs)
- `enum AuthorizationEffect` (crates/heptabao-authbus-contracts/src/lib.rs)
- `enum DigestAlgorithm` (crates/heptabao-authbus-contracts/src/lib.rs)
- `fn canonical_bytes` (crates/heptabao-authbus-contracts/src/lib.rs)
- `fn unsigned_payload` (crates/heptabao-authbus-contracts/src/lib.rs)
- `fn validate` (crates/heptabao-authbus-contracts/src/lib.rs)
- `fn verify_bound_assertion` (crates/heptabao-authbus-contracts/src/lib.rs)
- `fn with_capacity` (crates/heptabao-authbus-contracts/src/lib.rs)
- `struct AuthbusAssertion` (crates/heptabao-authbus-contracts/src/lib.rs)
- `struct InMemoryReplayCache` (crates/heptabao-authbus-contracts/src/lib.rs)
- `struct RequestBinding` (crates/heptabao-authbus-contracts/src/lib.rs)
- `struct UnixTimeSeconds` (crates/heptabao-authbus-contracts/src/lib.rs)
- `struct VerificationPolicy` (crates/heptabao-authbus-contracts/src/lib.rs)
- `struct VerifiedAuthbusIdentity` (crates/heptabao-authbus-contracts/src/lib.rs)
- `trait AssertionSignatureVerifier` (crates/heptabao-authbus-contracts/src/lib.rs)
- `trait CryptographicDigestProvider` (crates/heptabao-authbus-contracts/src/lib.rs)
- `trait ReplayCache` (crates/heptabao-authbus-contracts/src/lib.rs)

This index is generated from explicit `pub` declarations and is not a replacement for rustdoc. New public items require an invariant, error semantics, tests and an entry in this guide.

## State and invariants

- Authentication and authorization remain separate decisions.
- Assertion identity, key revision, issue/expiry time and canonical request binding are verified together.
- Replay-cache saturation, invalid capacity, expiry ambiguity and request mismatch fail closed.
- Secret-bearing assertion fields and request material are redacted from Debug output.

A code change that weakens one of these invariants requires a new plan revision rather than a silent compatibility interpretation.

## Failure and retry semantics

Verification may be retried only with the same immutable assertion and request binding before expiry. A replay rejection is terminal for that assertion identity.

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
- `assertion_debug_redacts_subject_and_cryptographic_fields` (crates/heptabao-authbus-contracts/src/lib.rs)
- `expiry_key_and_signature_fail_closed` (crates/heptabao-authbus-contracts/src/lib.rs)
- `future_issue_time_respects_bounded_skew` (crates/heptabao-authbus-contracts/src/lib.rs)
- `invalid_replay_cache_capacity_is_rejected` (crates/heptabao-authbus-contracts/src/lib.rs)
- `replay_cache_prunes_expired_entries` (crates/heptabao-authbus-contracts/src/lib.rs)
- `replay_cache_saturation_fails_closed` (crates/heptabao-authbus-contracts/src/lib.rs)
- `replay_is_rejected` (crates/heptabao-authbus-contracts/src/lib.rs)
- `request_binding_debug_redacts_target_host_and_body` (crates/heptabao-authbus-contracts/src/lib.rs)
- `request_binding_mismatch_is_rejected` (crates/heptabao-authbus-contracts/src/lib.rs)
- `valid_assertion_authenticates_but_does_not_authorize` (crates/heptabao-authbus-contracts/src/lib.rs)

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

Inspect verification failures by stable error class and key revision; never log subject, signature, token or request body bytes.

Diagnostics use stable typed error classes and opaque correlation identities. Operators must preserve suspect state for investigation instead of deleting files or rewriting evidence to obtain a pass.

## Known gaps

- Production signer/key-discovery provider is not selected.
- HA replay authority and durable nonce retention are not integrated.
- Identity/MFA and policy authorization domains remain outside this crate.


## Traceability and maintenance

- Crate path: `crates/heptabao-authbus-contracts`
- Module guide: `docs/modules/heptabao-authbus-contracts.md`
- Source baseline: `3582fda50cd9b03ca39713814cdd8229462bbbd2` / `123c99b71c7e33169bef6033eaefb71e386ed6ca`
- Validation: `scripts/validate_module_documentation_v1_4_4.py`
- Coverage object: `planning/HEPTABAO_MODULE_DOCUMENTATION_COVERAGE_V1_4_4.yaml`

The owner updates this document whenever public API, dependency edges, persistent formats, security invariants, retry behavior, tests or known gaps change.
