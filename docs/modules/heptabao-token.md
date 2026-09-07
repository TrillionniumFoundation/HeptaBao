# heptabao-token

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns opaque token issue, validation, renewal and revocation state. It does not generate entropy, hash bearer material, persist tokens, create child-token trees or provide network authentication.

## Public API and ownership

`TokenStore` owns token records. `TokenId` is redacted in debug output. `TokenView` exposes only authorization-relevant entity, policy, lifetime and generation metadata.

## State and data model

A token is active until expiration or explicit revocation. Renewal requires an active renewable token and advances the generation. Entity-wide revocation monotonically marks every active token.

## Invariants and authorization

Zero TTL, duplicate identifiers, expired tokens and revoked tokens are rejected. Validation returns policy identifiers but never grants access without subsequent identity and policy evaluation.

## Failure, retry and reconciliation

Issue failures occur before insertion. Renewal and revocation are deterministic in the in-memory store. The package has no after-entry unknown state; a durable adapter must add generation and reconciliation semantics.

## Concurrency and ordering

The store has no interior synchronization. The composition root serializes mutations and validates against one monotonic tick supplied by its trusted clock boundary.

## Security and privacy

Token identifiers are treated as bearer material and redacted from `Debug`. The candidate does not claim constant-time lookup, cryptographic generation, secure hashing or locked memory.

## Persistence and compatibility

No token persistence format exists. A production format must protect bearer material, version lifecycle fields and support revocation replay before serving requests.

## Observability

Token issue, renewal, expiration and revocation should emit bounded identifiers such as `token.issued` and `token.revoked`; token values must never be labels or error text.

## Operations

Entity compromise can be contained with `revoke_entity`. Production operation still requires root-token ceremonies, accessor-based administration, periodic tokens and revocation-tree processing.

## Tests and executable evidence

`cargo test -p heptabao-token` covers issue, renewal, expiration/revocation rejection and debug redaction. Strict workspace Clippy rejects panic, unwrap and expect use.

## Evolution and open boundaries

Child tokens, orphan tokens, periodic renewal, batch tokens, cubbyholes, accessors and durable revocation indexes remain open product work.
