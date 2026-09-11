# heptabao-token

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns opaque token issue, validation, renewal and revocation state. It does not generate entropy, hash bearer material, persist tokens, create child-token trees or provide network authentication.

## Public API and ownership

<!-- BEGIN GENERATED V1.4.7 PUBLIC API TRUTH; DO NOT EDIT -->
Source-bound lexical inventory: `crates/heptabao-token`; Cargo SHA-256 `1e3ce2af36291d20f00c54855df8c2f38baa662ad2f29efb1e2ab130c445ade5`.

| Kind | Name | Source | Declaration |
|---|---|---|---|
| `struct` | `TokenId` | `crates/heptabao-token/src/lib.rs:13` | `pub struct TokenId(Id);` |
| `fn` | `parse` | `crates/heptabao-token/src/lib.rs:16` | `pub fn parse(value: impl Into<String>) -> Result<Self, DomainError> {` |
| `struct` | `TokenView` | `crates/heptabao-token/src/lib.rs:28` | `pub struct TokenView {` |
| `struct` | `TokenStore` | `crates/heptabao-token/src/lib.rs:62` | `pub struct TokenStore {` |
| `fn` | `issue` | `crates/heptabao-token/src/lib.rs:67` | `pub fn issue(` |
| `fn` | `validate` | `crates/heptabao-token/src/lib.rs:99` | `pub fn validate(&self, token_id: &TokenId, now: Tick) -> Result<TokenView, TokenError> {` |
| `fn` | `renew` | `crates/heptabao-token/src/lib.rs:110` | `pub fn renew(` |
| `fn` | `revoke` | `crates/heptabao-token/src/lib.rs:137` | `pub fn revoke(&mut self, token_id: &TokenId, now: Tick) -> Result<(), TokenError> {` |
| `fn` | `revoke_entity` | `crates/heptabao-token/src/lib.rs:150` | `pub fn revoke_entity(&mut self, entity_id: &Id, now: Tick) -> usize {` |
| `enum` | `TokenError` | `crates/heptabao-token/src/lib.rs:164` | `pub enum TokenError {` |

This table is generated from the exact candidate source. It is a bounded lexical inventory, not a stability or compatibility promise.
<!-- END GENERATED V1.4.7 PUBLIC API TRUTH -->

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

## Machine-verified source truth

<!-- BEGIN GENERATED V1.4.7 MODULE FACTS; DO NOT EDIT -->
- Crate: `heptabao-token`
- Crate path: `crates/heptabao-token`
- Cargo manifest SHA-256: `1e3ce2af36291d20f00c54855df8c2f38baa662ad2f29efb1e2ab130c445ade5`
- Rust source files: `1`
- Public lexical declarations: `10`
- Discovered test functions: `2`
- Workspace-internal dependencies: `heptabao-domain` (dependencies)
- Authoritative inventory: `planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml`
- Regeneration: `python scripts/render_plan_v1_4_7.py --write`
- Verification: `python scripts/render_plan_v1_4_7.py --check`
<!-- END GENERATED V1.4.7 MODULE FACTS -->
