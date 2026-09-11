# heptabao-client-contracts

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns client-side failure and retry classification. It does not perform HTTP, TLS, authentication, backoff scheduling or service discovery.

## Public API and ownership

<!-- BEGIN GENERATED V1.4.7 PUBLIC API TRUTH; DO NOT EDIT -->
Source-bound lexical inventory: `crates/heptabao-client-contracts`; Cargo SHA-256 `3cb2674bb8da7d545ab93e3009c3e91c330a25e35cb88a4a1140fca6a0b81bad`.

| Kind | Name | Source | Declaration |
|---|---|---|---|
| `enum` | `OperationClass` | `crates/heptabao-client-contracts/src/lib.rs:9` | `pub enum OperationClass {` |
| `enum` | `FailureClass` | `crates/heptabao-client-contracts/src/lib.rs:16` | `pub enum FailureClass {` |
| `enum` | `RetryDecision` | `crates/heptabao-client-contracts/src/lib.rs:24` | `pub enum RetryDecision {` |
| `struct` | `ClientAttempt` | `crates/heptabao-client-contracts/src/lib.rs:31` | `pub struct ClientAttempt {` |
| `fn` | `decision` | `crates/heptabao-client-contracts/src/lib.rs:38` | `pub fn decision(&self, failure: FailureClass) -> RetryDecision {` |
| `fn` | `next_with_new_id` | `crates/heptabao-client-contracts/src/lib.rs:48` | `pub fn next_with_new_id(&self, request_id: Id) -> Self {` |

This table is generated from the exact candidate source. It is a bounded lexical inventory, not a stability or compatibility promise.
<!-- END GENERATED V1.4.7 PUBLIC API TRUTH -->

## State and data model

Attempts are immutable values. A retry creates a new value with a new request identifier and incremented attempt count.

## Invariants and authorization

Unknown-after-entry always maps to authoritative readback, never automatic retry. Committed and deterministic rejection outcomes map to do-not-retry.

## Failure, retry and reconciliation

Before-entry failure allows a new request. The original identifier is not reused. Nonidempotent operations receive no special bypass.

## Concurrency and ordering

The contract is stateless. A client runtime owns scheduling and must preserve ordering when one operation depends on another.

## Security and privacy

No credentials or bodies are stored. Request identifiers are bounded nonsecret correlation values.

## Persistence and compatibility

No persisted or wire format is owned. Transport adapters must map server outcomes without collapsing unknown-after-entry into generic timeout.

## Observability

Clients may record operation class, failure class and retry decision. Tokens, request bodies and full secret paths are forbidden labels.

## Operations

Operators can use the decision model to distinguish retry, stop and readback. Application code must not override readback-required outcomes.

## Tests and executable evidence

`cargo test -p heptabao-client-contracts` proves uncertainty preservation and new-identifier retry behavior.

## Evolution and open boundaries

Backoff, circuit breaking, redirects, leader discovery and transport implementations remain open.

## Machine-verified source truth

<!-- BEGIN GENERATED V1.4.7 MODULE FACTS; DO NOT EDIT -->
- Crate: `heptabao-client-contracts`
- Crate path: `crates/heptabao-client-contracts`
- Cargo manifest SHA-256: `3cb2674bb8da7d545ab93e3009c3e91c330a25e35cb88a4a1140fca6a0b81bad`
- Rust source files: `1`
- Public lexical declarations: `6`
- Discovered test functions: `2`
- Workspace-internal dependencies: `heptabao-domain` (dependencies)
- Authoritative inventory: `planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml`
- Regeneration: `python scripts/render_plan_v1_4_7.py --write`
- Verification: `python scripts/render_plan_v1_4_7.py --check`
<!-- END GENERATED V1.4.7 MODULE FACTS -->
