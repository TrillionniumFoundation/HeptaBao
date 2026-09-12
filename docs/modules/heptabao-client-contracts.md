# heptabao-client-contracts

Current source binding: [docs/modules/CURRENT_SOURCE_BINDING.md](CURRENT_SOURCE_BINDING.md). Runtime integration: [docs/modules/CURRENT_RUNTIME_MAP.md](CURRENT_RUNTIME_MAP.md).

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns client-side failure and retry classification. It does not perform HTTP, TLS, authentication, backoff scheduling or service discovery.

## Public API and ownership

### Current API contract and integration boundary

`ClientAttempt` is a public value containing `request_id`, `OperationClass` and a numeric attempt counter. `decision(FailureClass)` is pure: `BeforeEntry` permits a new request, `DeterministicRejection` and `Committed` prohibit retry, and `UnknownAfterEntry` requires authoritative readback. The current match does not vary by `OperationClass`; even a declared read-only or idempotent operation receives no uncertainty bypass.

`next_with_new_id(request_id)` returns a copied attempt with a saturating increment of `attempt`. Its name expresses caller intent: the implementation neither generates an identifier nor checks that the supplied identifier differs from the old one. Callers must enforce uniqueness and their own attempt limit; saturation at `u32::MAX` is not an error. Both methods are infallible and have no I/O or mutable shared state.

A transport adapter must establish whether the request actually entered the effect boundary before constructing `FailureClass`; a timeout alone cannot prove `BeforeEntry`. It must also implement readback, backoff and cancellation. This crate is outside the current `heptabao-server` dependency closure and supplies no HTTP client or exported SDK.

### Historical V1.4.7 lexical snapshot

The following generated block is retained unchanged for historical verification. Its declarations and line numbers are not the current API contract; use the explanation above and the [current source binding](CURRENT_SOURCE_BINDING.md).

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

Attempts are immutable values. A retry creates a new value with a caller-supplied request identifier and saturating-incremented attempt count; callers must ensure the identifier is fresh.

## Invariants and authorization

Unknown-after-entry always maps to authoritative readback, never automatic retry. Committed and deterministic rejection outcomes map to do-not-retry.

## Failure, retry and reconciliation

Before-entry failure allows a new request. The client adapter must not reuse the original identifier. Nonidempotent operations receive no special bypass.

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

Current executable anchors (source assertions, not a claim that tests were rerun for this documentation edit):

- [`tests::unknown_after_entry_never_becomes_automatic_retry`](../../crates/heptabao-client-contracts/src/lib.rs) checks the nonidempotent uncertainty decision.
- [`tests::retry_uses_a_new_request_identifier`](../../crates/heptabao-client-contracts/src/lib.rs) demonstrates caller-supplied distinct IDs and counter increment; it does not test rejection of reused IDs.

`cargo test -p heptabao-client-contracts` proves uncertainty preservation and new-identifier retry behavior.

## Evolution and open boundaries

Backoff, circuit breaking, redirects, leader discovery and transport implementations remain open.

## Machine-verified source truth

The V1.4.7 generated facts below are a preserved historical snapshot. Current dependency/integration statements are given above; historic declaration/test counts are not a current completion measure.

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
