# heptabao-client-contracts

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns client-side failure and retry classification. It does not perform HTTP, TLS, authentication, backoff scheduling or service discovery.

## Public API and ownership

`ClientAttempt` binds a request identifier, operation class and attempt count. `FailureClass` maps to an explicit `RetryDecision`.

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
