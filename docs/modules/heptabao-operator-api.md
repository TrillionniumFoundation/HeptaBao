# heptabao-operator-api

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns operator-facing commit classification and reconciliation records. It does not perform authoritative storage readback, authenticate operators or compensate external systems by itself.

## Public API and ownership

`OutcomeRecord` owns the external request identity, effect phase, commit state, optional recovery reference and optional resolution. `ReconciliationStore` indexes unknown-after-entry records by recovery reference and records without a recovery reference by request identifier, preventing two principals that reused one external request ID from colliding when their recovery references differ.

## State and data model

Records are created as before-entry, committed or unknown-after-entry. Unknown records preserve both the original request identifier and the independently generated recovery reference. Resolution is a one-way transition to confirmed committed, confirmed not committed or compensated.

## Invariants and authorization

Unknown-after-entry records always carry a recovery reference and classify to authoritative readback. Recovery references are unique lookup keys within a store. Resolved or committed records classify to do-not-retry. This package does not authorize access; a service boundary must restrict record and resolution operations to trusted operators.

## Failure, retry and reconciliation

Before-entry not-committed permits a new attempt. Unknown after entry forbids blind retry. Duplicate lookup keys and repeated resolution are rejected deterministically. Distinct recovery references may safely represent the same caller-provided request ID, preserving cross-principal reconciliation separation.

## Concurrency and ordering

The store has no interior synchronization. A service root generates a recovery reference, records the unknown outcome and retains its exact request binding before returning the reference. A concurrent implementation must make record publication and response delivery ordering explicit.

## Security and privacy

Recovery references are bounded opaque identifiers. Records contain no request body, token or secret value. Implementations must not derive recovery references directly from secret-bearing input and must keep them out of high-cardinality telemetry labels.

## Persistence and compatibility

No durable encoding exists. Production persistence must atomically bind external request identity, recovery reference, commit phase and resolution and support restart-before-serve replay. Lookup-by-recovery-reference is part of the V2 semantic contract.

## Observability

Recommended events are `operation.outcome_unknown`, `operation.readback_completed` and `operation.compensated`, without secret or raw identifier labels. Duplicate-reference rejection should be separately counted.

## Operations

Operators query a recovery reference, perform authoritative readback and then record a resolution. The service composition is responsible for releasing the corresponding non-evictable request binding only after resolution succeeds.

## Tests and executable evidence

`cargo test -p heptabao-operator-api` proves retry classification, one-way resolution and `distinct_recovery_references_disambiguate_the_same_external_request_id`. Service integration tests exercise unknown recording, cross-principal recovery separation and resolution.

## Evolution and open boundaries

Durable queues, role-based operator authorization, evidence attachment, expiry policies and compensation adapters remain open. External request IDs must never replace unique recovery references as the sole key for ambiguous effects.
