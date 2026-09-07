# heptabao-operator-api

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns operator-facing commit classification and reconciliation records. It does not perform authoritative storage readback or compensate external systems by itself.

## Public API and ownership

`OutcomeRecord` owns request phase, commit state, recovery reference and optional resolution. `ReconciliationStore` owns unique records keyed by request identifier.

## State and data model

Records are created as before-entry, committed or unknown-after-entry. Resolution is a one-way transition to confirmed committed, confirmed not committed or compensated.

## Invariants and authorization

Unknown-after-entry records always carry a recovery reference and classify to authoritative readback. Resolved or committed records classify to do-not-retry.

## Failure, retry and reconciliation

Before-entry not-committed permits a new attempt. Unknown after entry forbids blind retry. Duplicate records and repeated resolution are rejected deterministically.

## Concurrency and ordering

The store has no interior synchronization. A service root records an unknown outcome before returning its recovery reference to the caller.

## Security and privacy

Recovery references are bounded opaque identifiers. Records contain no request body, token or secret value.

## Persistence and compatibility

No durable encoding exists. Production persistence must atomically bind request identity, commit phase and resolution and support restart-before-serve replay.

## Observability

Recommended events are `operation.outcome_unknown`, `operation.readback_completed` and `operation.compensated`, without secret labels.

## Operations

Operators query a recovery reference, perform authoritative readback and then record a resolution. The runbook defines when escalation is required.

## Tests and executable evidence

`cargo test -p heptabao-operator-api` proves retry classification and one-way resolution. Service integration tests exercise unknown-after-entry recording.

## Evolution and open boundaries

Durable queues, role-based operator authorization, evidence attachment and compensation adapters remain open.
