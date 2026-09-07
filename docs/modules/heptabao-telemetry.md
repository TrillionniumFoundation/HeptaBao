# heptabao-telemetry

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns bounded telemetry events and a low-cardinality label allowlist. It does not export metrics, traces or logs to a production collector and does not replace audit records.

## Public API and ownership

`TelemetryEvent` owns a bounded event identifier and validated label map. `MemoryTelemetry` owns an ordered in-memory event sequence used by the service candidate and tests.

## State and data model

Events are append-only within the memory sink. Label keys are restricted to backend, kind, operation, outcome, state and generation bucket.

## Invariants and authorization

A label outside the allowlist is rejected before recording. Telemetry construction never grants authority and cannot alter a service result.

## Failure, retry and reconciliation

Validation failure occurs before the event enters a sink. Production exporters must preserve service commit classification and may not relabel a committed write as uncommitted because export failed.

## Concurrency and ordering

The memory sink has no interior synchronization. Its owning composition root records events in request order after classification.

## Security and privacy

Token, secret, key, unseal, credential, body and arbitrary path labels are structurally impossible through the current allowlist. Values remain bounded identifiers rather than free text.

## Persistence and compatibility

No persisted telemetry format is owned. Event names and label meanings are compatibility surfaces and require additive versioned evolution.

## Observability

The package is itself the observability contract. Current service events use `request_completed` with operation and outcome labels.

## Operations

Production deployment needs exporters, backpressure, sampling, retention and SLO alerts. None is implied by the memory sink.

## Tests and executable evidence

`cargo test -p heptabao-telemetry` proves forbidden-label rejection and accepted event recording. V2 CI compiles and documents the public API.

## Evolution and open boundaries

Metrics exporters, trace propagation, cardinality budgets and audit correlation remain open adapters with their own qualification requirements.
