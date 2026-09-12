# heptabao-telemetry

Current source binding: [docs/modules/CURRENT_SOURCE_BINDING.md](CURRENT_SOURCE_BINDING.md). Runtime integration: [docs/modules/CURRENT_RUNTIME_MAP.md](CURRENT_RUNTIME_MAP.md).

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns size-bounded event identifiers and an allowlist of label keys. Event-count and value-cardinality budgets belong to the caller. It does not export metrics, traces or logs to a production collector and does not replace audit records.

## Public API and ownership

### Current API contract and integration boundary

`TelemetryEvent::new(name, BTreeMap<Id, Id>)` owns a bounded event name and label map. It accepts only label keys `backend`, `kind`, `operation`, `outcome`, `state`, and `generation_bucket`, returning `ForbiddenLabel` otherwise. This constrains the key vocabulary; label values and event names remain arbitrary valid `Id` values, not enumerated low-cardinality values. Applications must enforce value vocabularies and must not place secrets in allowed keys.

`MemoryTelemetry::record(event)` appends an owned event and returns no error; `events()` lends the complete slice. The underlying vector has no capacity, eviction or backpressure limit. Event construction bounds individual identifiers, not total event count or distinct-value cardinality. The owner must select an external retention/export strategy before using this pattern in a long-running service.

This sink is used by the independent `heptabao-service-core` and is outside the current server dependency closure. It is not the server's Prometheus implementation or a persistent security audit device. A production exporter must define synchronization, overflow policy, delivery errors and ordering without changing a request's commit outcome.

### Historical V1.4.7 lexical snapshot

The following generated block is retained unchanged for historical verification. Its declarations and line numbers are not the current API contract; use the explanation above and the [current source binding](CURRENT_SOURCE_BINDING.md).

<!-- BEGIN GENERATED V1.4.7 PUBLIC API TRUTH; DO NOT EDIT -->
Source-bound lexical inventory: `crates/heptabao-telemetry`; Cargo SHA-256 `31cead0bd3fecb51d5afdc9c463e88a6fef6fab9c18026719b5b09e1a162841d`.

| Kind | Name | Source | Declaration |
|---|---|---|---|
| `struct` | `TelemetryEvent` | `crates/heptabao-telemetry/src/lib.rs:22` | `pub struct TelemetryEvent {` |
| `fn` | `new` | `crates/heptabao-telemetry/src/lib.rs:28` | `pub fn new(name: Id, labels: BTreeMap<Id, Id>) -> Result<Self, TelemetryError> {` |
| `fn` | `name` | `crates/heptabao-telemetry/src/lib.rs:37` | `pub fn name(&self) -> &Id {` |
| `fn` | `labels` | `crates/heptabao-telemetry/src/lib.rs:41` | `pub fn labels(&self) -> &BTreeMap<Id, Id> {` |
| `struct` | `MemoryTelemetry` | `crates/heptabao-telemetry/src/lib.rs:47` | `pub struct MemoryTelemetry {` |
| `fn` | `record` | `crates/heptabao-telemetry/src/lib.rs:52` | `pub fn record(&mut self, event: TelemetryEvent) {` |
| `fn` | `events` | `crates/heptabao-telemetry/src/lib.rs:56` | `pub fn events(&self) -> &[TelemetryEvent] {` |
| `enum` | `TelemetryError` | `crates/heptabao-telemetry/src/lib.rs:62` | `pub enum TelemetryError {` |

This table is generated from the exact candidate source. It is a bounded lexical inventory, not a stability or compatibility promise.
<!-- END GENERATED V1.4.7 PUBLIC API TRUTH -->

## State and data model

Events are append-only within the memory sink. Label keys are restricted to backend, kind, operation, outcome, state and generation bucket.

## Invariants and authorization

A label outside the allowlist is rejected before recording. Telemetry construction never grants authority and cannot alter a service result.

## Failure, retry and reconciliation

Validation failure occurs before the event enters a sink. Production exporters must preserve service commit classification and may not relabel a committed write as uncommitted because export failed.

## Concurrency and ordering

The memory sink has no interior synchronization. Its owning composition root records events in request order after classification.

## Security and privacy

Label keys outside the six-name allowlist are rejected. Values remain bounded identifiers, but their content and cardinality are not checked: an allowed key can still carry a sensitive or highly variable value if the caller supplies one.

## Persistence and compatibility

No persisted telemetry format is owned. Event names and label meanings are compatibility surfaces and require additive versioned evolution.

## Observability

The package is itself the observability contract. Current service events use `request_completed` with operation and outcome labels.

## Operations

Production deployment needs exporters, backpressure, sampling, retention and SLO alerts. None is implied by the memory sink.

## Tests and executable evidence

Current executable anchors (source assertions, not a claim that tests were rerun for this documentation edit):

- [`tests::sensitive_or_high_cardinality_labels_are_rejected`](../../crates/heptabao-telemetry/src/lib.rs) checks the forbidden token key; it does not reject sensitive/high-cardinality values under allowed keys.
- [`tests::approved_labels_are_recorded_without_payloads`](../../crates/heptabao-telemetry/src/lib.rs) checks a valid event appends to the memory sink.

`cargo test -p heptabao-telemetry` proves forbidden-label rejection and accepted event recording. V2 CI compiles and documents the public API.

## Evolution and open boundaries

Metrics exporters, trace propagation, cardinality budgets and audit correlation remain open adapters with their own qualification requirements.

## Machine-verified source truth

The V1.4.7 generated facts below are a preserved historical snapshot. Current dependency/integration statements are given above; historic declaration/test counts are not a current completion measure.

<!-- BEGIN GENERATED V1.4.7 MODULE FACTS; DO NOT EDIT -->
- Crate: `heptabao-telemetry`
- Crate path: `crates/heptabao-telemetry`
- Cargo manifest SHA-256: `31cead0bd3fecb51d5afdc9c463e88a6fef6fab9c18026719b5b09e1a162841d`
- Rust source files: `1`
- Public lexical declarations: `8`
- Discovered test functions: `2`
- Workspace-internal dependencies: `heptabao-domain` (dependencies)
- Authoritative inventory: `planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml`
- Regeneration: `python scripts/render_plan_v1_4_7.py --write`
- Verification: `python scripts/render_plan_v1_4_7.py --check`
<!-- END GENERATED V1.4.7 MODULE FACTS -->
