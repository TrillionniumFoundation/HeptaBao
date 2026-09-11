# heptabao-telemetry

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns bounded telemetry events and a low-cardinality label allowlist. It does not export metrics, traces or logs to a production collector and does not replace audit records.

## Public API and ownership

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

## Machine-verified source truth

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
