# heptabao-operator-api

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns operator-facing commit classification and reconciliation records. It does not perform authoritative storage readback, authenticate operators or compensate external systems by itself.

## Public API and ownership

<!-- BEGIN GENERATED V1.4.7 PUBLIC API TRUTH; DO NOT EDIT -->
Source-bound lexical inventory: `crates/heptabao-operator-api`; Cargo SHA-256 `98574a3c782be1c8e837b7997d0e1f1356b661a4a041ac34bd1f737581366b15`.

| Kind | Name | Source | Declaration |
|---|---|---|---|
| `enum` | `EffectPhase` | `crates/heptabao-operator-api/src/lib.rs:13` | `pub enum EffectPhase {` |
| `enum` | `CommitState` | `crates/heptabao-operator-api/src/lib.rs:19` | `pub enum CommitState {` |
| `enum` | `OperatorAction` | `crates/heptabao-operator-api/src/lib.rs:26` | `pub enum OperatorAction {` |
| `enum` | `Resolution` | `crates/heptabao-operator-api/src/lib.rs:34` | `pub enum Resolution {` |
| `struct` | `OutcomeRecord` | `crates/heptabao-operator-api/src/lib.rs:41` | `pub struct OutcomeRecord {` |
| `fn` | `before_entry` | `crates/heptabao-operator-api/src/lib.rs:50` | `pub fn before_entry(request_id: Id) -> Self {` |
| `fn` | `committed` | `crates/heptabao-operator-api/src/lib.rs:60` | `pub fn committed(request_id: Id) -> Self {` |
| `fn` | `unknown_after_entry` | `crates/heptabao-operator-api/src/lib.rs:70` | `pub fn unknown_after_entry(request_id: Id, recovery_reference: Id) -> Self {` |
| `fn` | `action` | `crates/heptabao-operator-api/src/lib.rs:80` | `pub fn action(&self) -> OperatorAction {` |
| `struct` | `ReconciliationStore` | `crates/heptabao-operator-api/src/lib.rs:96` | `pub struct ReconciliationStore {` |
| `fn` | `record` | `crates/heptabao-operator-api/src/lib.rs:101` | `pub fn record(&mut self, record: OutcomeRecord) -> Result<(), OperatorError> {` |
| `fn` | `get` | `crates/heptabao-operator-api/src/lib.rs:114` | `pub fn get(&self, reference: &Id) -> Result<&OutcomeRecord, OperatorError> {` |
| `fn` | `resolve` | `crates/heptabao-operator-api/src/lib.rs:120` | `pub fn resolve(&mut self, reference: &Id, resolution: Resolution) -> Result<(), OperatorError> {` |
| `enum` | `OperatorError` | `crates/heptabao-operator-api/src/lib.rs:134` | `pub enum OperatorError {` |

This table is generated from the exact candidate source. It is a bounded lexical inventory, not a stability or compatibility promise.
<!-- END GENERATED V1.4.7 PUBLIC API TRUTH -->

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

## Machine-verified source truth

<!-- BEGIN GENERATED V1.4.7 MODULE FACTS; DO NOT EDIT -->
- Crate: `heptabao-operator-api`
- Crate path: `crates/heptabao-operator-api`
- Cargo manifest SHA-256: `98574a3c782be1c8e837b7997d0e1f1356b661a4a041ac34bd1f737581366b15`
- Rust source files: `1`
- Public lexical declarations: `14`
- Discovered test functions: `3`
- Workspace-internal dependencies: `heptabao-domain` (dependencies)
- Authoritative inventory: `planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml`
- Regeneration: `python scripts/render_plan_v1_4_7.py --write`
- Verification: `python scripts/render_plan_v1_4_7.py --check`
<!-- END GENERATED V1.4.7 MODULE FACTS -->
