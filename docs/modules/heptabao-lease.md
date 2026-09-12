# heptabao-lease

Current source binding: [docs/modules/CURRENT_SOURCE_BINDING.md](CURRENT_SOURCE_BINDING.md). Runtime integration: [docs/modules/CURRENT_RUNTIME_MAP.md](CURRENT_RUNTIME_MAP.md).

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns lease issue, renewal, expiration and revocation state for secret and authentication leases. It does not execute backend revocation callbacks, persist leases or schedule background expiration.

## Public API and ownership

### Current API contract and integration boundary

`LeaseStore::issue(LeaseIssue)` owns lease ID, owner entity, scope, kind, timestamps, renewable flag and generation. The command requires a unique ID and nonzero TTL whose addition to `issued_at` fits in `Tick`; overflow maps to `InvalidTtl`. Issuance returns an owned `LeaseView` and does not generate or provision a secret in an external backend.

`validate(&mut self, id, now)` is mutating: it lazily marks an active lease expired at `now >= expires_at`, advances generation and returns `Expired`. `renew(id, now, ttl)` requires a live renewable lease and sets its deadline to `now + ttl`; it can shorten the old deadline, has no maximum-TTL policy and has no external provider callback. Its expired branch marks state without the same generation increment as `validate`. The caller must supply monotonic time and any stricter deadline/generation policy.

`revoke(id)` and `revoke_prefix(prefix)` mark only currently Active records and do not accept time; prefix matching respects path segments. They do not run revocation SQL, revoke a provider credential, cascade from a token, or schedule expiry. An adapter must coordinate those side effects and durably retain unknown outcomes before reporting revocation complete.

This standalone memory lifecycle is outside the current server dependency closure and is not a dynamic-secrets lease manager in the running server. Deployment needs a real issuance/revocation adapter, scheduler and restart-safe store before the model can support operational lease guarantees.

### Historical V1.4.7 lexical snapshot

The following generated block is retained unchanged for historical verification. Its declarations and line numbers are not the current API contract; use the explanation above and the [current source binding](CURRENT_SOURCE_BINDING.md).

<!-- BEGIN GENERATED V1.4.7 PUBLIC API TRUTH; DO NOT EDIT -->
Source-bound lexical inventory: `crates/heptabao-lease`; Cargo SHA-256 `23320b5bc43b0658b19373e2fa290f867791b0ec13219341f1a24f777ba369a5`.

| Kind | Name | Source | Declaration |
|---|---|---|---|
| `enum` | `LeaseKind` | `crates/heptabao-lease/src/lib.rs:13` | `pub enum LeaseKind {` |
| `enum` | `LeaseState` | `crates/heptabao-lease/src/lib.rs:19` | `pub enum LeaseState {` |
| `struct` | `LeaseIssue` | `crates/heptabao-lease/src/lib.rs:26` | `pub struct LeaseIssue {` |
| `struct` | `LeaseView` | `crates/heptabao-lease/src/lib.rs:37` | `pub struct LeaseView {` |
| `struct` | `LeaseStore` | `crates/heptabao-lease/src/lib.rs:79` | `pub struct LeaseStore {` |
| `fn` | `issue` | `crates/heptabao-lease/src/lib.rs:84` | `pub fn issue(&mut self, command: LeaseIssue) -> Result<LeaseView, LeaseError> {` |
| `fn` | `validate` | `crates/heptabao-lease/src/lib.rs:111` | `pub fn validate(&mut self, id: &Id, now: Tick) -> Result<LeaseView, LeaseError> {` |
| `fn` | `renew` | `crates/heptabao-lease/src/lib.rs:124` | `pub fn renew(&mut self, id: &Id, now: Tick, ttl: u64) -> Result<LeaseView, LeaseError> {` |
| `fn` | `revoke` | `crates/heptabao-lease/src/lib.rs:144` | `pub fn revoke(&mut self, id: &Id) -> Result<(), LeaseError> {` |
| `fn` | `revoke_prefix` | `crates/heptabao-lease/src/lib.rs:158` | `pub fn revoke_prefix(&mut self, prefix: &CanonicalPath) -> usize {` |
| `enum` | `LeaseError` | `crates/heptabao-lease/src/lib.rs:172` | `pub enum LeaseError {` |

This table is generated from the exact candidate source. It is a bounded lexical inventory, not a stability or compatibility promise.
<!-- END GENERATED V1.4.7 PUBLIC API TRUTH -->

## State and data model

Lease state moves monotonically from active to revoked or expired. Renewal is allowed only while active and renewable. Prefix revocation uses canonical segment boundaries.

## Invariants and authorization

Zero TTL and duplicate identifiers are rejected. Revoked and expired leases cannot return to active. Lease validity does not itself authorize a request.

## Failure, retry and reconciliation

Current transitions are deterministic and in-memory. A production backend revocation callback may have an unknown-after-entry result and must be paired with an operation ledger before retries.

## Concurrency and ordering

The store has no internal lock. A scheduler or service root serializes mutation and supplies one monotonic tick for each decision.

## Security and privacy

Lease records contain identifiers and canonical scopes but no secret payload. Telemetry must avoid high-cardinality secret paths and must never include token or credential material.

## Persistence and compatibility

No persisted lease schema or revocation queue exists. Future persistence must version state, generation, callback identity and retry classification.

## Observability

Recommended events are `lease.issued`, `lease.renewed`, `lease.expired` and `lease.revoked`, with kind and bounded outcome labels only.

## Operations

Operators can revoke one lease or a canonical prefix. Production operation still requires a durable expiration queue, backpressure, callback reconciliation and emergency mass revocation.

## Tests and executable evidence

Current executable anchors (source assertions, not a claim that tests were rerun for this documentation edit):

- [`tests::lease_lifecycle_is_monotonic`](../../crates/heptabao-lease/src/lib.rs) checks the demonstrated issue/renew/revoke path and subsequent revoked rejection.
- [`tests::prefix_revocation_respects_path_boundaries`](../../crates/heptabao-lease/src/lib.rs) checks /secret/app revocation leaves /secret/application outside the scope.

`cargo test -p heptabao-lease` covers command-object issue, renewal, revocation, expiration and segment-safe prefix revocation. The current CI compiles all targets, rejects excessive function arguments through strict Clippy and builds documentation.

## Evolution and open boundaries

Revocation callbacks, lease parentage, quotas, tidy operations, durable scheduling and disaster-recovery replay remain open until integrated with the operation ledger.

## Machine-verified source truth

The V1.4.7 generated facts below are a preserved historical snapshot. Current dependency/integration statements are given above; historic declaration/test counts are not a current completion measure.

<!-- BEGIN GENERATED V1.4.7 MODULE FACTS; DO NOT EDIT -->
- Crate: `heptabao-lease`
- Crate path: `crates/heptabao-lease`
- Cargo manifest SHA-256: `23320b5bc43b0658b19373e2fa290f867791b0ec13219341f1a24f777ba369a5`
- Rust source files: `1`
- Public lexical declarations: `11`
- Discovered test functions: `2`
- Workspace-internal dependencies: `heptabao-domain` (dependencies)
- Authoritative inventory: `planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml`
- Regeneration: `python scripts/render_plan_v1_4_7.py --write`
- Verification: `python scripts/render_plan_v1_4_7.py --check`
<!-- END GENERATED V1.4.7 MODULE FACTS -->
