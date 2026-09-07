# heptabao-lease

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns lease issue, renewal, expiration and revocation state for secret and authentication leases. It does not execute backend revocation callbacks, persist leases or schedule background expiration.

## Public API and ownership

`LeaseIssue` is the single auditable command object for identifier, owner, scope, kind, issue tick, TTL and renewable flag. `LeaseStore` owns records keyed by bounded identifiers, while `LeaseView` exposes the accepted state and generation.

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

`cargo test -p heptabao-lease` covers command-object issue, renewal, revocation, expiration and segment-safe prefix revocation. The current CI compiles all targets, rejects excessive function arguments through strict Clippy and builds documentation.

## Evolution and open boundaries

Revocation callbacks, lease parentage, quotas, tidy operations, durable scheduling and disaster-recovery replay remain open until integrated with the operation ledger.
