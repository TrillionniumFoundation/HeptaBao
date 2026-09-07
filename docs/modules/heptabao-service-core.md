# heptabao-service-core

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package is the mandatory V2 request composition root. It joins token validation, identity policy expansion, default-deny authorization, namespace qualification, mount routing, KV dispatch, telemetry and reconciliation. It is a single-process candidate, not a TLS server or durable production service.

## Public API and ownership

`ServiceCore` owns all in-memory control/data-plane stores and a `PostCommitHook`. `ServiceRequest` owns request identity, bearer token identifier, namespace, path and operation. `ServiceResponse` preserves completed versus unknown-after-entry outcomes.

## State and data model

Every request identifier is admitted once. Writes create KV versions; successful commits pass through a post-commit confirmation boundary. Failure there records an unknown outcome using the request identifier as recovery reference.

## Invariants and authorization

Token validation and identity expansion precede policy evaluation; default deny precedes namespace and backend dispatch. Namespace and mount identifiers are embedded in engine keys, preventing cross-namespace collisions.

## Failure, retry and reconciliation

Validation, authentication, authorization, namespace and route failures occur before engine entry. A post-commit failure returns `OutcomeUnknownAfterEntry`; the same request identifier is rejected on replay and operator readback is required.

## Concurrency and ordering

The current service is mutably owned and serial. It does not hold locks across hooks because it has no internal locks. A future concurrent server must preserve this logical order and request-id admission point.

## Security and privacy

Secret values use redacted buffers. Token identifiers are redacted. Telemetry is prepared before mutation and accepts only bounded labels. The service still lacks encryption, TLS, locked memory and durable token/policy state.

## Persistence and compatibility

All new control-plane and KV state is in memory. Durable composition must map the same outcome taxonomy onto journal, barrier, storage and operation-ledger providers without changing retry meaning.

## Observability

Completed and unknown outcomes emit `request_completed` with operation and outcome labels. Unknown outcomes also create a reconciliation record retrievable by recovery reference.

## Operations

Administrators currently configure stores through explicit mutable accessors for tests and composition. Production requires authenticated administrative endpoints, bootstrap ceremonies, backups and restart recovery.

## Tests and executable evidence

`cargo test -p heptabao-service-core` exercises accepted write/read, default denial, token revocation, namespace isolation and an injected post-commit failure that commits once and rejects replay.

## Evolution and open boundaries

Durable storage/journal integration, lease issuance, plugin execution, TLS transport, HA fencing and compatibility routing remain subsequent V2 work.
