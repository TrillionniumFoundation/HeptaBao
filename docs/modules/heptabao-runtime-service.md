# heptabao-runtime-service

Current plan: `HEPTABAO-PLAN-2026-09-07-V2.1`. Shared rules live in `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This crate is the mandatory admission adapter from inbound mutation/read/list requests to the private durable service. It authenticates, authorizes, records accepted-before-entry audit evidence, constructs the immutable durable envelope and classifies the result. It does not implement a network listener, credential protocol, persistent identity database, production audit provider or KMS/HSM.

## Public API and ownership

`RuntimeService<A,Z,U,B>` privately owns the authenticator, authorizer, audit sink and `DurableService<B>` and exposes no durable-writer accessor. `InboundMutation` carries only an opaque credential and caller request fields; callers cannot supply `AuthenticatedPrincipal` or `AuthorizationDigest`. `read(&Credential, namespace, resource, request_id)` returns an optional secret and `list(&Credential, namespace, prefix, request_id)` returns immediate child names. Both authenticate and authorize with distinct `OperationKind::Read`/`List`, then require pre-dispatch and result audit. `RuntimeOutcome` and `RuntimeError` are bounded result classes. `recovery_required` exposes the durable stop condition. `reconcile` is a trusted internal read-only lookup; a network assembly must gate it with its own operator authorization.

## State and data model

The adapter itself has no separate persisted database. It derives one request fingerprint and one authorization digest from authenticated, canonical inputs, then transfers principal, namespace, request ID, resource, operation and value into the durable envelope. Audit events carry only stage, fingerprint and optional generation. `AuditEvent::request_fingerprint()` returns the 32-byte correlation value for controlled durable audit serialization while Debug remains redacted; durable request identity is allocated only after admission succeeds.

## Invariants and authorization

Authentication precedes authorization; authorization binds principal, namespace, resource and operation. `AcceptedBeforeEntry` audit must succeed before durable dispatch. Inbound values cannot replace the derived identity or decision digest. Invalid credentials, denied policy, malformed inputs and pre-entry audit failure allocate no replay identity and produce no state generation. Reads/listing release their results only after `ReadCompleted`/`ListCompleted` audit succeeds; otherwise `AuditUnavailableAfterRead` returns no secret. Listing an empty prefix requests namespace-root access and must be explicitly authorized by the assembly.

## Failure, retry and reconciliation

Pre-entry failures are definite and may be retried only after correcting their cause. Once durable entry may have happened, including real append, snapshot or ledger I/O failure, the result is `OutcomeUnknown` with a service-generated recovery reference: never blind retry. The durable service converts these failures before this adapter maps errors. A poisoned live writer rejects later mutation/read/list as `RecoveryRequired` until reopening; this is distinct from a deterministic input rejection. A post-commit audit failure also returns outcome unknown rather than falsely acknowledging success. Reconciliation reports committed, aborted or unknown; an exact committed resubmission is a duplicate, not a second effect.

## Concurrency and ordering

The adapter uses the durable service's exclusive mutable ownership and writer fence. The fixed order is request validation, authenticate, authorize, accepted-before-entry audit, durable envelope construction, durable dispatch, result audit and response. There is no replay identity allocated before admission. Cancellation between durable dispatch and response is treated as post-entry uncertainty.

## Security and privacy

Request fingerprints and decision bindings use domain-separated SHA-256 with explicit length prefixes. The digest is not a signature and cannot replace a trusted policy engine, audit authenticator or Barrier. `Credential`, principal, authorization digest, namespace, request ID, resource, secret operation and audit fingerprint have redacted Debug implementations. Error display never includes secret or identity bytes. Owned credential buffers and durable `Secret` values zeroize on drop; this does not claim locked memory or erasure of all provider/compiler copies.

## Persistence and compatibility

Persistence belongs to `heptabao-durable-service`; this crate must not introduce a second write path. The injected Barrier protects durable state below the adapter. Compatibility is not inferred from matching function names: request, response, error and side-effect behavior require the independent compatibility/Oracle process. Any adapter format or API change must preserve exact request binding and recovery semantics.

## Observability

Safe metrics are authentication denied, authorization denied, pre-entry audit unavailable, durable committed, duplicate, outcome unknown, durable rejected and durable corrupt. High-cardinality identities and secret-bearing fields are forbidden labels. Operators correlate an outcome only through controlled recovery-reference lookup, not by logging the reference or credential in general telemetry.

## Operations

Assembly must construct exactly one durable root in a sealed composition boundary, install a production authenticator/authorizer/audit provider, and prevent unrelated code from constructing a bypass writer. On post-entry failure, withhold normal success and direct the authenticated operator to reconciliation. On audit or durable corruption, stop admission and preserve evidence.

## Tests and executable evidence

Run `cargo test -p heptabao-runtime-service`. Rust tests inject an actual post-publication ledger EISDIR error and verify preserved outcome reference, unknown audit event, blocked read and committed reopen reconciliation. Read/list tests verify authentication, authorization, fingerprint serialization and result-audit denial without releasing secret bytes. Existing tests prove invalid credentials and denied policy cannot preempt request identity, principal scoping holds, pre-entry audit failure prevents dispatch, post-commit audit failure is reconcile-only, durable unknown survives restart, exact replay is duplicate and Debug is redacted. Repository tests bind mandatory ordering, private ownership, truth files, read-only CI and the SHA-256 boundary.

## Evolution and open boundaries

Repository completion requires current exact-head/prospective-main-merge success and independent review. Production completion needs persistent identity and token administration, MFA/auth methods, append-only authenticated audit, TLS/HTTP transport, operator lookup authorization, concrete Barrier/KMS custody, destructive fault evidence, HA, compatibility admission, incident operations and release authority.

```text
qualification: false
compatibility_claim: false
production_authority: false
migration_authority: false
release_authority: false
authority_effect: NONE
```
