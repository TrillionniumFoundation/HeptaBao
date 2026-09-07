# `heptabao-runtime-service`

Documentation standard: V3  
Maturity: repository candidate; production authority is not granted.

## Purpose and ownership

`heptabao-runtime-service` owns the admission boundary between an inbound mutation and `heptabao-durable-service`. The runtime service privately owns its durable writer and exposes no mutable accessor. A mutation reaches durable intent only after bounded input validation, authentication, namespace/resource authorization, and a successful pre-entry audit append.

This module does not implement a network listener, a production token format, the full HeptaBao identity/policy data model, a production audit sink, a production Barrier, HA/Raft, or release admission. The `Authenticator`, `Authorizer`, and `AuditSink` traits are explicit integration seams whose production implementations require separate qualification.

## Trust boundary and non-goals

Untrusted inputs are the credential, namespace, request identifier, resource, operation, and secret value. An untrusted caller cannot choose the authenticated principal or authorization digest; those are created only by the injected authenticator and authorizer after validation.

The module does not reserve durable replay identity before authentication or authorization. It does not reinterpret timeout, cancellation, response loss, post-commit audit failure, or a durable post-entry error as a definite abort. It does not grant compatibility, migration, production, or release authority.

## Inputs, outputs, and dependencies

Inputs:

- `InboundMutation`, containing a bounded credential, namespace, request ID, resource, and put/delete operation;
- an `Authenticator` that returns a validated `AuthenticatedPrincipal` or denies;
- an `Authorizer` that binds principal, namespace, resource, and operation to a non-zero `AuthorizationDigest` or denies;
- an `AuditSink` that can durably append stage-classified audit events;
- a privately owned `DurableService<B>` using an injected `Barrier`.

Outputs:

- `RuntimeOutcome::Committed` only after durable-service acknowledgement and successful committed audit append;
- `RuntimeOutcome::Duplicate` only for the same exact durable binding and successful duplicate audit append;
- pre-entry denial classes that guarantee no durable request identity was allocated;
- `RuntimeError::OutcomeUnknown` with a recovery reference whenever durable entry or committed state may exist but a safe response cannot be proven;
- read-only reconciliation through the owned durable service.

## State machine and invariants

```text
Inbound
  -> InputValidated
  -> Authenticated
  -> Authorized
  -> PreEntryAuditDurable
  -> DurableIntentMayExist
  -> DurableCommittedOrDuplicate
  -> PostResultAuditDurable
  -> Response
```

Load-bearing invariants:

1. authentication precedes authorization;
2. authorization precedes pre-entry audit;
3. pre-entry audit precedes any durable-service call;
4. failed authentication, authorization, or pre-entry audit leaves durable generation and retained-request count unchanged;
5. authenticated principal is created by the authenticator and cannot be supplied by the inbound caller;
6. authorization digest is created by the authorizer and binds the admitted operation;
7. durable replay identity is principal- and namespace-scoped and exact-operation bound by `heptabao-durable-service`;
8. a post-commit audit failure is returned as outcome unknown, not a definite failure or retryable response;
9. an outcome-unknown durable error remains outcome unknown and carries the same recovery reference;
10. no public method exposes mutable access to the internally owned durable writer.

## Data ownership and persisted formats

This crate owns no additional persistent file format. Durable state, journal, replay ledger, generation, and recovery classification belong to `heptabao-durable-service`. Audit persistence belongs to the injected `AuditSink` implementation.

The service creates a bounded request fingerprint from authenticated principal, namespace, request ID, resource, operation kind, and authorization digest. The fingerprint is an audit correlation value, not a secret, credential, replay key, cryptographic signature, or replacement for the durable binding.

## API contracts

`RuntimeService::new` consumes the authenticator, authorizer, audit sink, and durable service. Ownership prevents an adapter caller from reaching that specific durable writer through a second mutable path.

`handle` performs the full ordinary admission sequence. `handle_with_failpoint` exists for deterministic crash-boundary testing and delegates the failpoint only after admission. `reconcile` is read-only and returns the durable service's authoritative classification. `generation` and `retained_request_count` are bounded diagnostic facts and do not expose secret data.

`Credential`, `InboundMutation`, `AuthenticatedPrincipal`, `AuthorizationDigest`, and audit event debug output redact sensitive fields. Credentials and secrets never appear in public error strings.

## Error, retry, and reconciliation semantics

| Result | Durable entry possible | Retry rule |
|---|---:|---|
| `InvalidRequest` | No | Correct the input; do not retry unchanged input. |
| `AuthenticationDenied` | No | Obtain valid credentials; the request ID was not reserved. |
| `AuthorizationDenied` | No | Change policy or operation; the request ID was not reserved. |
| `AuditUnavailableBeforeEntry` | No | Restore the audit sink before resubmission. |
| `DurableRejected` | Depends on the mapped durable class, but never carries a safe success claim | Operator classifies the storage/admission condition; do not invent success. |
| `DurableCorrupt` | Unknown historical state | Quarantine and recover; never bypass. |
| `OutcomeUnknown { recovery_reference }` | Yes | Never blind retry; query reconciliation and replay only after an authoritative `Aborted`. |
| `Committed` / `Duplicate` | Yes, committed | The operation is complete; a duplicate causes no second effect. |

A post-commit audit failure intentionally returns `OutcomeUnknown`, even though durable readback will classify it as committed. This prevents a client from repeating an already committed mutation merely because the final audit acknowledgement was unavailable.

## Concurrency, ordering, and cancellation

The current adapter is synchronous and uses exclusive `&mut self` mutation dispatch. The internally owned durable service provides its own single-writer generation and journal ordering. Authentication, authorization, and audit implementations must not call back into the same runtime service or create a second writer for the same root.

Cancellation before durable entry is a pre-entry failure only when the caller can prove the durable call was never invoked. Cancellation at or after durable dispatch is outcome unknown until recovery/readback classifies the recovery reference.

## Security model

Assets include credentials, secret values, principal identity, namespace/resource names, authorization decisions, request IDs, audit correlation, and recovery references. Debug implementations redact credentials, inbound paths, request IDs, principals, authorization digests, fingerprints, and put payloads.

Threats addressed include pre-authentication replay-store exhaustion, cross-principal request-ID preemption, authorization-to-storage rebinding, audit bypass before mutation, duplicate effects after response loss, secret-bearing diagnostics, and unsafe conversion of post-entry uncertainty into retry.

This crate does not prove that an injected authenticator, authorizer, audit sink, Barrier, filesystem, KMS/HSM, or network adapter is production secure. Those components require separate conformance, fault, custody, and independent-review evidence.

## Observability and operator actions

Audit stages are `AcceptedBeforeEntry`, `Committed`, `Duplicate`, and `OutcomeUnknown`. Operators may aggregate bounded counts by stage and stable low-cardinality outcome class. They must not label metrics with credentials, principals, namespaces, request IDs, resources, fingerprints, recovery references, ciphertexts, or secret values.

An `OutcomeUnknown` response must be preserved in operator tooling with its recovery reference. `Committed` readback closes the incident without replay; `Aborted` permits the exact operation to be resubmitted; `Unknown` requires further storage/recovery investigation.

## Test and verification evidence

Crate tests cover:

- invalid credentials cannot allocate durable replay identity;
- authorization denial cannot preempt a later authorized use of the same inbound request ID;
- the same request ID is independently scoped across authenticated principals;
- pre-entry audit failure leaves generation and retained-request count unchanged;
- post-commit audit failure becomes outcome unknown and reconciles to committed;
- a durable post-snapshot failure survives process restart and returns duplicate after authoritative recovery;
- credential, request ID, path, and secret debug redaction.

Repository regression `tests/repository/test_authorized_durable_runtime_v2_1.py` binds source, manifest, module guide, architecture, blocker state, capability matrix, and the main-targeted read-only CI lane.

## Compatibility, migration, and versioning

This crate owns integration contracts, not OpenBao wire compatibility. Trait changes, audit-stage changes, request-fingerprint domain changes, or durable error-mapping changes require semver review and end-to-end regression updates.

A future network adapter must preserve the same ordering and uncertainty semantics. A migration must never expose two mutable writers for one durable root and must preserve principal/namespace/request bindings and recovery references.

## Known gaps and acceptance criteria

Repository-controlled acceptance requires:

- source, module guide, architecture, repository regression, and capability/blocker truth in one exact tree;
- Rust 1.98 locked workspace tests, warnings-denied Clippy, rustdoc, repository and hostile workflow gates;
- exact-head and real prospective merge into `main` terminal success;
- eligible independent current-head review.

Production acceptance additionally requires concrete implementations of the authentication, identity/policy authorization, audit, Barrier/KMS/HSM, storage, network/TLS, recovery-anchor, and HA boundaries; destructive fault qualification; SLOs and 24×7 ownership; complete compatibility evidence; legal disposition; independent security assessment; independent reproduction; and release signatures.

Until those objects exist, `qualification`, `compatibility_claim`, `production_authority`, `migration_authority`, and `release_authority` remain false, and `authority_effect` remains `NONE`.
