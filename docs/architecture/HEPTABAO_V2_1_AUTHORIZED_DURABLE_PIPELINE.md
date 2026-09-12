# HeptaBao V2.1 authorized durable mutation pipeline

> Scope: this retained increment describes its named library composition and tests. It is not the complete current HTTP server assembly. See [current runtime architecture](HEPTABAO_CURRENT_RUNTIME_ARCHITECTURE.md) for the concrete server, private authentication boundary and per-process HA integration.

Status: repository candidate; no production or release authority.

## Objective

This pipeline removes the repository-level ambiguity between admission and persistence. `heptabao-runtime-service` privately owns one `heptabao-durable-service` writer. Inbound callers cannot supply an authenticated principal or authorization digest and cannot obtain a mutable reference to that owned writer.

## Mandatory sequence

```text
bounded inbound request
  -> authenticate credential
  -> create validated authenticated principal
  -> authorize principal + namespace + resource + operation
  -> create non-zero authorization digest
  -> append durable pre-entry audit event
  -> construct exact durable mutation envelope
  -> append/fsync sealed intent
  -> publish/fsync sealed snapshot
  -> append/fsync sealed commit
  -> publish/fsync sealed replay ledger
  -> append committed-or-duplicate audit event
  -> return response
```

There is no durable replay allocation before authentication, authorization, and pre-entry audit succeed.

## Binding carried across the boundary

The adapter carries these fields into durable intent without allowing the inbound caller to rewrite them after admission:

- authenticated principal;
- canonical namespace;
- bounded request identifier;
- canonical resource;
- operation kind;
- authorization decision digest;
- secret-value digest for put operations.

The durable runtime uses the principal, namespace, and request identifier as the replay key and binds that key to the exact remaining fields. Reusing the key for a different value, resource, operation, or authorization digest is rejected before mutation.


The operational retry rule is **never blind retry** after durable entry. Authentication or authorization rejection means **no replay identity allocated**. A **post-commit audit failure** withholds normal success and is reconciled from durable state.

## Failure classification

| Failure point | Durable effect possible | Response |
|---|---:|---|
| Input validation | No | Invalid request. |
| Authentication | No | Authentication denied; no replay identity allocated. |
| Authorization | No | Authorization denied; no replay identity allocated. |
| Pre-entry audit | No | Audit unavailable; no durable dispatch. |
| Before durable intent persistence | No when proven by the durable provider | Definite durable rejection. |
| After durable intent may exist | Yes | Outcome unknown with recovery reference. |
| After state commit but before final audit acknowledgement | Yes | Outcome unknown with recovery reference. |
| Duplicate of exact committed binding | Already committed | Duplicate response after duplicate audit append. |
| Persisted-state contradiction or authentication failure | Unknown historical state | Fail closed and invoke recovery. |

A transport timeout or cancellation is not itself proof that durable entry did not occur.

## Audit contract

The pre-entry audit is a hard gate: its failure prevents durable dispatch. The committed/duplicate audit follows durable acknowledgement. If that post-result audit fails, the adapter withholds a normal success response and returns `OutcomeUnknown`; authoritative durable reconciliation will report `Committed` and prevent a second effect.

Audit events contain a bounded request fingerprint and optional generation, not credentials, secret values, principal names, namespaces, resources, request IDs, authorization digests, or recovery references.

## Restart scenario

The minimum repository scenario is:

```text
authenticate
-> authorize
-> pre-entry audit
-> persist intent
-> publish sealed state
-> simulate response-path failure
-> terminate service object
-> reopen durable root
-> authenticate and authorize the same exact request
-> durable reconciliation reports committed
-> request returns duplicate without a second mutation
```

An intent-only crash is durably aborted on reopen and may be retried. A published snapshot or commit-journal record reconstructs the replay ledger and returns duplicate.

## Bypass analysis

Within `RuntimeService`, the durable writer is a private owned field with no accessor. Every public mutation method executes authentication, authorization, and pre-entry audit before calling it. The test failpoint API follows the same admission sequence and only injects failure after admission.

This is a module-level non-bypass property. It does not prevent unrelated code elsewhere in the process from independently constructing another `DurableService`; production service assembly must therefore keep durable-root construction in a sealed composition root and enforce one writer through configuration, filesystem fencing, and deployment policy.

## Capacity and denial of service

Rejected credentials and denied authorizations do not enter the durable replay ledger. The durable ledger has a finite configured capacity and never silently evicts committed or unresolved request identities. At capacity, new admitted mutations fail before intent persistence. Production operation requires capacity metrics, alerting, and a separately qualified compaction/epoch transition protocol.

## Security and non-claims

The pipeline addresses ordering, replay, rebinding, pre-authentication allocation, audit bypass, and ambiguous-result handling. It does not establish:

- a production credential protocol or identity database;
- production policy compilation and distribution;
- a production append-only audit sink;
- TLS/network framing and proxy semantics;
- production AEAD or isolated KMS/HSM custody;
- locked memory, zeroization, or crash-dump control;
- multi-node consensus or HA linearizability;
- destructive storage/power qualification;
- full OpenBao compatibility;
- legal, operational, independent-security, migration, or release authority.

Those remain separate fail-closed blockers.
## Cryptographic binding boundary

All request, value, frame and recovery bindings use domain-separated SHA-256 with explicit length prefixes. The digest is not a signature. Confidentiality and authenticated persistence remain the responsibility of the injected Barrier and its separately qualified key custody.
