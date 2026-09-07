# heptabao-durable-service

Current plan: `HEPTABAO-PLAN-2026-09-07-V2.1`. Shared cross-cutting rules are defined in `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This crate owns the restart-safe single-node mutation boundary: durable intent, Barrier-protected state publication, commit evidence, replay ledger publication, then acknowledgement. It does not authenticate callers, implement policy, provide TLS, claim HA, or select a production KMS/HSM. The current source is a repository candidate, not a supported secrets server.

## Public API and ownership

`DurableService<B>` is the sole writer for one absolute root while its writer fence is held. `PutRequest` and `DeleteRequest` carry an already-authorized principal, namespace, request identifier, resource and authorization digest. `Barrier` is injected and owns confidentiality/authenticity; `MutationOutcome`, `ServiceError` and `ReconciliationStatus` expose bounded outcome classifications without secret-bearing diagnostics.

## State and data model

The root contains `state.hbs`, append-only `journal.hbj`, replace-by-generation `ledger.hbl`, and a writer-lock file. The snapshot stores namespace-qualified keys and an exact last-commit marker. Journal events are intent, commit or abort with contiguous sequence numbers. Ledger records bind the replay key to the exact operation digest, committed generation and service-generated recovery reference.

## Invariants and authorization

The crate accepts only pre-authorized envelopes and treats the non-zero authorization digest as immutable evidence, not as an authorization engine. Request identity is scoped to authenticated principal, canonical namespace and request ID, then exact-bound to operation, resource, authorization digest and value digest. A conflicting reuse, capacity overflow, stale generation, duplicate decoded key or contradictory persisted record fails before a second effect.

## Failure, retry and reconciliation

A proven failure before intent persistence may be resubmitted after the storage fault is classified. Any failure after intent may exist is `OutcomeUnknown` and must never blind retry. Reopen authenticates all files, aborts an intent whose state was not published, reconstructs a committed ledger record from matching durable state/journal evidence, and rejects ambiguity or contradiction. A committed exact replay returns `Duplicate` without another mutation.

## Concurrency and ordering

One service instance holds the exclusive writer fence. The required total order is intent journal, sealed state publication, commit journal, replay ledger, acknowledgement. File and directory synchronization occur before publication is reported. Cancellation, transport loss and process termination after entry preserve uncertainty; later work is fenced until authoritative reopen or reconciliation establishes the outcome.

## Security and privacy

Security binding digests use domain-separated SHA-256 with explicit length prefixes. The digest is not a signature and does not provide confidentiality, key custody or independent authenticity. Every persisted payload crosses the injected Barrier with distinct associated-data context; production Barrier implementations must use reviewed AEAD and isolated keys. Secret, principal, namespace, request, resource, root and recovery-reference surfaces are redacted from Debug and telemetry labels.

## Persistence and compatibility

All formats have fixed magic/version domains, bounded lengths and zero trailing-byte tolerance. Snapshot and ledger replacement use temporary write, file sync, atomic rename and parent-directory sync; journal append is framed and synced. There is no implicit legacy adoption or online migration. A new format requires a separately versioned migration protocol, original preservation, interruption recovery and rollback policy.

## Observability

Safe counters include committed, duplicate, rejected-before-entry, outcome-unknown, recovered-committed, recovered-aborted, capacity-exhausted, writer-locked and corrupt-root. Labels must exclude identities, paths, ciphertext, digests and recovery references. The operator-facing value is the classification and generation, while detailed storage errors stay inside a redacted diagnostic boundary.

## Operations

Create-new requires an empty validated root; reopen requires all authoritative files and completes recovery before traffic. Operators preserve the root before destructive action, never delete one apparently corrupt file as a repair, and use the recovery/rollback-anchor procedures for restore. Capacity exhaustion is a hard admission stop until a qualified compaction or epoch transition exists.

## Tests and executable evidence

Rust tests cover restart, intent-only abort, published-state reconciliation, missing-ledger reconstruction, duplicate suppression, exact-operation conflict, capacity without eviction, namespace isolation, writer fencing, plaintext absence, tamper rejection and wrong Barrier context. `tests/repository/test_durable_runtime_v2_1.py` and `tests/repository/test_security_hashing_v2_1.py` bind source, documentation, truth files, digest construction and read-only CI.

## Evolution and open boundaries

Repository closure still requires terminal exact-head and prospective-main-merge gates plus current independent review. Production acceptance additionally requires a concrete AEAD/KMS provider, durable audit/anchor integration, destructive power and I/O campaigns, capacity/compaction SLOs, network service assembly, HA or an explicit single-node support decision, legal disposition and release authority.

```text
qualification: false
compatibility_claim: false
production_authority: false
migration_authority: false
release_authority: false
authority_effect: NONE
```
