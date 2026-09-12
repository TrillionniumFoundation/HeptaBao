# HeptaBao V2.1 durable single-node runtime pipeline

> Scope: this retained increment describes its named library composition and tests. It is not the complete current HTTP server assembly. See [current runtime architecture](HEPTABAO_CURRENT_RUNTIME_ARCHITECTURE.md) for the concrete server, private authentication boundary and per-process HA integration.

Status: repository candidate; production authority is not granted.

## Purpose

This document defines the implemented single-node durability boundary in `heptabao-durable-service`. It complements the in-process authorization and routing path in `heptabao-service-core`; it does not claim that the HTTP server, TLS listener, HA control plane, KMS/HSM custody, or a production secrets engine has already been qualified.

## Required pre-dispatch facts

A caller may enter the durable mutation runtime only after the outer service has established all of the following:

1. the token is valid and not revoked;
2. identity and group expansion succeeded;
3. the namespace resolved to an active canonical path;
4. policy authorized the namespace-qualified canonical resource;
5. mount routing and backend validation succeeded;
6. the request carries a non-zero digest binding the authorization decision.

The durable runtime does not reimplement policy. It persists the authenticated principal, namespace, request identifier, operation kind, resource, authorization digest, and value digest as one exact idempotency binding.

The phrase **sealed state publication** denotes the atomic Barrier-protected snapshot step.

## Persist and acknowledge order

For each accepted mutation the required happens-before chain is:

```text
validate bounded request and retained-capacity preconditions
  -> append and fsync sealed intent journal record
  -> apply mutation to a candidate snapshot
  -> seal, fsync, atomically publish, and directory-sync snapshot
  -> append and fsync sealed commit journal record
  -> seal, fsync, atomically publish, and directory-sync replay ledger
  -> return committed acknowledgement
```

No successful acknowledgement may precede replay-ledger persistence. A write failure before intent persistence is a definite failure. A failure after intent persistence is reported as `OutcomeUnknown` with a service-generated recovery reference. The rule is **never blind retry**; reconcile from durable evidence instead.

## Recovery classification

On reopen, the runtime authenticates and strictly decodes the snapshot, journal, and ledger before accepting traffic.

| Observed durable state | Recovery result |
|---|---|
| Intent exists; matching generation was not published | Append durable abort; classify the reference as `Aborted`; the same exact request may be retried. |
| Intent exists; snapshot `last_commit` exactly matches it | Append durable commit if necessary; restore replay-ledger entry; classify as `Committed`. |
| Commit exists; replay-ledger entry is missing | Rebuild the exact ledger entry from the authenticated commit marker. |
| Ledger contradicts journal, generations regress, sequence gaps exist, or a frame fails authentication | Fail closed and refuse reopen. |

A current process with an unresolved post-intent result fences further mutation dispatch. Restart performs authoritative recovery before clearing that fence.

## Replay and capacity

Replay identity is scoped by authenticated principal, canonical namespace, and request identifier, and is exact-operation bound. Committed records are not FIFO-evicted. When the configured retained-request capacity is exhausted, a new mutation fails before journal or state entry. This is intentionally fail-closed; compaction requires a separately versioned, proven non-reinterpretation protocol.

## Persisted formats

The implementation owns three versioned files:

- `state.hbs`: barrier-protected snapshot generation, namespace-qualified KV state, and the exact last commit marker;
- `journal.hbj`: append-only, sequence-numbered, barrier-protected intent/commit/abort records;
- `ledger.hbl`: barrier-protected request-binding and recovery-reference index.

Outer frames have independent domain-separated integrity digests. The injected `Barrier` must additionally provide confidentiality and authenticity, bind the supplied context as associated data, and reject modified ciphertext. The repository test barrier is not a production cryptographic provider.

## Failure and concurrency model

Only one writer may hold a root at a time. The root must be absolute, non-symlinked, and directory-backed. File reads reject symlinks, non-regular objects, oversized frames, duplicate map keys, trailing bytes, malformed UTF-8, non-canonical identifiers, sequence gaps, and generation mismatches.

The current writer lock is a single-host filesystem lock-file contract. Production qualification still requires the existing filesystem-guard/controller campaign, abnormal-process cleanup design, disk-full and I/O-fault injection, real power-cut execution, and documented operator recovery.

## Executable evidence

The crate-level tests exercise:

- write, process drop, reopen, read, and duplicate suppression;
- crash after intent, after snapshot publication, and after commit journal;
- ledger reconstruction and authoritative reconciliation;
- namespace key separation and exact-operation request binding;
- retained-capacity fail-closed behavior without eviction;
- writer fencing, debug redaction, no plaintext secret bytes in persisted files;
- tamper detection and wrong-state refusal.

The V2.1 CI lane also runs repository truth, hostile workflow checks, historical documentation gates, platform and Oracle suites, Rust 1.98 formatting, locked workspace tests, warnings-denied Clippy, and rustdoc on the exact PR head.

## Non-claims and remaining admission gates

This implementation closes a repository-controlled durability composition gap. It does not by itself establish:

- production AEAD or KMS/HSM key custody;
- a network/TLS service adapter and full secret-management API;
- multi-process crash cleanup under every supported filesystem;
- Raft replication or HA linearizability;
- destructive power-cut qualification;
- complete OpenBao compatibility;
- legal, incident-response, independent security-review, migration, or release authority.

Those gates remain independently fail-closed until their real completion evidence is admitted.
## Cryptographic binding boundary

All request, value, frame and recovery bindings use domain-separated SHA-256 with explicit length prefixes. The digest is not a signature. Confidentiality and authenticated persistence remain the responsibility of the injected Barrier and its separately qualified key custody.
