# `heptabao-durable-service`

Documentation standard: V3  
Maturity: repository candidate; production authority is not granted.

## 1. Purpose and ownership

`heptabao-durable-service` owns the restart-safe, single-writer mutation durability boundary for already authenticated and authorized secret operations. It persists one namespace-qualified state snapshot, an append-only intent/commit/abort journal, and a non-evicting replay ledger. It classifies ambiguous post-entry failures by a service-generated recovery reference.

The crate owns no network listener, token parser, identity resolver, policy compiler, mount router, production cryptographic implementation, HA consensus, or release decision. Those responsibilities remain in their dedicated modules and admission gates.

## 2. Trust boundary and non-goals

Inputs are trusted only to the extent explicitly represented in the request envelope. The caller must already have established token validity, identity expansion, active namespace resolution, authorization of the namespace-qualified canonical resource, mount/backend validity, and a non-zero authorization-decision digest.

The crate does not treat a caller-provided path or request identifier as authorization. It does not make the repository test barrier a production AEAD. It does not claim that a filesystem lock file is sufficient for every abnormal process, network filesystem, or multi-node deployment.

## 3. Inputs, outputs, and dependencies

Public inputs:

- `PutRequest`: authenticated principal, canonical namespace, request identifier, canonical resource, authorization digest, and secret value;
- `DeleteRequest`: the same identity and authorization binding without a secret payload;
- `Barrier`: injected confidentiality/authenticity provider whose context is authenticated associated data;
- an absolute non-symlinked root and a finite retained-request capacity.

Public outputs:

- `MutationOutcome::Committed` after intent, snapshot, commit journal, and replay ledger are durable;
- `MutationOutcome::Duplicate` for the same exact binding without a second effect;
- `ServiceError::OutcomeUnknown` with a recovery reference after durable entry but before a safe acknowledgement;
- `ReconciliationStatus` after authoritative reopen/recovery.

## 4. State machine and invariants

Mutation state machine:

```text
Validated
  -> IntentDurable
  -> SnapshotPublished
  -> CommitDurable
  -> LedgerDurable
  -> Acknowledged
```

Recovery may transform `IntentDurable` into `Aborted`, or transform `SnapshotPublished`/`CommitDurable` into `LedgerDurable` by authenticated readback. No other shortcut is legal.

Load-bearing invariants:

1. a successful acknowledgement happens only after the replay ledger is atomically published and directory-synced;
2. request identity is scoped by authenticated principal, canonical namespace, and request identifier;
3. the identity is exact-operation bound to resource, operation kind, authorization digest, and value digest;
4. a conflicting reuse is rejected before mutation;
5. committed request identities are not FIFO-evicted;
6. at capacity, a new request fails before journal or state entry;
7. journal sequence numbers are contiguous and generations never regress;
8. a ledger record must be supported by an authenticated matching commit event;
9. an unmatched intent is either proven unpublished and durably aborted, or proven published and committed;
10. malformed, unauthenticated, contradictory, duplicated, oversized, or trailing persisted data fails closed.

## 5. Data ownership and persisted formats

The crate is the authoritative writer for three files in its root:

| File | Ownership | Contents |
|---|---|---|
| `state.hbs` | replace-by-generation | Barrier-protected namespace-qualified KV snapshot and exact `last_commit` marker. |
| `journal.hbj` | append-only | Sequence-numbered Barrier-protected intent, commit, and abort records. |
| `ledger.hbl` | replace-by-generation | Barrier-protected request binding, generation, and recovery-reference index. |

Every format has a magic/version domain, strict length bounds, no trailing-byte tolerance, and an outer domain-separated integrity digest. The injected Barrier receives a distinct context for snapshot generation, journal sequence, and ledger generation. A provider must authenticate that context.

The snapshot publication protocol is temporary-file write, file sync, atomic rename, then parent-directory sync. Ledger publication uses the same protocol. Journal append is length-framed and file-synced before returning.

## 6. API contracts

`create_new` accepts only an empty root, creates the initial sealed snapshot/journal/ledger, and acquires the writer fence. `reopen` requires all three authoritative files, authenticates and decodes them, replays the journal, reconciles pending/committed records, republishes a repaired ledger where required, and only then accepts traffic.

`put` and `delete` are ordinary mutation APIs. Their failpoint variants are deterministic test seams and preserve the same durability semantics. `get` validates namespace/resource shape and returns a redacted `Secret` wrapper. `reconcile` is read-only and never converts unknown state into a guessed success.

## 7. Error, retry, and reconciliation semantics

| Error class | Retry rule | Required action |
|---|---|---|
| Invalid root/request/namespace/resource/secret/auth digest | Do not retry unchanged input | Correct the caller or configuration. |
| Writer locked | Do not start a second writer | Resolve the active/stale writer under the operator runbook. |
| Request binding conflict | Never retry under the same identity with a changed operation | Allocate a new request identity only for a genuinely new operation. |
| Capacity exhausted | No backend effect occurred for the rejected new request | Stop admission; compact only under a separately qualified protocol or provision a new epoch. |
| I/O before durable intent | Retry only after operator classifies the storage fault | No effect was admitted by this runtime. |
| `OutcomeUnknown` | Never blind retry | Reopen/read back and query the recovery reference. |
| Corrupt state or Barrier failure | Never bypass | Quarantine the root and invoke recovery/restore procedures. |

After reopen, a reference is `Committed`, `Aborted`, or `Unknown`. Only `Aborted` permits the exact request to be submitted again. `Committed` maps the original request to `Duplicate` without a second effect.

## 8. Concurrency, ordering, and cancellation

The current implementation is a synchronous single-writer service. The root lock fences concurrent cooperating writers. All mutations execute under the exclusive mutable service instance, so snapshot generation and journal sequence advancement have a single total order.

Cancellation after intent persistence must be surfaced as outcome unknown; callers must not treat task cancellation, connection loss, or timeout as a definite abort. The outer service must retain the recovery reference across response loss.

## 9. Security model

Protected assets are secret values, authorization bindings, namespace-qualified resources, request identities, generations, and reconciliation outcomes. Debug representations redact roots, principal/namespace/request/resource fields, authorization digests, and secret bytes.

Persisted payloads are passed through the Barrier before disk publication. Repository tests assert that a known plaintext secret is absent from state, journal, and ledger files. This is a regression property, not proof that the test Barrier is cryptographically secure.

Threats addressed include replay, cross-namespace key collision, request rebinding, partial publication, missing ledger update, journal truncation/corruption, context substitution, symlinked authoritative files, oversized inputs, duplicate decoded keys, and stale generation acknowledgement.

Production qualification still requires a reviewed AEAD/KMS implementation, locked-memory and zeroization policy, crash-dump policy, key ceremony, filesystem/controller campaign, and incident/revocation operations.

## 10. Observability and operator actions

The public API intentionally returns classifications rather than raw secret-bearing diagnostics. An adapter may emit bounded metrics for committed, duplicate, rejected-before-entry, outcome-unknown, recovery-committed, recovery-aborted, writer-locked, and corrupt-root outcomes. It must not label metrics with principal, namespace, request ID, resource, recovery reference, ciphertext, or secret material.

Operator procedures must preserve the root before destructive action. A corrupt/authentication failure is not repaired by deleting one file. Restore requires the recovery and rollback-anchor contracts, an empty target, and an externally verified checkpoint.

## 11. Test and verification evidence

Crate tests cover:

- put, drop, reopen, read, and durable duplicate suppression;
- recovery after intent only, snapshot publication, and commit-journal publication;
- authenticated ledger reconstruction;
- namespace storage isolation and exact-operation request binding;
- hard capacity without committed-record eviction;
- single-writer fencing and secret-safe Debug;
- absence of a known plaintext in all persisted files;
- frame tampering and wrong-state failure closure.

Repository regression `tests/repository/test_durable_runtime_v2_1.py` binds the crate, guide, architecture document, blocker entry, capability matrix, and read-only CI. The V2.1 workflow runs Rust 1.98 locked workspace tests, warnings-denied Clippy, rustdoc, repository truth, hostile workflow checks, module documentation, platform, and Oracle suites.

## 12. Compatibility, migration, and versioning

The file magics and domain strings are V1 internal formats. Unknown magic, changed context, trailing bytes, or unsupported structure fails closed. No online format migration is implicit. A future format must have a separately documented version negotiation, all-writers-offline or writer-fenced migration protocol, original preservation, interruption recovery, and rollback rule.

The crate exposes no OpenBao compatibility claim. Compatibility admission belongs to `heptabao-compatibility` and requires external Oracle evidence and side-effect comparison.

## 13. Known gaps and acceptance criteria

Repository-controlled completion of this module requires exact-head and prospective-merge CI success, warnings-denied Clippy, all recovery tests, clean workflow trust, and eligible independent source review.

Production completion additionally requires:

- a service adapter joining the authenticated `service-core` decision to this durable envelope without a bypass path;
- a production Barrier backed by reviewed AEAD and isolated KMS/HSM custody;
- durable audit integration and externally anchored recovery checkpoints;
- multi-process kill/restart, disk-full, fsync-loss, torn-write, corruption, and real power-cut execution;
- capacity/retention/compaction and upgrade SLOs;
- HA/Raft integration or an explicit single-node support boundary;
- legal, independent product-security, incident-operation, compatibility, migration, and release admission.

Until those objects exist, `qualification`, `compatibility_claim`, `production_authority`, `migration_authority`, and `release_authority` remain false and `authority_effect` remains `NONE`.
