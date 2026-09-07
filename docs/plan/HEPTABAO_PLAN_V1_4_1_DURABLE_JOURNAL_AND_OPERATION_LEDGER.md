# HeptaBao Plan V1.4.1 — Durable Journal and Operation Ledger

**Plan ID:** `HEPTABAO-PLAN-2026-08-28`  
**Revision:** `1.4.1`  
**Status:** `NORMATIVE_DURABLE_JOURNAL_AND_OPERATION_LEDGER_INPUT`  
**Authority effect:** `NONE`

## 1. Purpose

V1.4.1 extends the frozen V1.4 durable single-node foundation with the first
persistent audit/request-effect reconciliation kernel. It closes the gap
between a process-local request-ID duplicate set and a replayable state machine
that can answer whether a mutation was merely accepted, had a durable intent,
committed state, produced an unknown external effect, failed response audit or
failed delivery after commit.

The frozen V1.4 baseline is:

```text
commit = 33e1c14c3e417ea1c9ea181e2181751736c7bce5
tree   = 7c49319a20ffbbe7a9b8b078e052da63dd6b636b
```

V1.4.1 remains a single-process development profile:

```text
profile = HB-P1-DEV-JOURNALED-SINGLE-PROCESS
production_supported = false
replicated = false
multi_process_supported = false
compatibility_supported = false
```

It does not provide a production audit device, multi-process writer fencing, a
selected MAC/KMS/HSM provider, remote replication, retention policy, OpenBao
compatibility, qualification or operational authority.

The executable filesystem profile is Linux-only. Every marker, entry and tail
temporary file is created with owner-only mode `0600`; other operating-system
profiles remain unsupported until they prove equivalent access and durability
semantics.

## 2. Added implementation layers

V1.4.1 adds four provider-separated crates:

1. `heptabao-journal-api` — checked sequence, opaque payload, authentication
   chain, append receipt and replay contracts;
2. `heptabao-single-node-journal` — immutable entry files plus an atomically
   published and directory-synchronized `TAIL` pointer;
3. `heptabao-operation-ledger` — strict versioned operation events, replayed
   state machine and retry directives;
4. `heptabao-journaled-core` — acceptance and intent journaling before the V1.4
   barrier/storage mutation, followed by exact state-commit and response
   outcome transitions.

The journal authenticator is injected. The repository does not embed a key or
claim that its test authenticator is cryptography.

## 3. Journal authoritative order

One journal append follows:

```text
validate marker, in-memory tail and on-disk tail
→ reject stale expected sequence
→ reject unresolved exact-next orphan
→ derive checked next sequence
→ authenticate(domain, sequence, previous tag, payload)
→ create immutable entry file
→ write all + flush + file sync
→ sync journal directory
→ atomically replace TAIL with sequence and tag
→ sync journal directory
→ reread and verify TAIL
→ reread and authenticate the appended entry
→ publish in-memory tail
→ return append receipt
```

If entry persistence succeeds but `TAIL` publication cannot be proven, the
append returns `AppendOutcomeUnknown`. A later reopen may observe exactly one
next orphan. It is not silently accepted; the caller must invoke explicit
`reconcile_next_orphan`, which re-authenticates the complete entry and only
then publishes the tail. Gaps, multiple future entries, duplicate sequence,
non-regular paths, symlinks, unexpected entries and unresolved temporary files
fail closed.

## 4. Operation ledger

Every operation has immutable:

```text
operation_id
request_digest
operation_class
```

Optional state generation/digest, external-effect key digest and response
digest become accumulated immutable facts once present. Every journal payload
is a strict `HEPTABAO-OPERATION-EVENT-V1` binary envelope; truncation, trailing
bytes, unknown phase/class, zero digest, malformed flags and illegal field
shape are rejected.

The operation phases are:

```text
Accepted
RejectedBeforeDispatch
IntentCommitted
EffectStarted
EffectSucceeded | EffectFailed | EffectUnknown
StateCommitted
ResponseAudited | ResponseAuditFailedAfterCommit
Delivered | DeliveryFailedAfterCommit
Reconciled
```

Replay applies the same closed transition table as live append. An event whose
`previous_phase` does not match the current state, a duplicate acceptance, a
missing previous operation or immutable-field drift invalidates the ledger.

## 5. Mutation happens-before

A durable state mutation follows:

```text
reject an already observed operation ID
→ journal Accepted
→ journal IntentCommitted
→ seal plaintext through the V1.4 barrier
→ persist and publish the next durable state generation
→ journal StateCommitted(generation, digest)
→ later journal response-audit outcome
→ later journal delivery outcome
```

The storage mutation is never executed before the durable intent. If state
publication succeeds but `StateCommitted` cannot be appended, the API returns
`StateCommittedLedgerIncomplete` containing the exact commit receipt. This is
not a failed mutation and does not authorize replay. The operation remains
`ReconcileOnly` until a separately validated reconciliation transition is
written.

`reconcile_committed_state` first rereads the authoritative storage snapshot and
requires its generation and digest to equal the supplied commit receipt. Only
then may the ledger append the missing `StateCommitted` transition. A forged,
stale or mismatched receipt fails closed and leaves the operation unresolved.

An unresolved operation globally fences every later mutation whose state could
advance the authoritative generation. `Accepted`, `IntentCommitted`,
`EffectStarted`, `EffectSucceeded` and `EffectUnknown` must be durably
resolved before a new operation ID reaches the barrier or storage. A known
pre-dispatch failure closes through `record_rejected_before_dispatch`; a
postcommit gap closes only through exact stored-snapshot reconciliation.

## 6. Retry and recovery semantics

| Last durable phase | Permitted client/server behavior |
|---|---|
| no record | normal admission using a new operation ID |
| `Accepted` | manual hold or bounded operator recovery; do not assume dispatch |
| `RejectedBeforeDispatch` | a new operation ID may be admitted; the old ID remains consumed |
| `IntentCommitted` | reconcile only; do not blindly create again |
| `EffectStarted` / `EffectUnknown` | provider lookup/reconcile only |
| `EffectFailed` | no automatic retry under the same operation ID |
| `StateCommitted` | lookup committed result only |
| `ResponseAudited` | deliver/lookup result; no duplicate mutation |
| response-audit or delivery failure after commit | lookup/re-audit/reconcile only |
| `Delivered` | lookup result only |
| `Reconciled` | terminal; no automatic retry |

A process restart reconstructs these directives from authenticated journal
records. An in-memory request-ID set is not the source of truth.

## 7. Security boundary

`JournalPayload` and operation-bearing state avoid implicit `Clone`, redact
safe `Debug` output and overwrite owned user-space buffers on controlled drop
paths. Operation IDs are opaque in diagnostics. These controls do not prove
allocator, kernel, swap, core-dump or side-channel erasure.

The single-node journal uses pure-`std` path checks and therefore does not claim
TOCTOU-safe descriptor-relative filesystem operation. Its authenticator
interface is provider-neutral; a production MAC/signature provider, key
custody, rotation and revocation policy remain unselected. An attacker able to
rewrite the complete journal directory can also roll back marker, tail and
entries unless an external rollback anchor verifies.

## 8. Repository-controlled blockers

V1.4.1 introduces and addresses at source level:

- `HB-BLK-REPO-023`: no provider-neutral authenticated journal contract;
- `HB-BLK-REPO-024`: no strict single-node append/replay/orphan-reconciliation
  implementation;
- `HB-BLK-REPO-025`: no durable request/effect state machine and retry matrix;
- `HB-BLK-REPO-026`: durable intent was not composed before state mutation and
  post-commit journal incompleteness was not explicit;
- `HB-BLK-REPO-027`: no version-aware exact-head V1.4.1 execution gate.

Source presence alone does not close them. Technical closure requires the exact
head, frozen V1.4 replay and current Rust/Python gates to pass, followed by
current independent storage and security review.

## 9. Exact execution gates

### Gate A — exact additive source

- the exact current head descends from the frozen V1.4 commit/tree;
- the complete Git delta matches the closed 20-path V1.4.1 extension allowlist;
- no V1.4 file is modified except root workspace/lock extension;
- no source-export or write-capable materializer workflow remains in the final
  tree;
- manifest, status, blocker register, source and workflow agree;
- every authority and qualification field remains false/NONE.

### Gate B — current semantic and regression tests

- V1.4.1 validator and hostile mutation tests pass;
- current platform and Oracle regressions pass;
- duplicate YAML/JSON keys, authority promotion, missing crate, illegal phase,
  chain drift and mutation-before-intent changes fail closed.

### Gate C — frozen V1.4 replay

A detached worktree at exact V1.4 must pass its manifest/source validator,
exact inherited-surface verifier, V1.4 mutation tests, platform/Oracle suites
and Rust 1.98 formatter/tests/strict Clippy. Ancestor success is not silently
relabeled as current execution.

### Gate D — current Rust 1.98

```text
cargo +1.98.0 fmt --all -- --check
cargo +1.98.0 test --locked --workspace --all-targets
cargo +1.98.0 clippy --locked --workspace --all-targets -- -D warnings
```

### Gate E — independent review and final ratification

Independent storage/distributed-systems and security reviewers must bind their
findings to the exact source and execution. After all review-driven changes
stop, the designated project ratifier must publish the required final
no-tree-change source identity. No connected author or workflow may fabricate
those identities.

## 10. Remaining gaps and stop rule

V1.4.1 still does not close production authenticator/key custody,
descriptor-relative filesystem access, multi-process fencing, external rollback
anchor, retention/compaction, replicated audit, external-effect provider
integration, backup/restore, policy/token/lease/namespace/plugin domains,
Raft/HA, Oracle compatibility or any inherited external/control blocker.

The truthful state remains
`SOURCE_IMPLEMENTED_EXACT_HEAD_EXECUTION_AND_INDEPENDENT_REVIEW_REQUIRED` until
all exact gates and independent receipts exist. Even after repository technical
closure:

```text
qualification=false
compatibility_claim=false
selected_candidates=[]
selection_effect=NONE
production_authority=false
migration_authority=false
release_authority=false
authority_effect=NONE
```
