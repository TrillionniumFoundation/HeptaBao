# Native V6 + Raft: one durable commit authority (design contract)

**Status:** design only; NOT implemented or production-qualified. The current V6 native path remains single-node and must fail closed when HA is enabled.

**Source context:** the isolated local merge `0b617cf96877ead41b967a269961fd2fbcd15567` combines `e0b784a` V6 migration work with `d652f474` HA peer-deadline work. Those three local commits were not retrievable from GitHub when this document was written. This document is intentionally based on a separately published development branch; it is **not** evidence that the local merge was published or tested by GitHub CI.

## The actual incompatibility

In `crates/heptabao-server/src/main.rs`, `--fixture-native-v6-service` requires exactly `--config`, while a multi-node server uses `--config ... --ha-config ...`. The V6 startup path is gated by the `fixture-native-v6-service` compile feature. In `service_native_v6_reader.rs` and `service_native_v6_writer.rs`, native candidate custody explicitly rejects `self.ha.is_some()`; `service_snapshot_v6.rs` also rejects HA during snapshot transfer.

These checks prevent two unrelated writers from asserting the same durable root. **Do not remove them as a shortcut.** Existing real 66-version HTTPS migrations prove single-node functionality; existing 57-check physical three-host HA passes prove a separate V5 path. Their conjunction is not a V6 HA pass.

## Non-negotiable authority invariants

1. **Exactly one authoritative commit order.** A client-visible V6 mutation is ordered by one Raft log entry, not by a stand-alone local filesystem commit plus a best-effort Raft notification.
2. **Authenticated immutable payload before reference.** No published V6 root may reference ciphertext which was not durably replicated to the quorum required by the Raft commitment. Use the existing bounded HA application-object/chunk facilities where possible; never rely on an unreplicated filesystem path.
3. **Root compare-and-publish.** An authorized transition binds `cluster_id`, membership/replay epoch, `expected_prior_root`, prior and new generation, canonical new root digest, ordered object references and the original request identity. Mismatched base/root/epoch fails closed before visibility.
4. **Never acknowledge merely because the log was appended.** Reply success only after Raft majority commitment and local V6 publication is durable and verified. If an earlier commit is known but local publication cannot be verified by the original deadline, reply unknown/unavailable and retain reconciliation identity; never fabricate an HTTP 200.
5. **ReadIndex cannot bypass application.** Follower reads require a fresh linearizable authority witness and a locally applied/persisted state at least as recent as that witness; a signed old root alone is insufficient.
6. **No double submit after an ambiguous response.** Preserve the exact original command identity across TCP loss, client timeout, leader change, resume and reconciliation. A new command identity must never silently retry a possibly committed command.
7. **Fail-closed recovery.** Missing chunks, wrong barrier or seal, stale epoch, root corruption, partial publication, disk-full or lost owner fences make the replica unavailable until authenticated recovery. Never fall back to an older acknowledged root.

## Minimal ordered implementation

### A. Replicated immutable V6 objects (no external writer authority)

Extend the existing typed HA application-object protocol with a V6 object domain, a canonical object reference including ciphertext size and digest, and bounded chunk framing. Authentication belongs to the original barrier/actor/ACL owner; the Raft log contains only validated commands and ciphertext/object hashes, never raw bearer credentials. Carry all external-object dependencies into the committed state machine and ensure replica replay is deterministic. Add negative tests for duplicate identifiers, aliasing, out-of-order fragments, digest collisions by metadata reuse, oversized payloads and mismatched cluster epochs.

### B. Single root publication entry

Introduce a typed `V6PublishRoot` entry rather than calling the single-node `restore_v6_prepared_with_io_gate` directly from HA. The entry must contain the prior-root precondition, canonical next-root identity, object commitment closure and original operation/actor authorization binding. Only the Raft apply path can advance the externally visible V6 state. The local filesystem may stage objects ahead of this event but cannot publish a root or return success ahead of Raft commitment. Generation and root identity must be monotonic per epoch.

### C. Crash-safe apply and replay

Reuse existing safe staging, no-replace publication, exact-byte and fsync mechanics only *behind* a Raft-ordered authority fence. Persist a binding `(cluster, epoch, term, log_index, root_digest)` with the native root. At cold reopen, verify the canonical root and closure, then reconcile Raft committed index vs local publication index before granting unseal/read/leadership. A follower that has a committed index but lacks verified objects must fetch/catch up under authenticated membership, never announce readiness or return stale data.

### D. Migration and HA admission

Keep the currently passing stand-alone V6 HTTPS import/export unchanged. To admit migrated state into a new HA cluster, quiesce its single-node publication authority and create one explicit *Raft genesis/checkpoint* that binds the sealed V6 root and its complete object closure. Replicate and verify this checkpoint on each node before switching traffic. No node may independently import the same snapshot after consensus is active. During staged rollouts, incompatible binaries/reader floors cannot join the voting set or become leader.

### E. HA request and token semantics

Preserve existing completed-forward and unknown-outcome receipts, RequestDeadlineScope behavior, original 15-second snapshot budget and HA peer TCP admission deadlines. Preserve AuthBus/token/ACL/seal owner identity at command preparation *and* final authority checks. A follower cannot convert a denial into a new leader write. Rotate/revoke credential authority independently of log replication, then verify a prior credential does not regain permissions after restart.

## Required physical-machine evidence

Use the **same exact committed source tree** on Linux, X230 and Mac ARM64, with independent platform-native binary hashes and retained build receipts. Run unique-data (not repeated-block) 66-version HTTPS source migration and cold target replay on each participating platform with the unchanged 15-second server budget. Then exercise the *same candidate's* real V6 HA rather than a V5 fixture:

| Fault/window | Required independent observation |
|---|---|
| Three-node startup and genesis | Identical authenticated V6 root and object closure; no second local writer |
| Mutate on follower | Exactly one original operation identity; leader commits and all healthy replicas converge |
| Leader SIGKILL after quorum commit, before HTTP reply | New leader recovers committed mutation exactly once; client outcome remains reconcilable |
| Leader SIGKILL before quorum commit | No acknowledged mutation; no candidate root becomes visible |
| Follower offline during commit | Healthy quorum progresses; lagging follower catches up before ReadIndex reads |
| Partition 1+2, then reunite | One-voter minority cannot serve writes; no split-brain or stale-epoch publication |
| Kill during native local-object publication and cold restart | Journal + Raft index reconcile to a single authenticated root or fail closed |
| Disk full / corrupted object / changed seal | Replica denied until repair; no old acknowledged state silently substituted |
| Unseal, token revocation, AppRole and AuthBus restart | Original authorization and leases remain consistent with consensus |
| Exact versioned comparison with OpenBao 2.7.1 | KV2, auth/policies, leases, transit, PKI, audit, snapshot, restart/recovery and providers graded individually |

**Pass rule:** retain command/receipt identities and SHA256s; all required checks run on the same candidate, no unresolved unknown submissions, no acknowledged data loss, no unproved recovery claim. Two independent full physical HA runs and repeated V6 migrations are necessary but still do not replace long-horizon, external-provider or production-custody qualification.

## Stop conditions

- If the code can only start native V6 with `--fixture-native-v6-service`, record **NOT PRODUCTION**.
- If `--ha-config` plus V6 cannot start without removing the single-node custody check, record **NOT V6 HA**.
- If only a V5 three-host HA result is available, record **V5 HA ONLY**.
- If a write's final publication or acknowledgment is ambiguous, **reconcile by original identity; never auto-replay**.
- Do not retire OpenBao 2.7.1, change production AuthBus or weaken Desktop Commander as part of these isolated trials.

## Review order

Implement A → B → C, prove the crash windows locally, then D and E with real three-host tests. Keep each step independently reversible and source-bound. Avoid a new parallel storage engine; extend the existing HA record/chunk and durable V6 mechanisms. Promotion requires signed/hashed exact-source build and test evidence, not merely compilation or a clean merge.
