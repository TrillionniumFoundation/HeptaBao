# HeptaBao replay-epoch lifecycle protocol

Status: current implementation contract for the V2.1 candidate. This document is source-bound architecture, not a compatibility, production, migration, release, or independent-admission receipt.

## Purpose and state ownership

HeptaBao retains exact durable request identities so a lost response cannot turn a retry into a second state effect. The active detailed replay ledger is bounded to **32,000** operation identities. Ordinary compaction does not evict those identities. Capacity exhaustion therefore needs an explicit authenticated lifecycle transition rather than silent LRU-style forgetting.

`crates/heptabao-server/src/service.rs` owns a cluster-visible `replay_epoch: u64` inside `State` (introduced in schema 5; the current discriminator is defined in `HEPTABAO_CURRENT_STATE_FORMAT.md`). `heptabao-durable-service` owns each node's local detailed replay ledger and its local epoch. The two values have different jobs:

- application-state `replay_epoch` is the replicated cluster ordering point;
- the durable-service epoch fences the node-local operation-identity namespace;
- state for epoch N may be published locally only after the durable replay owner is in epoch N.

The operator transition is root-namespace `POST` or `PUT sys/storage/raft/replay-retire` with an empty JSON object. It is a HeptaBao maintenance route, not an OpenBao compatibility surface.

## Transition invariants

A valid transition obeys all of the following rules.

1. An operator retirement transition is exactly current cluster epoch + 1. Normal/local publication cannot jump epochs; regression, overflow, or an unexplained state/durable mismatch fails closed. A stale node applying authoritative Raft state may traverse multiple already-committed missing epochs locally, one retirement at a time.
2. Normal application mutations stay in the current epoch and cannot retire the replay ledger as a side effect.
3. The active **32,000**-identity bound applies per replay epoch. Reaching it refuses ordinary new durable identities; an authenticated one-step retirement remains the explicit escape path.
4. In HA, the epoch marker is committed as ordinary authoritative Raft application state. A node applying a higher committed epoch retires its local durable replay ledger immediately before publishing that state locally.
5. A node never publishes application state for epoch N while its local durable replay owner remains in an older epoch.
6. Failure after local retirement but before state publication is not relabelled as a safe pre-entry rejection. The service is fenced for reopen/reconciliation.
7. Standby HTTP forwarding is not evidence of follower-local convergence. Cross-node acceptance must force a former follower to become leader and commit after the retirement.

## Single-node sequence

For a single-node Service, the authenticated route clones the current state, checks that its `replay_epoch` matches the durable-service epoch, increments exactly once, and persists the candidate through the selected storage path. Local replay retirement precedes publication of either the legacy owner manifest or the V5 record root under the new epoch. The response is released only after local convergence is observed.

If the operation-identity ledger is already full, the retirement path is still admitted specifically so capacity can be recovered without silently deleting old identities. A restart must reopen with the same epoch frontier before new state effects are accepted.

## HA sequence

In HA, the leader performs the same authorization and one-step validation, but the target `State.replay_epoch` is first proposed through the existing Raft application-state path. Committing that state defines the cluster order of the transition; it does not by itself delete every node's local ledger.

When the leader or a follower applies the committed target state, the selected legacy or record publication path compares the target epoch with the node-local durable epoch. Normal publication permits at most one-step advancement. The dedicated authoritative HA catch-up path may be several epochs behind: it repeatedly invokes the same durable replay-retirement primitive until the local owner reaches the committed target, verifies the exact epoch, and only then publishes the local owner manifest or record root. This is not an unguarded restore path and cannot be selected by a normal request.

A newly elected leader must be able to observe the committed epoch locally and commit an ordinary mutation in it. That behavioral check is important because a standby HTTP request can be forwarded to the leader and cannot prove the standby's local replay ledger advanced.

## Reopen, legacy normalization, and failure fencing

On unseal/reopen, application state ahead of the durable replay authority is rejected because publishing it would lose the detailed replay fence. Older single-node candidates could retire the durable ledger without recording the epoch in application state. The current reader permits only that one-way legacy condition: if the durable epoch is ahead, current state is normalized upward and rewritten before the state can participate in HA.

A partial retirement/publication failure sets the Service recovery fence. The caller must not blindly replay the maintenance request or a preceding write after an ambiguous result. Recovery follows the ordinary durable reconciliation boundary; deleting ledger or journal material to resume is invalid.

## Storage and capacity interaction

Replay retirement retains the same identity frontier across both storage paths.
Legacy `heptabao-state-owners-v4` stores one bounded logical State in owner chunks;
HBSM4 replicates that complete logical image. Current
`heptabao-state-records-v5` separates immutable KV1 blocks/index pages from opaque
owners and publishes a single authenticated root; HBSM5 orders typed object
staging and root publication. KV2 and other opaque owners still have whole-owner
serialization costs. A pure legacy read/reopen does not migrate; ordinary logical
mutation explicitly constructs the V5 candidate before publication.

The [capacity contract](../operations/HEPTABAO_CAPACITY_AND_GROWTH.md) records
source-bound V4 chunk limits and distinct V5 root, owner, value, page, and graph
limits. Durable artifact/journal limits, replay identities and HA snapshot limits
remain independent and can reject before any logical component ceiling is reached.
A passing drift guard establishes documentation consistency only, not scalability
or replacement qualification.

The retained root-only `GET sys/internal/storage/capacity` view exposes `replay_epoch`, `retired_through_generation`, and `replay_retirement`. In HA the latter is `raft-coordinated`. `GET sys/internal/capacity` reports the newer logical application-state capacity contract. Neither route reserves capacity or grants replacement authority.

## Executable evidence

Focused Rust source scenarios in `crates/heptabao-server/src/service_capacity_tests.rs` cover:

- `replay_retirement_is_root_only_and_state_commits_continue_in_new_epoch`;
- `replay_epoch_transition_bypasses_full_ledger_and_restart_preserves_frontier`;
- `ha_catch_up_epoch_transition_retires_local_ledger_before_state_publication`;
- `ha_catch_up_can_advance_across_multiple_committed_replay_epochs_without_widening_local_writes`;
- `failed_state_publication_after_epoch_retirement_fences_service`.

`qa/openbao-acceptance/replay_epoch_ha.py` extends the existing real three-process mTLS/Raft destructive harness. On private synthetic loopback state it performs repeated retirements and leadership changes, then deliberately keeps one voter offline across two consecutive committed epoch transitions. After rejoin, the fixture reduces the live set to a two-of-three quorum, transfers leadership to that formerly stale voter, verifies its local epoch and requires a real mutation in the latest epoch. The result binds the exact server binary digest and remains repository-controlled evidence.

`.github/workflows/replay-epoch-ha.yml` runs that fixture against the pull request's immutable exact head with read-only repository permissions and no persisted checkout credentials. A source file or workflow being present is not a pass receipt; only the current exact-head run establishes the named observation.

The current SSD Linux receipt is [`qa/openbao-acceptance/evidence/replay-epoch-e57f045.json`](../../qa/openbao-acceptance/evidence/replay-epoch-e57f045.json): 53 scoped scenarios passed for binary digest `e57f04533c3beaf9560b0d5dd1af66355231df6bf8ddc09ace03598e338579b3`. It leaves the directed-partition, forced-snapshot, disk/power-fault, mixed-version, multi-host and independent-reproduction exits below open.

## Remaining admission gaps

This protocol and its repository-controlled three-process fixture do not close replacement admission by themselves. Still required are at least:

- replay retirement during directed network partition and heal;
- forced snapshot installation/catch-up across an epoch transition;
- actual saturation beyond 32,000 operations and repeated long-running retirements;
- disk-full, permission, fsync/rename and power-loss faults at each transition boundary;
- mixed-version and rolling-upgrade behavior across schema/epoch changes;
- multi-host timing/storage behavior rather than loopback processes;
- independent exact-head reproduction and release/security authority.

Accordingly, source presence and a scoped passing fixture leave `replacement_authority`, `production_authority`, `release_authority`, and independent qualification false until their separate gates are satisfied.
