# HeptaBao replay-epoch lifecycle protocol

Status: current implementation contract for the V2.1 candidate. This document is source-bound architecture, not a compatibility, production, migration, release, or independent-admission receipt.

## Purpose and state ownership

HeptaBao retains exact durable request identities so a lost response cannot turn a retry into a second state effect. The active detailed replay ledger is bounded to **32,000** operation identities. Ordinary compaction does not evict those identities. Capacity exhaustion therefore needs an explicit authenticated lifecycle transition rather than silent LRU-style forgetting.

`crates/heptabao-server/src/service.rs` owns a cluster-visible `replay_epoch: u64` inside current `State` schema 5. `heptabao-durable-service` owns each node's local detailed replay ledger and its local epoch. The two values have different jobs:

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

For a single-node Service, the authenticated route clones the current state, checks that its `replay_epoch` matches the durable-service epoch, increments exactly once, and persists the new state through `persist_state_batch`. That persistence path retires the local detailed replay ledger first and then writes the chunked state under the new epoch. The response is released only after local convergence is observed.

If the operation-identity ledger is already full, the retirement path is still admitted specifically so capacity can be recovered without silently deleting old identities. A restart must reopen with the same epoch frontier before new state effects are accepted.

## HA sequence

In HA, the leader performs the same authorization and one-step validation, but the target `State.replay_epoch` is first proposed through the existing Raft application-state path. Committing that state defines the cluster order of the transition; it does not by itself delete every node's local ledger.

When the leader or a follower applies the committed target state, `persist_state_batch` compares the target epoch with the node-local durable epoch. Normal publication permits at most one-step advancement. The dedicated authoritative HA catch-up path may be several epochs behind: it repeatedly invokes the same durable replay-retirement primitive until the local owner reaches the committed target, verifies the exact epoch, and only then publishes the local chunk manifest/state batch. This is not an unguarded restore path and cannot be selected by a normal request.

A newly elected leader must be able to observe the committed epoch locally and commit an ordinary mutation in it. That behavioral check is important because a standby HTTP request can be forwarded to the leader and cannot prove the standby's local replay ledger advanced.

## Reopen, legacy normalization, and failure fencing

On unseal/reopen, application state ahead of the durable replay authority is rejected because publishing it would lose the detailed replay fence. Older single-node candidates could retire the durable ledger without recording the epoch in application state. The current reader permits only that one-way legacy condition: if the durable epoch is ahead, current state is normalized upward and rewritten before the state can participate in HA.

A partial retirement/publication failure sets the Service recovery fence. The caller must not blindly replay the maintenance request or a preceding write after an ambiguous result. Recovery follows the ordinary durable reconciliation boundary; deleting ledger or journal material to resume is invalid.

## Storage and capacity interaction

Replay retirement does not make the current state layout horizontally scalable. The serialized logical application state is bounded to **16 MiB**. Local durability splits it into immutable **512 KiB** chunks plus the authenticated alternating-slot `heptabao-state-chunks-v1` manifest, while HA still serializes and proposes the complete logical state. Record-oriented state ownership and bounded write amplification remain separate replacement-admission work.

The retained root-only `GET sys/internal/storage/capacity` view exposes `replay_epoch`, `retired_through_generation`, and `replay_retirement`. In HA the latter is `raft-coordinated`. `GET sys/internal/capacity` reports the newer logical application-state capacity contract. Neither route reserves capacity or grants replacement authority.

## Executable evidence

Focused Rust source scenarios in `crates/heptabao-server/src/service_capacity_tests.rs` cover:

- `replay_retirement_is_root_only_and_state_commits_continue_in_new_epoch`;
- `replay_epoch_transition_bypasses_full_ledger_and_restart_preserves_frontier`;
- `ha_catch_up_epoch_transition_retires_local_ledger_before_state_publication`;
- `ha_catch_up_can_advance_across_multiple_committed_replay_epochs_without_widening_local_writes`;
- `failed_state_publication_after_epoch_retirement_fences_service`.

`qa/openbao-acceptance/replay_epoch_ha.py` extends the existing real three-process mTLS/Raft destructive harness. On private synthetic loopback state it performs a first retirement, kills the acknowledged leader with the harness' process-kill path, requires a former follower to become leader and commit in the new epoch, restarts the old leader, makes the restarted process authoritative again and commits, then performs a second retirement followed by another leader loss and mutation. The result binds the exact server binary digest and remains repository-controlled evidence.

`.github/workflows/replay-epoch-ha.yml` runs that fixture against the pull request's immutable exact head with read-only repository permissions and no persisted checkout credentials. A source file or workflow being present is not a pass receipt; only the current exact-head run establishes the named observation.

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
