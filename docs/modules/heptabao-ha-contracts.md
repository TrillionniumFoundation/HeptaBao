# heptabao-ha-contracts

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns term, membership and writer-fence semantics for an HA composition. It does not implement Raft networking, log replication, snapshots, quorum reads or leader election.

## Public API and ownership

`HaState` owns local role, term, leader, voters, learners and generation. `WriterFence` binds one leader, term and exact generation at a write boundary.

## State and data model

Nodes are followers, leaders or removed. Higher terms demote a leader. Learners must be explicitly promoted before they are voters, and the last voter cannot be removed.

## Invariants and authorization

Only the exact local leader fence validates for writing. Stale terms, nonvoter leaders and stale generations fail closed. Membership does not imply application authorization.

## Failure, retry and reconciliation

Stale fence and membership failures occur before a write enters storage. A provider failure after a validated fence still requires the durable unknown-outcome taxonomy.

## Concurrency and ordering

A real consensus runtime serializes term and membership updates. Writer validation must occur at the storage commit boundary, not only when a request is accepted.

## Security and privacy

Cluster identifiers are bounded and nonsecret. Production peer identity, mTLS, certificate rotation and join authorization remain external provider responsibilities.

## Persistence and compatibility

No Raft log or snapshot format is owned. Persisted term, vote, membership and fence state require versioned crash-consistent storage.

## Observability

Recommended events are leader change, term change, membership change and stale-fence rejection, using node role and outcome labels only.

## Operations

Learner addition, promotion and voter removal are explicit transitions. Production runbooks must include quorum loss, certificate failure, snapshot restore and split-brain fencing.

## Tests and executable evidence

`cargo test -p heptabao-ha-contracts` proves stale-fence rejection, learner promotion and last-voter protection.

## Evolution and open boundaries

OpenRaft or another implementation, joint consensus, read indexes, snapshots and network fault qualification remain open.
