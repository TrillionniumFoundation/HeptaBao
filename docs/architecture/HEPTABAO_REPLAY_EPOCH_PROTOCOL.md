# Replay epoch retirement and HA application protocol

Status: current source contract. The exact Git commit/tree and executable tests
bind the behavior; historical branch names are not authority. This document does
not grant OpenBao compatibility or production qualification.

## Problem

`DurableService` retains exact resolved request identities so an acknowledged,
unknown or duplicated operation is never re-entered under the same replay
context. The server profile bounds the detailed active ledger at 32,000 records.
Journal compaction cannot solve that bound because deleting replay authority
would make an old request indistinguishable from a fresh one.

The durable layer therefore owns an authenticated `replay_epoch` and a
`retired_through_generation` frontier. A request is internally scoped to the
current epoch. Retirement replaces the detailed old-epoch ledger with an
authenticated next-epoch ledger/frontier; a caller explicitly bound to the old
epoch is rejected with `ReplayEpochMismatch`.

Single-node retirement existed before this candidate. The missing composition was
cluster ordering: retiring one node locally before its peers would create
incompatible replay authority.

## Authoritative state

Application schema 5 adds `State.replay_epoch: u64`, defaulting to zero for old
serialized states. It is omitted from canonical JSON only when zero so historical
schema-1 through schema-4 bytes remain unchanged. `State::validate_format`
forbids a nonzero replay epoch on schema <5.

On unseal, the server compares application-state epoch with the authenticated
durable ledger epoch:

- equal: admit normally;
- application state ahead of durable authority: fail closed;
- durable epoch ahead of application state: this is the recoverable legacy or
  interrupted-local-retirement condition. Normalize the in-memory state upward
  and rewrite the state format before the node can be treated as converged.

The normalization is one-way. No path decrements an epoch.

## Ordinary mutation

For a normal state publication, target `State.replay_epoch` must equal the local
durable epoch. Before any HA proposal, `preflight_new_identity()` proves that the
current detailed ledger has capacity. Known saturation therefore returns before
a new Raft effect.

## Epoch transition

`POST|PUT /v1/sys/storage/raft/replay-retire` requires an authenticated root
principal in the root namespace and an empty object. The server:

1. verifies application and durable epochs are equal;
2. computes exactly `current + 1`; overflow fails closed;
3. creates the next application state with schema 5 and the new epoch;
4. in HA, proposes that complete state through the existing linearizable Raft
   state transition; on a single node, proceeds directly to local persistence;
5. immediately before publishing the local state batch, advances local durable
   replay authority one authenticated epoch at a time until it equals the target;
   the active leader's own transition is exactly one step, while an offline
   follower may perform several crash-durable local retirements during catch-up;
6. publishes the state chunks/manifest under the resulting durable epoch;
7. updates the in-memory state only after the complete path succeeds.

Unlike an ordinary mutation, step 4 is allowed while the detailed ledger is full:
retirement is the authenticated capacity escape hatch itself. Client-originated
retirement still advances exactly one cluster epoch. Old-epoch writes and a target
epoch that does not match the resulting durable authority are rejected.

## Follower catch-up

A follower learns the same schema-5 state through the existing committed Raft
state. `sync_from_ha()` validates the cluster ID and state schema, then calls the
same `persist_local()` path. If the follower was offline across several committed
retirements, it advances its local durable replay epoch repeatedly until the
authenticated local epoch equals the committed target, then publishes that state.
The node processed no requests in those skipped epochs, so it has no intermediate
local request identities to preserve. Every local retirement is individually
crash-durable; restart resumes from the authenticated durable epoch rather than
deleting or resetting the ledger by hand.

A target behind local durable authority is still rejected. A client cannot request
an arbitrary cluster jump: the leader route computes only `current + 1`. The
multi-step path exists solely while applying an already committed HA state.

## Failure ordering

The critical local crash window is:

```
authenticated next replay ledger published
    -> application state batch publication
```

If the first effect succeeds and the second fails, the node has advanced replay
authority without yet publishing matching application metadata. The server marks
itself recovery-required even when the durable store itself is not otherwise
fenced. It must not continue from cached old application state. Restart performs
the one-way normalization described above; an HA node may instead catch up to the
already committed state.

If retirement fails before its authenticated epoch publication, the state batch
is not entered. If a later durable state batch has unknown outcome, existing
reconciliation/fencing rules remain authoritative; no blind retry is introduced.

## Capacity and observability

The capacity endpoint reports current epoch and retired generation frontier. It
labels retirement `local-epoch` for a non-HA server and `raft-coordinated` for the
HA composition. `replay_id_eviction` stays false because normal compaction is not
retirement and no implicit FIFO eviction exists.

## Executable evidence

Native server tests cover:

- root-only retirement and a normal mutation after retirement;
- retirement while a deliberately one-record active ledger is full;
- restart preserving application and durable epoch;
- follower-style application of a committed next-epoch state;
- follower-style catch-up across multiple retired epochs without manual ledger reset;
- fencing when retirement publishes but the following state request is rejected.

`heptabao-durable-service` tests additionally cover authenticated frontier
encoding, stale-epoch refusal, retirement crash windows and backup/restore.

Replacement admission still requires a current exact-head multi-process fixture
that crosses the retirement boundary under leader change, network partition/heal,
snapshot and more than 32,000 logical operations. Source presence is not that
receipt.
