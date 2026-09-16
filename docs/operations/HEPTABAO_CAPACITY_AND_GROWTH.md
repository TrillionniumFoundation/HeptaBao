# Capacity observation, replay epochs and growth

Current plan: `HEPTABAO-PLAN-2026-09-07-V2.1`. This document describes the
actual bounded runtime on the current source. It is an operational contract, not
a production-capacity or OpenBao-replacement claim.

## Real owner and state format

The running `Service` owns one logical application `State`, but current local
durability no longer stores that state as one 768 KiB record. Schema-5 state is
serialized with a **16 MiB** hard bound, split into **512 KiB** chunks, and
published through a versioned `heptabao-state-chunks-v1` manifest. All chunks
and the manifest for one logical publication are submitted through one
`DurableService` atomic batch, so readers see either the previous complete state
or the new complete state. Legacy unchunked state is admitted only after strict
validation and is rewritten through the same batch path during unseal.

This is still an aggregate logical-state design. A mutation can serialize the
whole `State`; Auth, Identity, engines, provider intents and Raft-admin metadata
remain members of that object. The current HA codec is a separate, tighter
boundary: `heptabao-server::ha_state` admits at most **768 KiB** of plaintext
application state per replicated proposal and the Raft envelope is bounded
accordingly. Therefore a configuration can fit local 16 MiB durability while
being too large to enter HA. The API reports the local state bound and must not
be read as an HA admission promise.

The durable journal/file safety bound remains **64 MiB** and the active replay
ledger is bounded to **32,000 identities per replay epoch** in the server profile.

## Capacity interface

`GET /v1/sys/internal/storage/capacity` follows the normal audited Service path,
requires the root principal in the root namespace, and reports metadata only:

| Field | Meaning |
|---|---|
| `state_bytes`, `state_limit_bytes`, `state_remaining_bytes` | Local logical committed state usage and the 16 MiB local bound. |
| `retained_requests`, `request_limit`, `requests_remaining` | Detailed identities in the current replay epoch and the active-epoch bound. |
| `journal_bytes`, `journal_limit_bytes` | Current authenticated journal usage and hard bound. |
| `generation` | Local durable generation; not a cluster reservation. |
| `replay_epoch` | Current authenticated replay epoch. |
| `retired_through_generation` | Highest durable generation covered by the retired-epoch frontier. |
| `replay_retirement` | `local-epoch` on a single node; `raft-coordinated` when HA is composed by this candidate. |
| `replay_id_eviction` | False. Ordinary compaction never silently discards active replay identities. |

The response contains no tenant path, token, key, credential, request ID or
secret plaintext. Sealed/recovery-fenced instances reject the observation. In HA
the values are the serving node's local durable counters, not a sum over replicas.

## Before-entry capacity and retry rules

`DurableService::preflight_new_identity` refuses a known-full active replay
ledger before an ordinary new state effect is proposed to Raft. Journal capacity
has one narrowly scoped recovery path: a proven pre-entry
`JournalCapacityExhausted` may checkpoint authenticated state and retry the exact
same bound envelope once. `OutcomeUnknown`, corruption, I/O failure, binding
conflict and detailed-ledger exhaustion never enter a blind retry loop.

A replay-epoch transition is different from an ordinary mutation. It is the
explicit authenticated escape from a full detailed ledger and therefore may be
proposed when `preflight_new_identity` is full. The current candidate records the
next `replay_epoch` in authoritative application state. In HA that state marker is
Raft-committed first; each node, when applying that committed state, retires its
local detailed ledger to the same next epoch immediately before publishing the
new local state batch. Epoch jumps, rollback to an older epoch, or an application
state ahead of durable replay authority fail closed.

If local epoch retirement succeeds but the following state publication fails,
the node is recovery-fenced even when the underlying durable primitive can still
answer reads. Restart normalization or committed HA catch-up is required before
serving again. This prevents a node from continuing with mismatched application
and replay authority.

## Replay retirement evidence and remaining qualification

`sys/storage/raft/replay-retire` is root-only and accepts an empty POST/PUT body.
It returns the previous/current epoch, retired generation frontier and retired
request count. Single-node restart preserves the epoch; the same state transition
is consumable by the follower catch-up path. Source tests cover a deliberately
full one-record ledger, restart, follower-style apply and the post-retirement
publication-failure fence. `heptabao-durable-service` separately covers retirement
crash windows, backup/restore and explicit stale-epoch rejection.

This implementation removes the old *permanent* 32,000-record lifetime model,
but replacement admission remains open until current exact-source execution also
demonstrates more than 32,000 logical operations, real multi-process leader and
follower retirement, partition/heal, snapshot/catch-up and recovery across the
epoch boundary. Historical or model-only passes do not satisfy that gate.

## Scalable-storage exit still required

Chunking and replay epochs address concrete boundedness defects; they do not make
the storage architecture record-oriented. Local point mutations can still
serialize and hash the entire logical state, HA currently replicates a complete
state image, and the 768 KiB HA codec is smaller than the local 16 MiB format.
Complete replacement therefore still requires either record ownership with
atomic multi-record manifests or another implementation whose write amplification,
peak memory, snapshot/catch-up behavior and failure recovery are demonstrated to
scale with real production-sized data.

Admission must exercise large object counts and histories, data materially above
the historical 768 KiB boundary, leader/follower catch-up, authenticated streaming
snapshots or equivalent bounded transfer, backup/restore, disk-full/torn-write/
fsync faults, rolling upgrade and measured latency/memory/write amplification.
Raising constants alone is not closure.
