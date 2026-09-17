# Capacity observation, admission and growth

Current plan: `HEPTABAO-PLAN-2026-09-07-V2.1`. This is a concrete runtime contract
and unresolved scalability exit, not a new plan or a production-capacity claim.

## Real owner and interface

The running Service owns one logical serialized `State` containing Auth, Identity,
KV, Transit, PKI, SSH, wrappers, local leases, PostgreSQL intents and Raft-admin
state. The durable representation is no longer one 768 KiB value: a state
publication is split into **512 KiB** immutable chunks plus a versioned
`heptabao-state-chunks-v1` manifest and is committed by one durable atomic batch.
The shared serialized-state admission bound is **16 MiB**, and HA replication uses
that same bound. A point mutation can still serialize and replicate the complete
logical state, so this is bounded chunking rather than record-oriented scalability.

The active replay ledger admits at most **32,000 identities per epoch**. A
root-authorized replay retirement operation advances an authenticated durable
frontier and the schema-5 application `replay_epoch`; retired requests do not
become fresh. In HA mode the next epoch is first ordered as ordinary replicated
application state, and each admitted node advances its local durable replay epoch
immediately before publishing that committed state. The source protocol is present,
but destructive leader-change/partition/snapshot/stale-rejoin qualification across
retirement remains required. Each underlying durable file/journal is bounded to
**64 MiB**; request parsing bounds are separate from state capacity.

`GET /v1/sys/internal/capacity` accepts an empty request object and reports:

| Field | Meaning |
|---|---|
| `state_bytes`, `state_limit_bytes`, `state_remaining_bytes` | Current serialized logical application payload and 16 MiB hard bound. |
| `retained_operations`, `operation_limit`, `operations_remaining` | Active-epoch local durable replay identities and remaining slots. |
| `journal_bytes`, `journal_limit_bytes` | Current local replay journal and configured hard bound. |
| `generation` | Durable committed local generation, not a cluster-wide capacity reservation. |
| `admission_reserved` | Always false: sizes, ciphertext overhead, concurrent activity or I/O may invalidate headroom. |
| `compaction_reclaims_operation_identities` | Always false. Ordinary compaction is not replay retirement. |

Only a root token in the root namespace may enter this diagnostic. Normal request
and result audit remain; sealed state and recovery fencing reject observation. HA
forwarding returns the serving leader's local counters, not a sum or reservation.
No token, key, path, resource name, request identity or credential is returned.
This is a HeptaBao extension, not an OpenBao compatibility surface closure.

## State publication and legacy migration

`system/state` may contain either the historical serialized `State` record or the
current manifest. A writer alternates between two bounded chunk slots. All chunks
for the next state and the new manifest are submitted through one
`DurableService::apply_batch` binding, so one logical state publication consumes
one replay identity and one durable generation. A reader accepts only a complete
manifest whose state schema, chunk count, total length and SHA-256 binding verify.

On unseal, a valid legacy state is decoded before conversion and is rewritten
through the same atomic batch protocol. Malformed manifests, missing chunks,
digest mismatches or indeterminate publication outcomes never fall back to an
older representation by guesswork. Fresh initialization and HA catch-up use the
same state publication path.

## Before-entry capacity handling

`DurableService::preflight_new_identity` rejects a known-full active replay epoch
before `Service::persist` proposes a fresh HA operation. This preflight is not a
future I/O guarantee. Exact duplicates inside the active epoch use their retained
record; identities at or before a retired authenticated frontier remain stale and
cannot be admitted as new work.

The server uses `put_with_compaction`: attempt once, and only on the specific
`JournalCapacityExhausted` result before an intent was appended, create one
existing authenticated checkpoint and attempt that exact envelope once more.
There is no retry loop. `OutcomeUnknown`, corruption, I/O failure, binding conflict
and full active-epoch capacity never trigger retry. A checkpoint publication
failure fences the Service when it fences its durable owner.

Before-HA-publication state or identity capacity refusal returns HTTP 507. Once
Raft has committed an effect, any local persistence failure instead returns 503,
fences the Service and preserves its recovery reference. It cannot be relabelled
as a safe before-entry failure. Unknown effects never release requested secret
material or become automatic retries.

## Replay retirement

`POST`/`PUT /v1/sys/storage/raft/replay-retire` with an empty object is root-only.
It requires application and durable epochs to agree, advances exactly one epoch,
and returns the previous/current epoch plus retired counts. In single-node mode the
transition is local. In HA mode the schema-5 epoch marker is committed through the
existing Raft state transition before the local detailed replay ledger is retired;
follower catch-up uses the same durable state-publication path. A node cannot jump
multiple epochs, and a crash after durable retirement but before matching state
publication fences the process for restart normalization or HA catch-up.

This closes the previous source-level `409` placeholder; it does **not** by itself
close replacement admission. The exact candidate still needs a destructive
multi-process fixture that crosses retirement under leader loss, partition/heal,
snapshot install, stale-node rejoin and more than 32,000 logical operations while
proving delayed old-epoch traffic remains rejected.

## Executable evidence

Current source anchors include:

- `crates/heptabao-server/src/service_state_store.rs` for manifest/chunk framing,
  shared 16 MiB admission and legacy-state assembly;
- `crates/heptabao-server/src/ha_state.rs` for authenticated HA replication using
  the same serialized-state bound, including a >768 KiB round trip;
- `crates/heptabao-durable-service/src/capacity.rs` for replay retirement restart,
  crash-window and backup/restore tests;
- `crates/heptabao-server/src/service_capacity_tests.rs` for root-only retirement
  and continued state commits in the new epoch;
- `qa/openbao-acceptance/capacity_live.py` for a real synthetic TLS process.

Commands and source anchors are requirements, not inherited success receipts. The
exact candidate and prospective merge must execute the native gate before they may
be used as admission evidence.

## Scalable-storage and HA lifecycle exits still required

Chunking removes the obsolete single-value 768 KiB ceiling but does not remove
whole-state serialization or whole-state Raft proposals. Production-scale closure
still requires record ownership or another demonstrated architecture whose write
amplification, peak memory, snapshot streaming and recovery cost remain bounded as
the dataset grows. The HA replay-epoch protocol now exists in source; its destructive
multi-process and long-history qualification remains a separate admission exit.

Before admission, exercise total datasets materially above the legacy ceiling,
long write histories beyond one replay epoch, leader/follower catch-up,
snapshot/backup/restore, disk-full/torn-write/fsync faults, stale-node rejoin,
rolling restart and supported mixed-version behavior. Record peak memory, bytes
written per mutation, throughput and tail latency versus total stored bytes. Do
not raise constants and infer scalability from a small happy-path fixture.

The same precedence applies after an observed external provider effect: final
local publication failure preserves pending reconciliation state and returns
reconcile-only 503, not a new-attempt capacity rejection.
