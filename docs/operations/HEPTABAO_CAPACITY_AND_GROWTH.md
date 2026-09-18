# Capacity observation, admission and growth

Current plan: `HEPTABAO-PLAN-2026-09-07-V2.1`. This is a concrete runtime contract
and unresolved scalability exit, not a new plan or a production-capacity claim.

## Real owner and interface

The running Service owns one logical serialized `State` containing Auth, Identity,
KV, Transit, PKI, SSH, wrappers, local leases, PostgreSQL intents and Raft-admin
state. The durable representation is no longer one 768 KiB value. Current local
storage uses the `heptabao-state-chunks-v3` content-addressed manifest and
deterministic content-defined boundaries: chunks are at least **384 KiB**, target
**512 KiB**, and are capped at **768 KiB** except the final short chunk. New chunks,
retired chunk references and the manifest publication point are committed through
one durable atomic batch. The shared serialized-state admission bound is
**16 MiB**, and HA replication uses that same bound with its own chunk framing. A
point mutation can still clone/serialize the complete logical state, so this is
bounded physical chunk reuse rather than record-oriented scalability.

The active replay ledger admits at most **32,000 identities per epoch**. A
root-authorized replay retirement operation creates a durable authenticated
generation frontier, advances the replay epoch, checkpoints the journal and
allows new identities without making retired requests fresh again. In HA, the
leader first orders the next epoch through Raft; each voter advances its local
durable replay owner before publishing application state for that committed epoch.
A follower that was offline across several already-committed retirements advances
through each missing local epoch during authoritative catch-up; ordinary local
writes remain unable to skip epochs. Each underlying durable file/journal is
bounded to **64 MiB**; request parsing bounds are separate from state capacity.

`GET /v1/sys/internal/capacity` accepts an empty request object and reports:

| Field | Meaning |
|---|---|
| `state_bytes`, `state_limit_bytes`, `state_remaining_bytes` | Current serialized logical application payload and 16 MiB hard bound. |
| `state_storage_format`, `state_chunk_target_bytes` | Exact current local state framing identity (`heptabao-state-chunks-v3`) and 512 KiB target chunk size; these are diagnostics, not a compatibility promise. |
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

`system/state` may contain either a historical serialized `State` record, a V1
alternating-slot manifest, a V2 fixed content-addressed manifest, or the current
V3 content-defined manifest. A V3 writer hashes each chosen chunk, reuses existing
content-addressed chunks when their digest is still referenced, creates only new
chunks, deletes replaced previous-generation chunk resources and publishes the new
manifest in the same `DurableService::apply_batch` binding. The manifest is the
sole logical publication point, so one state transition consumes one replay
identity and one durable generation. A reader accepts only a complete manifest
whose version-specific chunk shape, state schema, total length and SHA-256 binding
verify.

On unseal, a valid legacy state or older manifest is decoded before the next
mutation promotes it through the current atomic publication path. Malformed
manifests, missing chunks, digest mismatches or indeterminate publication outcomes
never fall back to an older representation by guesswork. Fresh initialization and
HA catch-up use the same state publication path.

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
In single-node mode it compacts first, commits a new replay epoch and authenticated
retired-through generation, checkpoints that state, and returns the previous and
current epoch plus retired counts. Restart, crash-window and encrypted
backup/restore tests verify that requests from the retired epoch remain rejected.

When HA is enabled the route performs a quorum-ordered transition: the leader
commits the next epoch as authoritative Raft application state, and local durable
replay owners retire before that epoch is published on each node. Normal requests
cannot manufacture an epoch jump. Authoritative catch-up may advance a stale node
through multiple already-committed epochs, one local retirement at a time, so a
node that missed several transitions can rejoin without weakening the replay
frontier. Repository-controlled tests exercise repeated retirement and leadership
change; snapshot-install, directed-partition, disk/power-fault, mixed-version and
multi-host qualification remain separate exits.

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
the dataset grows. The implemented HA replay-epoch protocol still requires the
fault, snapshot, upgrade and multi-host qualification cases listed below.

Before admission, exercise total datasets materially above the legacy ceiling,
long write histories beyond one replay epoch, leader/follower catch-up,
snapshot/backup/restore, disk-full/torn-write/fsync faults, stale-node rejoin,
rolling restart and supported mixed-version behavior. The current
`capacity_live.py` profile records per-write logical-state bytes, durable
data-directory bytes, process write bytes, write latency and Linux RSS observations,
and derives throughput, p50/p95/p99 latency and physical write-amplification curves.
It also measures startup plus unseal/load recovery at both the small initial state
and the near-capacity state, yielding a source-bound recovery-cost curve instead of
one final restart anecdote. Those measurements expose growth/write-amplification,
memory, latency, disk and recovery trends for the bounded whole-state implementation;
they do not convert it into a record-oriented scale claim. Production admission
still requires repeatable curves on representative multi-host hardware and larger
datasets under a storage architecture that is not constrained by whole-state
serialization. Do not
raise constants and infer scalability from a small happy-path fixture.

The same precedence applies after an observed external provider effect: final
local publication failure preserves pending reconciliation state and returns
reconcile-only 503, not a new-attempt capacity rejection.
