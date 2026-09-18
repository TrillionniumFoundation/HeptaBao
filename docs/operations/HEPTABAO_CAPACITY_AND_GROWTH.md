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

The active replay ledger admits at most **32,000 identities per epoch**. In
single-node mode a root-authorized replay retirement operation creates a durable
authenticated generation frontier, advances the replay epoch, checkpoints the
journal and allows new identities without making retired requests fresh again.
In HA mode replay retirement is ordered through Raft: the leader proposes the
next consecutive epoch, followers reject stale or jumping transitions, and local
replay authority is advanced during committed-state catch-up before a lagging
voter can become authoritative. Repository-controlled three-process coverage now
includes repeated retirement and a voter that rejoins after missing multiple
epochs. Snapshot-install, partition/power-loss, mixed-version and physical
multi-host qualification remain open. Each underlying durable file/journal is
bounded to **64 MiB**; request parsing bounds are separate from state capacity.

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
In single-node mode it compacts first, commits a new replay epoch and authenticated
retired-through generation, checkpoints that state, and returns the previous and
current epoch plus retired counts. Restart, crash-window and encrypted
backup/restore tests verify that requests from the retired epoch remain rejected.

When HA is enabled the route uses the Raft-coordinated transition rather than a
node-local retirement. The transition must be exactly +1 from the committed
epoch; stale or jumping requests fail closed. Catch-up reconciles a lagging
voter's local replay authority to the committed epoch before that voter is
permitted to serve authoritative writes. Current repository-controlled evidence
covers leader loss, repeated retirement and a node missing multiple epochs before
rejoin. The remaining replacement blockers are destructive partition/power-loss
windows, forced snapshot installation across epochs, rolling mixed-version
upgrade, sustained histories beyond one 32,000-entry epoch and physical
multi-host qualification.

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
the dataset grows. It also requires the remaining destructive and long-horizon HA replay-epoch qualification above.

Before admission, exercise total datasets materially above the legacy ceiling,
long write histories beyond one replay epoch, leader/follower catch-up,
snapshot/backup/restore, disk-full/torn-write/fsync faults, stale-node rejoin,
rolling restart and supported mixed-version behavior. Record peak memory, bytes
written per mutation, throughput and tail latency versus total stored bytes. Do
not raise constants and infer scalability from a small happy-path fixture.

The same precedence applies after an observed external provider effect: final
local publication failure preserves pending reconciliation state and returns
reconcile-only 503, not a new-attempt capacity rejection.
