# Capacity observation, admission and growth

Current plan: `HEPTABAO-PLAN-2026-09-07-V2.1`. This is a concrete runtime contract
and unresolved scalability exit, not a new plan or a production-capacity claim.

## Real owner and interface

The Service remains the sole application authority. Schema36 adds a KV1 record
path: `state_records` holds immutable value blocks and ordered index pages, while
`heptabao-state-records-v5` binds that graph and five opaque owners. Constructing and applying an ordinary KV1 delta
encodes the changed value/index path and any changed opaque owner. Raft snapshots,
local durable checkpoints, initial migration, cold HA catch-up and periodic garbage
collection still perform whole-state or whole-graph work; a public write that triggers
maintenance can pay that cost. Raft snapshots currently trigger every 128 log entries,
not every 128 KV writes. KV2, Auth/provider state, Identity, Transit, PKI, SSH,
wrappers, leases and database/Raft administration remain in opaque JSON owners.

The budgets are independent:

| Boundary | Enforced limit and meaning |
|---|---|
| Logical components | Opaque owners total 16MiB; KV1 conservative encoded graph 64MiB, including repeated references; individual canonical value 16MiB. The normal HTTP request limit remains 256KiB. |
| Local durability | Existing 64MiB artifact/journal limits and 32,000 replay identities per epoch. Immutable-publication preflight includes the cumulative staged peak, final root, ciphertext/framing and replay records before HA submission. |
| HA | Typed application data has a 47MiB encoded budget and at most 131,072 objects; the existing 128MiB complete-snapshot ceiling is not raised. Sealed/encoded objects and retained Raft data can reject earlier than a logical component bound. |

The sum of logical component ceilings is **not 80MiB of usable storage**. Shared
content, index metadata, encryption, retained operations and staging determine
actual admission. A diagnostic remainder is not an allocation reservation.

Legacy V4 stores retain their 16MiB whole-State bound and HBSM4 owner-bound
whole-image replication until an ordinary logical mutation explicitly converts
its real candidate. Pure read/reopen does not perform this conversion. V1–V3
and HBSR1/HBSM2/HBSM3 remain explicit legacy decoding/migration paths; malformed
or incomplete current state never falls back to them. HBSR1 still requires the
explicit owner migration before a V5 transition.

Migration needs room for the old authoritative state and new immutable objects
at the same time. The legacy double-slot HA layout can exhaust the 47MiB staging
budget even when the final V5 graph would fit. The V5 transition now authenticates
the complete HBSM4 manifest and active chunks before a Raft-ordered, exact-status
CAS removes only inactive canonical slots. A persistent preparation marker fences
all subsequent legacy production writes; a completed compact checkpoint and fresh
leader/ReadIndex verification precede typed staging. Reads alone do not start
this transition. Once preparation commits, recovery/retry requires the current
binary; mixed old/new writers and rollback to schema35 are unsupported.

Real near-limit old-binary migration still requires its dedicated live receipt;
a small upgrade profile cannot qualify that boundary. Dense small-record states
can exceed 47MiB even with only the active old slots and need a separate bounded
migration design. No existing limit is raised to hide this staging peak.

The source-bound limits below distinguish legacy layout constraints from V5
component constraints. They do not replace the tighter durable/HA admission
checks above; no row is a reservation or a measured capacity result.

| Layout | Source constant | Enforced value | Scope |
|---|---|---|---|
| Shared | `server::MAX_APPLICATION_STATE_BYTES` | 16 MiB | V4 whole serialized State; V5 aggregate opaque-owner JSON, excluding KV1 records. |
| V4 legacy | `service_owner_store::STATE_STORAGE_FORMAT` | `heptabao-state-owners-v4` | Legacy owner-manifest discriminator, retained for reopen and explicit transition. |
| V4 legacy | `service_owner_store::STATE_CHUNK_BYTES` | 512 KiB | Content-defined owner chunk target. |
| V4 legacy | `service_owner_store::STATE_CHUNK_MIN_BYTES` | 384 KiB | Minimum content-defined boundary; final owner chunk may be shorter. |
| V4 legacy | `service_owner_store::STATE_CHUNK_MAX_BYTES` | 768 KiB | Maximum content-defined owner chunk. |
| V5 records | `state_record_root::STORAGE_FORMAT` | `heptabao-state-records-v5` | Current typed publication root discriminator. |
| V5 records | `state_record_root::MAX_ROOT_BYTES` | 64 KiB | Canonical serialized publication root. |
| V5 records | `state_record_root::OWNER_CHUNK_BYTES` | 256 KiB | Opaque-owner chunk payload. |
| V5 records | `state_records::BLOCK_BYTES` | 256 KiB | KV1 value block payload. |
| V5 records | `state_records::PAGE_BYTES` | 32 KiB | Encoded index page bound. |
| V5 records | `state_records::MAX_VALUE_BYTES` | 16 MiB | One canonical KV1 value; HTTP request admission remains separately tighter. |
| V5 records | `state_records::MAX_GRAPH_BYTES` | 64 MiB | Conservative encoded KV1 graph count, including repeated references. |

Stable HBSM4 reads can reuse fully verified state after a fresh ReadIndex and
manifest authentication, bound to unchanged Raft and local durable generations.
In the same-host three-process development fixture, 24 reads of one small KV
value at each state size produced these median latencies:

| Logical state bytes | Before reuse | With reuse |
|---|---:|---:|
| 920,099 | 52.723 ms | 5.371 ms |
| 3,676,235 | 197.561 ms | 5.343 ms |
| 9,188,507 | 480.396 ms | 5.598 ms |

The [baseline receipt](../../qa/openbao-acceptance/evidence/ha-read-baseline-5c6aa90.json)
and [reuse receipt](../../qa/openbao-acceptance/evidence/ha-read-cached-7c10621.json)
bind the same measurement runner and exact source/binary observations. Each
point also checked that reads left durable counters unchanged. These are scoped
development measurements, not a multi-host production latency commitment;
they measure the historical V4 path, not the schema 36 KV1 record path.

Transparent sharing of mounts, KV entries and historical payloads also reduced
small-write CPU costs in a separate single-node development-build fixture. With
1,149,819 / 3,907,031 / 9,420,395 logical bytes, twelve CAS writes to one key had
median latencies of 232.096 / 781.095 / 1710.870 ms
[before](../../qa/openbao-acceptance/evidence/kv-write-baseline-ded9dfa.json) and
210.023 / 706.807 / 1451.222 ms
[after](../../qa/openbao-acceptance/evidence/kv-write-cow-6e07000.json).
The same runner retained large history and unrelated mounts, checked exact CAS
versions, and reopened both latest and historical values. Physical write counts
were unchanged; peak RSS did not improve at every size. For that historical V4/KV2 measurement, full serialization,
hashing and changed-owner chunking grow with total state size. These
unoptimized development-build observations do not establish production capacity.

The explicit HA migration endpoint is
`POST` or `PUT /v1/sys/storage/raft/migrate-owner-state` (an empty JSON object
is required). It is root-namespace and root-token only, requires the current
leader, and is idempotent after the committed envelope is already HBSM4 or
HBSM5. HBSM5 returns its typed record digest without calling the legacy-only
whole-state reader. The
route suppresses unrelated lease and wrapping-clock maintenance for that one
request so an HBSR1 image is not rejected before the migration gate runs.
Migration preserves the exact logical bytes and binds the new owner manifest to
the committed HBSR1 digest; it does not upgrade application schema or grant
mixed-version, rolling-upgrade, or production migration authority.

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
| `state_bytes`, `state_limit_bytes`, `state_remaining_bytes` | V4: canonical State bytes/16MiB. V5: opaque-owner JSON plus logical KV1 value JSON, component-sum upper bound and logical headroom only; `state_remaining_is_admission_budget` is false. |
| `state_storage_format`, `state_chunk_target_bytes` | Exact active format: `heptabao-state-owners-v4`/512KiB target or `heptabao-state-records-v5`/256KiB owner chunks. These fields do not infer migration from schema alone. |
| `state_size_basis`, `durable_payload_bytes`, `durable_artifact_limit_bytes` | Distinguish logical measurement from stored resources and the tighter encrypted-artifact admission boundary. |
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

`system/state` is the sole local authority: a legacy State/manifest, V4 owner
manifest, or V5 record root. With V5, up to 95 new immutable objects plus the root
share one 96-mutation batch. Larger migration/catch-up closures stage full bounded
batches first; only the final batch publishes the root. Readers accept no partial
closure, and an uncertain stage/publication outcome retains recovery fencing.
Old schema-35 binaries reject schema 36 and the new root rather than losing record data.

HBSM5 replicates typed Stage/Publish/Prune commands with authenticated object
metadata and sealed bytes. Publication compares a typed legacy/record base.
A follower validates the full committed closure before its local root becomes
authoritative. The explicitly authorized first HA anchor emits the complete
local V5 closure, including after restart; ordinary commits remain deltas.
ReadIndex, namespace/ACL admission, finite-use accounting and audit release rules
are unchanged.

Current readers pin fully materialized immutable graphs. Unreachable local objects
are collected against the current published root every 64 successful writes or on
the first later write after reopen/catch-up. This is scheduled full-closure work,
not a claim that every maintenance request is logarithmic. GC does not reset
replay identities. Once converted, provider and lifecycle commits also retain V5;
KV2/provider payloads have not become independently addressable records.

## Before-entry capacity handling

V5 uses `DurableService::preflight_immutable_publication` to check cumulative
staging/publication bounds without cloning or scanning the full stored values.
Legacy `DurableService::preflight_new_identity` rejects a known-full active replay epoch
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

- `crates/heptabao-server/src/state_records.rs`, `state_record_root.rs` and
  `service_records.rs` for record/index framing, root identity, bounded staging,
  initial anchor closure and interrupted-stage/reopen behavior;
- `crates/heptabao-server/src/service_state_store.rs` for legacy manifest/chunk
  framing and the old 16MiB state-assembly bound;
- `crates/heptabao-server/src/ha_record_codec.rs` and `ha_record_runtime.rs` for
  HBSM5 authenticated objects and typed root publication; `ha_state.rs` retains
  the legacy whole-image framing;
- `crates/heptabao-durable-service/src/capacity.rs` for replay retirement restart,
  crash-window and backup/restore tests;
- `crates/heptabao-server/src/service_capacity_tests.rs` for root-only retirement
  and continued state commits in the new epoch;
- `crates/heptabao-server/src/service_state_store_integration_tests.rs` for
  `large_unchanged_owner_bounds_v4_write_set_to_changed_owner`, which checks
  that a multi-megabyte local V4 update rewrites only the changed owner's
  chunks and the publication manifest;
- `qa/openbao-acceptance/capacity_live.py` for a real synthetic TLS process.

Commands and source anchors are requirements, not inherited success receipts. The
exact candidate and prospective merge must execute the native gate before they may
be used as admission evidence.

## Scalable-storage and HA lifecycle exits still required

Schema36 connects KV1 record ownership through local publication and typed HA
state-machine commands. This source implementation does not establish measured
capacity or qualify its lifecycle. KV2 and the remaining opaque owners still have
whole-owner serialization costs. Record growth, periodic GC, peak memory, snapshot
encoding and recovery must be measured together with the HA replay-epoch and
fault/upgrade cases below.

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
memory, latency, disk and recovery trends for the historical whole-state profile;
they are not receipts for the new KV1 record implementation. Production admission
still requires repeatable curves on representative multi-host hardware and larger
datasets under a storage architecture that is not constrained by whole-state
serialization. Do not
raise constants and infer scalability from a small happy-path fixture.

The same precedence applies after an observed external provider effect: final
local publication failure preserves pending reconciliation state and returns
reconcile-only 503, not a new-attempt capacity rejection.

## Immutable KV read cost and runtime counter

Eligible unlimited-token KV GET/LIST/SCAN operations borrow shared authoritative
state and use the corresponding `engines/kv.rs` or `engines/kv1_records.rs`
immutable handlers. They do not clone the EngineState,
serialize the complete State, advance a generation or allocate replay identities.
Ordered KV listing seeks from the cursor and skips emitted shallow subtrees.
Live token/parent/Identity/namespace/ACL checks, ReadIndex and both audits remain;
finite-use tokens, wrapping and local lease reconciliation use the transactional
path. Empty lifecycle work is detected before owner cloning.

`kv_read_only_dispatches` in the root-only capacity response is a saturating
process-local count of immutable-branch requests, including authorization denials,
not a successful-read counter. It resets on restart and is deliberately excluded from
durable-state equality; it is not a compatibility counter or a persisted promise.
The real TLS profile `qa/openbao-acceptance/kv_read_scaling_live.py` verifies
unchanged generation, replay and journal bytes plus both audit records per read
while growing state through three declared points. It reports read latency and
RSS, and repeats a read after SIGKILL/reopen. `--baseline` measures the same workload
without claiming the new dispatch path. Timing is descriptive and sample counts
are explicit; this single-host development fixture cannot grant production scale.

Owner-level sharing and immutable reads are distinct from the V5 KV1 write path.
Neither removes component/local/HA admission bounds, opaque-owner write costs,
or the remaining long-horizon HA/fault exits.

The explicit JSON/base64 manual backup profile retains its 20MiB decoded limit.
Local Linux servers also support native gzip/tar transfer: GET/HEAD defaults to
`application/gzip`; `Accept: application/json` selects the JSON profile. POST/PUT
with a JSON content type retain JSON restore; other snapshot uploads accept the
native archive with a fixed length or strictly bounded chunked framing. Native
archives are limited to 131MiB compressed, containing at most 130MiB of HBB2
state. Authentication and finite-use admission precede reading the large body.

The archive explicitly identifies HeptaBao's encrypted HBB2 state. Its four
canonical tar members include independently authenticated sealed checksums;
this is not OpenBao's state or seal encoding. Native HA transfer returns409,
and force restore still requires the same barrier. OpenBao archive migration,
cross-seal restore and non-Linux native transfer remain unimplemented.
Explicit JSON HA export and Raft's internal snapshot replication are separate.

Each Service admits one native transfer. Upload and gzip construction run outside
the Service writer, using immediately unlinked descriptor-backed files below
the configured data directory. Finalization rechecks the original deadline,
live actor, activation and exact state identity before publishing or releasing a
download. The staged archive and extracted state can use up to261MiB of disk,
plus the existing restore transaction's old/new copies. There is no disk-space
reservation; whole-component authentication still needs bounded component memory.
The real official-CLI qualification command is
`native_snapshot_cli_live.py --binary <server> --build-source-commit <commit> --work-parent <private-SSD-directory> --output <new-private-json>`;
the source/binary-bound receipt, not these limits, determines measured capacity.

The schema36 `a6d4664` build (binary SHA256
`ccc2e1809f397a652864eccbe90fd4020c9149e3c57d0dcbe50c74a6cc34ad80`)
passed the [76-check actual schema35 local upgrade](../../qa/openbao-acceptance/evidence/kv1-records-upgrade-a6d4664.json)
and [20-cluster/75-API-check userpass HA profile](../../qa/openbao-acceptance/evidence/userpass-native-ha-a6d4664.json).
These qualify only the named paths. The initial 32MiB local run passed its 618
business checks but failed the end-of-run source identity check; it is not accepted
as capacity evidence. A repeat now retains both source observations and their
exact differing fields. The [clean 618-check repeat](../../qa/openbao-acceptance/evidence/kv1-record-scale32-e554136.json)
passed on `e554136` with the same binary: 33,722,278 logical payload bytes,
147 distinct large values, replacement/deletion and full restart hash checks.
Its three small writes at each size are descriptive observations, not a sustained
performance result. The later [913-check 32MiB HA run](../../qa/openbao-acceptance/evidence/kv1-record-ha32-0adfc0d.json)
qualifies same-version three-process catch-up, failover and restart at that size.
Near-limit historical HA migration, dense small-record growth and independent
host/fault qualification remain separate open work.
