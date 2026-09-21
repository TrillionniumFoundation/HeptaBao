# Raft membership, persisted snapshots and bounded Autopilot

Status: implemented same-version, pre-enrolled development profile with real
multi-process tests. Not full OpenBao Integrated Storage compatibility, arbitrary
node discovery, mixed-version upgrade or independent destructive qualification.

## Owners and persistence

`heptabao-raft-runtime/src/process/admin.rs` uses native Raft membership, committed
configuration, applied frontier, peer replication/contact and persisted snapshots.
`heptabao-server/src/service_raft_admin.rs` owns the encrypted Service Autopilot
policy and requested candidate promotions. Source, transport and durable boundaries
are those of the existing Service/Raft pipeline; configuration text is never itself
a committed membership receipt.

The host enrolls every peer's ID, address and TLS certificate before start. The
optional `initial_voters` selects 3–9 voters from that fixed peer set. An enrolled
peer outside this list starts as a future learner, not an automatic voter. There
is no endpoint that grants a submitted host/address/certificate network authority.
All admin paths require root namespace, a live authenticated principal, operation
capability and sudo. Requests cannot supply arbitrary network destinations, weaken
quorum bounds or bypass policy by setting an unknown force flag.

## Service operations and expected-frontier fence

```text
GET  sys/storage/raft/configuration
POST sys/storage/raft/join
POST sys/storage/raft/promote
POST sys/storage/raft/demote
POST sys/storage/raft/remove-peer
GET  sys/storage/raft/snapshot-status
GET  sys/storage/raft/autopilot/state
GET  sys/storage/raft/autopilot/configuration
POST sys/storage/raft/autopilot/configuration
```

Membership requests bind `server_id` to an enrolled peer and `expected_index` to
the observed committed membership frontier. Join registers a learner; promotion
requires the continuously observed health interval and catch-up to the policy's
applied frontier. Native APIs carry the actual change through consensus, including
joint configuration. Success is returned only after committed and effective
membership agree, the configuration is no longer joint, the desired member state
is observed, and a fresh ReadIndex establishes current authority.

Timeout or inability to observe completion produces an explicit reconcile outcome,
not "nothing changed". Read the current configuration and obtain a new frontier
before another operation. Removing a learner really removes its native node entry;
demoting a voter retains a learner. Removal or demotion may never leave fewer than
three voters. The policy min_quorum may impose a stricter limit. The original
step-down path now selects actual voters rather than any configured peer.

Leadership transfer uses an explicit authenticated peer RPC (wire kind 5).
The receiver binds the request's former leader and recipient to the transport
source and local node before OpenRaft checks its vote and flushed-log frontier.
Without this RPC, the upstream network trait's default only reports unreachable;
waiting for a subsequent election is not evidence that the requested target took
over. A completed transfer still requires a fresh leader/application observation.

Replication batches are bounded by encoded bytes as well as entry count.
`DurableLogStore::limited_get_log_entries` returns a contiguous prefix that fits
the unchanged 768 KiB complete RPC limit, reserving the maximum serialized vote
and log-ID metadata. Proposal admission rejects a single unsendable entry before
appending it. This prevents a newly elected leader from repeatedly rejecting its
own large catch-up batch before it can replicate the new-term blank entry.
ReadIndex covers both quorum confirmation and application of its required log;
the runtime bounds that complete wait at eight seconds and accepts a shorter
caller budget. Timeout grants no read and does not retry a write.

## Snapshots: durable completion, not queue acceptance

A requested native snapshot waits for an appropriate persisted snapshot frontier,
then returns the native snapshot identity, applied index, exact byte count and
SHA-256 of the stored data. Triggering Raft work alone is not a completion result.
A learner joined after prior logs are purged must catch up through Raft's snapshot
installation mechanism; the five-process suite exercises this path.

The local `state-bundle.bin` format now distinguishes legacy version 1 byte-array
snapshots from version 2 canonical, unpadded base64 snapshots. Opening version 1
does not rewrite it; a successful snapshot build or installation publishes version
2. Application schema and Raft snapshot wire payloads are unchanged. Earlier
binaries cannot read version 2, so this is an explicit local rollback boundary.

Both serialization and file reads enforce the same 128 MiB whole-artifact bound,
including the 20-byte checksum/header envelope. Oversized serialization fails
before a temporary file is opened or the previous bundle is replaced. Snapshot
build/install tests verify that rejection preserves the prior bundle, journal,
generation and in-memory state, and that reopening still succeeds. Compact encoding
reduces the nested JSON byte-array expansion; the runtime still materializes the
whole state and snapshot. This does not establish record-oriented storage or prove
that 32 MiB of application data fits the artifact budget.

`raft_membership_live.py --require-compact-snapshots` observes actual version 2
files during learner catch-up after log purge and former-leader restart.
`raft_snapshot_upgrade.py` creates version 1 with a pinned, qualified old binary,
checks unchanged bundle bytes on candidate read-only reopen, explicitly creates
version 2, and tests refused old-binary open without changes anywhere in the Raft
directory. Candidate recovery, writes on every voter, failover and restart follow.
These are actual local process checks, not mixed-version rolling qualification.

Candidate `20a3d68c91dad04ce0216ad0c4b8d063ed56a09a` passes the
[45-check five-process compact snapshot profile](../../qa/openbao-acceptance/evidence/raft-compact-membership-20a3d68.json)
and [13-check actual old-binary upgrade](../../qa/openbao-acceptance/evidence/raft-compact-upgrade-20a3d68.json).
Both bind binary SHA-256 `e35755d580eb3cb277a349b399eae26e0b3d116119c3f1f4ac75cc2b75af0c32`
to the unchanged clean source observed during the run. The old binary pin is
`d26ed9d5c3bfd1cac6c669f7b767c753adc2f823`; no old snapshot was fabricated by
editing a new program's output. These runs do not measure large-state capacity.

The runtime also accepts typed immutable record staging, root publication and
garbage collection commands. A published root fences legacy application writes;
publication checks its prior root and the complete bounded reference graph before
changing application state. Rejected commands advance the applied Raft frontier
without replacing that state. Record snapshots use bundle and wire version 3,
while legacy state keeps the version 1/2 read paths. Record payloads have a 47 MiB
combined encoded budget and retain the 128 MiB complete-artifact bound. Runtime
tests cover journal replay, rejection, snapshot install/reopen and legacy-data
retirement. Schema 36 connects these APIs to server KV1 record publication;
see the [current runtime architecture](../architecture/HEPTABAO_CURRENT_RUNTIME_ARCHITECTURE.md)
and [current capacity contract](HEPTABAO_CAPACITY_AND_GROWTH.md) for its actual
graph, staging and backup limits. Historical receipts below retain their original
scope and do not qualify the newer record path.

The `7baeddb` runtime build (SHA256
`882d8bccf4b25190d3fd36d781ccb5b58d7694bfdb84d853ef1156394114d989`)
passed the same [45-check membership profile](../../qa/openbao-acceptance/evidence/raft-compact-membership-7baeddb.json)
and [13-check actual legacy snapshot upgrade](../../qa/openbao-acceptance/evidence/raft-compact-upgrade-7baeddb.json).
These verify the unchanged legacy application path with the new runtime, not
server publication or capacity of the record format. A separate userpass HA run
exposed a forwarding timeout: password processing exceeded the 500 ms
peer deadline and returned 503 after the mutation committed. The same failure
was reproduced with the preserved schema-35 binary; that historical profile is
not passed. Subsequent forwarding-budget and userpass HA evidence is recorded
with the corresponding newer source/binary identities, not retroactively applied
to this receipt.

The existing Service HTTP snapshot body remains the repository's encrypted backup
format, **not an OpenBao `raft.snap` binary**. Native persisted snapshot status
and learner catch-up do not implement cross-product snapshot restore, forced
restore, disaster recovery with another seal, or mixed-version snapshot formats.
Service restores with database provider records are refused rather than reviving
external credentials from a stale local image.

## Autopilot safety and lifecycle

The current bounded configuration persists cleanup enablement, contact threshold,
maximum trailing logs, min_quorum and server stabilization time. Cleanup defaults
to false. Default contact threshold is 10 seconds, default dead-server threshold
is one day, default min_quorum is 3 and default stable interval is 10 seconds.
Supported bounds: contact 1–60 seconds, dead contact 60–86400 seconds, stable
interval 1–600 seconds, min_quorum 3–9, max trailing logs up to 10000.

Health requires known recent peer contact and bounded native replication lag.
Unknown contact is not proof of a dead peer. Promotion additionally requires a
fresh matched frontier; being reachable alone is insufficient. The advisory
continuous-stability clock resets on term, membership, config or health change.
`stabilized` is reported from those real observations, not from time since an API
request. It is not an independently certified node-health assertion.

The existing lifecycle worker performs at most one guarded consensus transition
per tick. It promotes only requested eligible learners and cleans up only after
explicit enablement plus the full dead-contact grace. A policy change is committed
through Service before external consensus administration. Losing leadership or
quorum blocks further admission. Existing Service/raft persistence, retry/reconcile
and audit boundaries remain in force; no operator safety override is manufactured.

## Operation and verification

Changing static enrollment requires a reviewed host-profile change, not a join
URL. Observe configuration and Autopilot state before and after each transition.
A queued change may have committed despite response loss. Do not assume retry is
safe against an old expected_index, force an unseal, or erase logs to recover.

```sh
cargo test --locked -p heptabao-raft-runtime
python qa/openbao-acceptance/raft_membership_live.py --binary <server> --dead-cleanup --output <new-json>
python qa/openbao-acceptance/ha_network_partition.py --binary <server> --output <new-json>
```

The membership suite starts five real local processes with three initial voters,
persists a snapshot, joins learners, checks stale/unknown-peer rejection, observes
stabilization and catch-up, promotes/demotes/removes native members, verifies real
dead-server grace and cleanup, then checks leader failure and restart. These are
same-binary loopback tests, not five physical hosts or simulated power failures.
ARM64/macOS/Windows, large-state load, physical disk faults, OpenBao binary-format
parity, automatic arbitrary-node challenge enrollment, force restore and rolling
mixed-version upgrade require separate evidence.

The current SSD Linux receipts use the `6cc53a3` candidate binary with digest `eac7867bc9f7b0626b291bce7362eec8eba3a61b02578549e17644e18c4aaf8f`: [`raft-membership-6cc53a3.json`](../../qa/openbao-acceptance/evidence/raft-membership-6cc53a3.json) records 38 native membership scenarios; [`raft-membership-dead-cleanup-6cc53a3.json`](../../qa/openbao-acceptance/evidence/raft-membership-dead-cleanup-6cc53a3.json) records 41 scenarios including dead-voter cleanup. The companion [`ha-network-partition-6cc53a3.json`](../../qa/openbao-acceptance/evidence/ha-network-partition-6cc53a3.json), [`ha-step-down-6cc53a3.json`](../../qa/openbao-acceptance/evidence/ha-step-down-6cc53a3.json) and [`idle-lifecycle-ha-6cc53a3.json`](../../qa/openbao-acceptance/evidence/idle-lifecycle-ha-6cc53a3.json) receipts cover partition fencing, explicit leadership transfer and autonomous expiry after leader loss. They remain same-version loopback evidence and do not grant production or compatibility authority.

### Explicit linearizable read probe

`GET sys/storage/raft/linearizable-read` is a root-scoped diagnostic route. It
first executes the native OpenRaft `ReadIndex` barrier and only then reads the
current term, committed membership frontier and applied index. A successful
`200` response includes `data.linearizable=true` and
`observation_scope=native-raft-ReadIndex`; a lost leader or quorum returns
`503` and no stale success is emitted. The route is an HeptaBao qualification
probe, not an OpenBao compatibility claim, and still requires independent
partition/failover evidence before production authority can be granted.
