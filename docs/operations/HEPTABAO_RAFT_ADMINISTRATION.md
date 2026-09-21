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

Each configured HA peer may include `api_address`, an absolute HTTPS origin for
that node's HTTP listener, such as `https://bao-1.example:8200`. Paths, query
strings, credentials and fragments are rejected. `sys/leader.leader_address`
reports only this explicit address for the locally observed leader; missing
configuration or an unknown leader omits the field. Raft transport addresses are never
substituted for HTTP addresses. Native snapshot requests on an unsealed standby
now return307 with this configured origin and the validated original path/query.
They do not consume token uses, read the upload or allocate a spool. Missing API
address, unknown leader, sealed state or an elapsed admission deadline returns503.
The receiving leader still authorizes the request and passes ReadIndex before
releasing its staged archive. The `0b31fb2` release passes the
[162-check redirect profile](../../qa/openbao-acceptance/evidence/native-redirect-0b31fb2.json):
three TLS voters return empty307 replies for GET/HEAD and upload headers, retain
the raw validated query and token uses, and change the destination after leadership
transfer. Resolving the configured leader first permits one official CLI SAVE
and one RESTORE; complete value hashes survive every voter and restart. A separate
deliberate mutation/restore observes the next replay epoch. This does not claim
automatic CLI redirect replay, missing-address behavior or separate physical hosts.
Schema39 native HA
restore publishes a new same-cluster/same-seal record root at the live epoch plus
one; it does not rewind the local ledger, Raft log or membership. Complete
closure/capacity preflight precedes Stage, and uncertain publication outcomes
require recovery. The first profile requires a root actor and unchanged Raft
administration state, discards imported OIDC pending sessions and rejects external
database/OpenLDAP secret state. Its separate real-process qualification is pending.
JSON backup keeps its separate behavior.

The [68-check restore fault profile](../../qa/openbao-acceptance/evidence/native-ha-fault-0b31fb2.json)
uses the unchanged `0b31fb2` release and three TLS voters. Killing the serving
leader with one archive byte withheld preserves live KV values and the ACL owner.
A separate complete upload deliberately reads no response; authenticated reads
through a survivor must first prove the archived values and ACL restored before
the serving leader is killed. Both phases verify every voter, a complete restart
and a new write/save, without retrying a mutation. These are incomplete-upload
and client-uncertainty tests, not exact post-Stage or commit-before-local-persist
crash windows, physical power loss or separate hosts.

A terminal native-upload admission rejection now drains valid remaining body
framing outside the Service writer before sending its response. The decoder's
size/chunk limits and original connection deadline still apply; no archive is
parsed or staged and no application operation is retried. Download and redirect
paths do not drain. This addresses complete uploads losing their refusal when
the connection closes with unread request bytes; incomplete or slow uploads,
earlier parse/rate-limit failures and expired connection budgets remain outside
that response-delivery guarantee. The `0b31fb2` release passes the
[22-check single-node rejection profile](../../qa/openbao-acceptance/evidence/native-snapshot-rejection-0b31fb2.json):
the official CLI and independent length/chunked uploads each receive a complete403,
while generation and every stored value hash remain unchanged. The earlier
`24c2e74` failed receipts are retained on the SSD; server-side403 audit records
were not accepted in place of a delivered HTTP response.

The pinned OpenBao2.6.2 CLI has an independently reproduced redirect limitation:
its snapshot client discards the second response, and restore does not rewind
the original file body. A [small TLS transport observation](../../qa/openbao-acceptance/evidence/official-snapshot-cli-redirect-observation.json)
records successful direct SAVE/RESTORE and failed transfers after a single307.
This uses a synthetic175-byte archive and does not qualify server restore or
archive authentication. Resolve the anonymous `sys/leader` address first and
submit the CLI command directly to that leader once; do not blindly retry an
uncertain restore. Server307 support does not claim transparent CLI replay.

`sys/leader` now follows the dedicated public GET diagnostic path. It answers
locally on a standby without authentication, token-use consumption, wrapping,
audit writes, HA forwarding or application catch-up. A non-HA server returns only
`ha_enabled:false`, including before initialization or while sealed; a sealed HA
node returns503. Other methods return405, including HEAD. Local committed/applied
Raft indices and leader identity come from one passive metrics observation.
False/unknown optional fields are omitted. These diagnostics never grant read or
write authority; protected operations retain their ReadIndex checks. `active_time`
and `leader_cluster_address` remain unimplemented rather than fabricated. The
schema39 [78-check live profile](../../qa/openbao-acceptance/evidence/sys-leader-24c2e74.json)
compares the official file/Raft lifecycle and exercises three TLS candidate
processes, finite-use preservation, seal/restart, loss of quorum and leadership
transfer. A diagnostic remains available during a partition while a protected
read fails. The HTTP parser now retains the dedicated handler's original method,
ignores logical body/header fields and checks only the global GET list/scan
selectors using Go's first-valid-query-value behavior. Conflicting true selectors
or invalid booleans return400 with an empty errors list; framing and deadline
limits remain. The [186-check expanded comparison](../../qa/openbao-acceptance/evidence/sys-leader-http-0b31fb2.json)
passes on `0b31fb2`, including all35 HTTP edge cases on official file/Raft servers
and the candidate file server, followed by the three-process HA lifecycle.
The exact leader route now admits every nonempty ASCII HTTP-token method so its
dedicated handler can return405 for valid extensions such as OPTIONS and TRACE.
Malformed methods still return400, and other API routes keep their existing
method allowlist. The two omitted fields remain separate compatibility work;
the expanded method matrix awaits its next release-binary live run.
The schema38 [three-process TLS native SAVE receipt](../../qa/openbao-acceptance/evidence/native-snapshot-ha-fa61fa7.json)
passes269 checks with the official2.6.2 CLI and unchanged5-second listeners,
including quorum loss, leadership transfer, HEAD/ACL/finite-use behavior and
full value hashes at every voter. This profile does not qualify HA restore,
anonymous/standby `sys/leader` compatibility, or separate physical hosts.

Replication batches are bounded by encoded bytes as well as entry count.
`DurableLogStore::limited_get_log_entries` returns a contiguous prefix that fits
the unchanged 768 KiB complete RPC limit, reserving the maximum serialized vote
and log-ID metadata. Proposal admission rejects a single unsendable entry before
appending it. This prevents a newly elected leader from repeatedly rejecting its
own large catch-up batch before it can replicate the new-term blank entry.
ReadIndex covers both quorum confirmation and application of its required log;
the runtime bounds that complete wait at eight seconds and accepts a shorter
caller budget. Timeout grants no read and does not retry a write.
The HTTP listener now propagates its original absolute deadline through Service
HA lock acquisition, forwarding and nested ReadIndex checks. Waiting for an HA
mutex or starting a second authority check does not reset the budget. Request
scope is restored on return or unwind and is not inherited by Raft background
tasks. This bounds read admission; it does not cancel a filesystem operation,
provider side effect or write whose commit outcome still needs reconciliation.
The [29-check listener deadline receipt](../../qa/openbao-acceptance/evidence/ha-request-deadline-248e9bd.json)
stops both follower processes while leaving the leader running. A direct read
returns503; twelve delayed-body concurrent reads yield nine actual503 responses
and three separately recorded pre-response EOFs, with a maximum elapsed5003.4ms.
The healthy delayed-body control succeeds, and recovery checks one CAS write
and the exact new value through every voter. The original listener budget is5s;
the observer allows750ms of scheduling slack. This loaded same-host run does
not claim that EOF is an HTTP503 or that writes can be canceled at the deadline.

The `0adfc0d` release binary (`40eacb3fdc897cca44df381dac49d2273c66548ba440f50c6a7e07c602a23dfa`)
passes the [913-check 32 MiB KV1 HA profile](../../qa/openbao-acceptance/evidence/kv1-record-ha32-0adfc0d.json).
It writes 147 distinct large values, purges logs beyond an offline voter's
frontier, observes the installed record snapshot, transfers authority to that
voter, and verifies every value by authenticated HTTP. It also covers edits,
deletion, leader crash, complete process restart, quorum loss and recovery with
the original five-second listener deadline. The unchanged clean source and
binary are recorded before and after execution. This is same-version local
three-process evidence, not a cross-host power-loss or mixed-version qualification.
The same binary passes the [57-check native JSON backup restore profile](../../qa/openbao-acceptance/evidence/kv1-record-backup-0adfc0d.json),
including complete value/other-owner checks after restore and restart. That
receipt does not test the large-transfer limit or physically interrupt restore.
Its [61-check PostgreSQL backup profile](../../qa/openbao-acceptance/evidence/kv1-record-backup-pg-0adfc0d.json)
repeats those checks against PostgreSQL 17 with an unprivileged storage role,
verifies one remote manifest and encrypted remote chunks, and confirms that no
local storage fallback was used. It retains the same JSON transfer and local
server scope; it does not qualify PostgreSQL outages or native gzip transfer.

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
