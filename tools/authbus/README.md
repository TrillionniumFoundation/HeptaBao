# Independent AuthBus coordinator candidate

`authbus_coordinator.py` is a new, uninstalled credential publisher for the
existing OpenClaw AuthBus inbox, immutable profile, and manifest contracts.
It is independent of J3160. It does not claim to be recovered old coordinator
code, an installed production replacement, or a provider refresh scheduler.

The inspected original `openclaw-authbus` plugin is an event producer and
canonical profile consumer. Its `leader=true` branch can refresh an eligible
OAuth profile and publish a `leader-refresh` inbox event. The plugin has no
inbox merger, immutable profile writer, or manifest CAS publisher. This new
service supplies that credential publication step.

## Authorization and data contract

An owner-controlled configuration fixes one coordinator UUID and the allowed
source host IDs. Each source AppRole may only create its own inbox events;
it has no write permission to the manifest or canonical profiles. Every
credential transition also requires an explicit operator authorization with
all seven fields below:

```json
{
  "authorizationId": "a unique UUID",
  "profileId": "the selected actual profile ID",
  "sourceHost": "the authorized event producer",
  "provider": "the selected provider",
  "identityDigest": "64 hex characters",
  "expectedCurrentDigest": "the current 64-character digest, or null for a new profile",
  "nextDigest": "the exact authorized next credential digest"
}
```

The owner supplies that document in a private file. A source timestamp, a new
inbox event, an unexpired OAuth metadata value, or possession of an inbox
AppRole does not grant rotation authority. The service verifies the full
credential and identity digests, checks that the event host/UUID equals its
actual inbox path, and requires inbox KV version 1. It rejects unresolved
secret references and non-safe-integer credential JSON numbers.

Authorizations reside in the same CAS-protected manifest as the canonical
profile references. Publishing consumes the exact grant in that manifest
CAS. Revoking a pending authorization changes that same version, so a stale
publication attempt must lose CAS. This is a trusted service boundary:
the writer AppRole itself can update the manifest, and server ACLs do not
independently evaluate the JSON authorization rules.

The original plugin's manifest fields remain available. Additional
`coordinator` and `sourceEvent` metadata records provenance without exposing
credential values. A canonical profile key is `sha256-<digest>` over the
**entire canonical profile document**, including profile ID. Two profile IDs
with identical credentials therefore do not collide. Both profiles and
receipts are written with CAS 0 and verified by exact content and version 1.

Receipt identity binds the source host, event UUID, and complete canonical
event digest. Reusing an event ID with a different body cannot silently
replace the earlier event. Agent reports receive a receipt explicitly marked
`observed_no_scheduler_action`. Other control events are retained as
unsupported; this service does not invent scheduling or health decisions.

## Publication, crash recovery, and unknown outcomes

Only one coordinator process/state directory is intended to own publication.
An owner-only `flock` serializes commands using that directory. A private,
fsynced write-ahead journal records the exact event identity, expected
manifest version, next immutable profile reference, desired full manifest,
and intended receipt before any manifest mutation is dispatched.

The ordered commit is:

1. Persist the planned operation and confirm the immutable profile.
2. Persist `manifest_dispatched`, then send one manifest CAS request.
3. Confirm the manifest result, create/read back the immutable receipt, and
   persist a completed operation before removing the pending journal.
4. Confirm the previous committed receipt before accepting the next event.

A known exact CAS conflict permits a later fresh replan. A lost reply or
transport failure after mutation dispatch remains an unknown outcome. The
service does not resend that manifest write. Recovery must read either the
exact current version or the actual KV2 history at `expectedVersion + 1`,
and match the complete desired manifest digest. Pruned, missing, or different
history leaves the operation unknown and blocks subsequent publication.

If a completed private archive was already fsynced before a crash interrupted
pending-file cleanup, recovery compares every operation binding to that
archive and checks the permitted terminal state. A known CAS rejection can
then finish cleanup without pretending it committed. A completed commit also
requires its original immutable remote receipt to still match exactly. An
unrelated archive, or a missing receipt for an archived commit, does not
resolve the pending operation.

`lastReceipt` in the manifest is an additional newest-operation recovery
anchor. It is not used to infer arbitrary old outcomes after later events
have overwritten the newest event. Pending journals and immutable receipts
must be retained in backups. Completed private journals contain credential
digests and references, never access/refresh/API-key values.

Initialization and operator authorization/revocation are single CAS
commands. If their reply is unknown, stop and inspect the exact canonical
state; these administrative commands do not currently have the event
publisher's automatic journal recovery. Initializing an existing manifest
is deliberately refused. Migration of an existing canonical manifest needs
its own reviewed source snapshot and ownership transfer.

## Transport and local custody

The service accepts HTTPS only, verifies the configured CA and hostname,
requires TLS 1.2 or newer, and compares the actual peer DER certificate to
the configured SHA-256 pin on every new connection. AppRole role ID and
Secret ID are read from owner-only regular files. The bearer stays in memory.

Login and renewal lease deadlines are conservatively anchored to request
start, including time spent waiting for the reply. Renewal dispatch uses
the original bearer directly, without recursively ensuring a token or
temporarily extending its accepted deadline. Each HTTP operation checks its
fixed request budget and bearer deadline after connect/pin, before send,
before response headers, and after decoding the bounded response. A mutation
that may have been sent before an error remains unknown.

Configuration, grants, journal files, CA copy, role ID, and Secret ID must
be regular, owner-held mode-0600 files. The existing state directory must be
owner-held mode 0700. The candidate requires `production_cutover: false` and
does not install a service unit, modify an installed plugin/SDK, or delete
existing credentials or backups.

Example private configuration, with literal paths supplied by the operator:

```json
{
  "schema": "heptabao-authbus-coordinator-v1.config",
  "address": "https://127.0.0.1:18200",
  "ca_file": "/owned/fixture/ca.crt",
  "role_id_file": "/owned/fixture/role_id",
  "secret_id_file": "/owned/fixture/secret_id",
  "server_certificate_sha256": "the actual server certificate DER digest",
  "state_dir": "/owned/fixture/coordinator-state",
  "owner_id": "one fixed coordinator UUID",
  "source_hosts": ["producer-host"],
  "request_timeout_seconds": 10,
  "poll_interval_seconds": 15,
  "production_cutover": false
}
```

Commands are `initialize`, `authorize --authorization <private-file>`,
`revoke-authorization --authorization-id <UUID>`, `once`, `recover`, and
`serve`, all with `--config <private-file>`. The CLI emits fixed result codes
and digests. Exit 3 means an unknown mutation outcome; exit 2 means another
failure. The `serve` command stops on a failed cycle instead of repeatedly
retrying an unresolved mutation.

## Validation and actual integration entry point

Run the local deterministic contract suite from the repository root:

```bash
python3 qa/openbao-acceptance/authbus_coordinator_contract_test.py
```

The suite uses the actual service implementation and real private fsynced
journals with a synthetic key/value transport. It covers path ownership,
exact operator grants, immutable collisions, receipt/dedup recovery, known
CAS races, committed/uncommitted unknown replies, pruned history, revocation
fencing, original request deadlines, conservative token leases, and inbox
capacity refusal. It qualifies no actual SDK, HTTPS connection, or physical
HA behavior.

The separate live driver starts an owned new native V6 HTTPS server and
imports an unchanged copy of the actual installed 0.3.1 plugin together with
the real installed OpenClaw SDK. It uses only synthetic OAuth-shaped source
credentials and new SQLite stores. Its producer has `leader=true`; its
follower has `leader=false`. Both preserve `publishNew=true`,
`manageOrder=true`, release 201, and missing scheduler/enforcement settings,
which the original plugin normalizes to shadow mode.

```bash
/usr/bin/python3 qa/openbao-acceptance/native_v6_authbus_coordinator_live.py \
  --binary /absolute/path/to/verified/heptabao-server \
  --central-source /absolute/path/to/tools/authbus/authbus_coordinator.py \
  --plugin-root /absolute/path/to/actual/openclaw-authbus \
  --openclaw-root /absolute/path/to/actual/openclaw \
  --node /absolute/path/to/node \
  --work-dir /absolute/path/to/a/new/coordinator-canary-root
```

Keep the repository-relative QA layout: the driver imports the frozen
`native_v6_authbus_client_live.py`, `native_v6_openclaw_authbus_live.py`,
`cert_auth_live.py`, `fixture_mounts.py`, `owned_process.py`, and
`qa/single-node/smoke.py`. Its companion is
`native_v6_authbus_coordinator_consumer.mjs`. No production plugin file is
rewritten. The driver only seeds empty order/scheduler fixtures; successful
credential profile/manifest publication comes from this independent service.

The intended real checks include original new-profile/manual-login events,
source-scoped ACLs, actual immutable create versus forbidden update,
manifest CAS conflict, abrupt coordinator exit immediately after commit,
server SIGKILL and cold journal recovery without manifest replay, actual SDK
A-to-B consumption, closed SQLite backup/restore, wrong-CA configuration
rollback, genuine token renewal/revocation, and persistent Secret ID
revocation. ACL rejection checks include immediate successful reads with
the same bearers so expired tokens cannot produce false positive results.
The actual driver must pass on a real host before those results are claimed.

## Remaining production gates

- **Inbox capacity:** a source LIST is bounded to 1024 children and a cycle
  processes at most 32 new events. A larger LIST fails closed. Existing
  inbox entries are never deleted, and there is no qualified pagination,
  persistent scan cursor, or garbage collection. Repeated reports will
  eventually reach this capacity. This is an explicit unattended-service
  limitation, not an event retention policy. No DELETE permission is given.
- **Single owner:** the local operation lock is not a distributed ownership
  lease. Before production transfer, fence the old canonical writer and
  prove exclusive ownership; do not run independent writers with copied
  private state and infer that CAS alone supplies coordinator leadership.
- **Provider credentials:** source liveness, all selected client/provider
  credentials, and OAuth refresh ownership still require host-local proof.
  The live integration fixture calls no provider and rotates no real OAuth
  tokens. Its `leader=true` profile is not active in order policy and has a
  far-future expiry, so it performs no provider refresh.
- **Scheduler and order maintenance:** the service does not calculate
  production order policy, assignments, refresh leases, or health policy.
  Existing shadow client semantics remain unchanged. Optional enforced-lease
  SDK persistence failures remain separately unqualified.
- **Operations:** startup supervision, continuous-load qualification,
  journal retention/restore procedures, all real client/backup references,
  sequential production cutover, and legacy cleanup remain separate gates.
  Passing this isolated candidate does not authorize claiming those done.
