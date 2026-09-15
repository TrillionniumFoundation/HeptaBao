# PostgreSQL dynamic credentials and renewable lease implementation

Status: implemented development profile; actual PostgreSQL 17 server execution is
an **unmet qualification gate** in the current delivery. TLS/SCRAM protocol-model
success is not SQL execution, a database login, external revocation or OpenBao
PostgreSQL plugin compatibility. All production, migration and independent
compatibility authority remains false.

## Ownership and source

`crates/heptabao-server/src/service_database.rs` owns encrypted connection,
role, lease and pending-effect records inside the existing Service state.
`postgres_wire.rs` owns bounded PostgreSQL TLS/SCRAM/extended-query transport.
`bootstrap/postgresql/provider.sql` owns the separate provider-side transaction
and idempotency ledger. `outbound.rs` owns host-enrolled network destinations.
No component may infer an external transaction's success from local persistence.

The ordinary Service request admission, live Identity/ACL, pre-entry audit,
encrypted durable writer and Raft commit remain mandatory. A database mutation
never installs a second local authoritative store. Service state is now schema 4;
read-only opening of valid older state does not upgrade it. Any real mutation
publishes schema 4. An old executable must refuse the new state; changing the
schema number by hand is not a downgrade or rollback procedure.

## Enrollment and bounded API

At process startup, an operator registers an `outbound_endpoints` entry:

```json
{
  "origin": "postgresql://db.internal:5432",
  "address": "192.0.2.20:5432",
  "server_name": "db.internal",
  "ca_pem": "<explicit trusted PEM CA>",
  "path_prefix": "/app"
}
```

This is an illustrative documentation address, not a working deployment.
The URL must have an explicit port, no userinfo, escaping, query, fragment or
relative path. The actual IP and server identity are frozen at process startup;
there is no DNS, proxy, redirect, plaintext fallback or implicit system CA.
Peer TLS verification is mandatory, followed by SCRAM-SHA-256 with verification
of the server proof. TLS resumption is disabled. SCRAM-PLUS, client certificates,
MD5/trust auth, connection pooling and multi-host failover are not implemented.

After independently provisioning the SQL contract, configure the database mount:

```text
POST sys/mounts/database                         {"type":"database"}
POST database/config/local                      connection configuration
POST database/roles/reader                      bounded role configuration
GET  database/creds/reader                       creates real provider intent
POST sys/leases/lookup                          {"lease_id":"..."}
POST sys/leases/renew                           {"lease_id":"...","increment":120}
POST sys/leases/revoke                          {"lease_id":"..."}
POST sys/leases/reconcile/<exact-lease-id>        {}
LIST sys/leases/lookup/database/creds/reader
```

Connection configuration accepts `plugin_name` equal to
`postgresql-database-plugin`, `connection_url`, `username`, `password`,
`allowed_roles`, and optional `verify_connection=true`. The manager credential is
sealed by existing Service persistence, never returned by config read. Successful
configuration requires a verified current-user and provider-contract query.

Role configuration uses `db_name`, **`provider_role`**, `default_ttl` and `max_ttl`.
`provider_role` is a separately approved, non-login PostgreSQL group; it is not
arbitrary SQL or an OpenBao creation-statement template. HTTP-provided creation,
rollback, rotation and revocation SQL are rejected. Consequently this API is a
bounded provider profile, not a drop-in OpenBao database plugin.

Config and role mutation plus system lease operations require `sudo` in addition
to their operation capability. Issue requires read authority on the real creds
path. A body lease ID conflicting with an authorized URL is rejected before any
provider request. Database response wrapping, batch/prefix revoke, automatic
unmount and connection replacement after lease records exist are explicitly
unsupported, not acknowledged as success. Registry capacity does not evict
revocation tombstones. Root enumeration is not a union of all engine classes.

## State machine and external-effect boundary

Each operation binds cluster identity, namespace, mount/client lease ID, opaque
provider ID, generated username, issuer digest, provider configuration, sequence,
operation class, expiry and semantic digest. The provider identifier is a
length-delimited SHA-256 namespace/cluster binding, not a credential or signature.

```text
issue:  persist PendingIssue -> provider apply -> post-commit observe -> Active
renew:  persist PendingRenew -> provider apply -> post-commit observe -> Active
revoke: persist PendingRevoke -> provider apply -> post-commit observe -> Revoked
```

The Service commits the intent before provider entry. The native PostgreSQL
client consumes CommandComplete and idle ReadyForQuery, then runs a separate
readback. Apply's JSON result alone cannot finish the lease. Readback must match
provider identity, username, sequence, action, digest and expiry. Issue/renew also
require the controlled role and LOGIN state; revoke requires NOLOGIN/absence and
zero active sessions. A durable completion is committed before credentials or a
success response are released. A post-commit result-audit failure withholds the
response and retains the committed state under the existing recovery fence.

A timeout, SQL error, lost response, mismatched readback or failed local completion
never means "not issued" or "revoked". It returns a safe pending/reconcile error
and retains the encrypted intent. Restart or explicit reconciliation does **not**
retry credential issuance: it stages a higher-sequence revoke. Pending renewal is
also resolved by revocation rather than silently extending authority. A provider
that returns an ownership conflict remains pending until operator diagnosis; no
forced takeover or deletion of an unowned role exists.

The provider serializes operations with an advisory transaction lock and row lock.
Same-sequence retries must have the same internally computed payload digest as
well as the supplied request digest. Old sequences fail. A higher-sequence revoke
may cancel an uncertain earlier request. A durable tombstone permanently rejects
later issue/renew for that provider identity, including delayed old-leader traffic.
This is per-lease sequencing, not a global external fencing-token service.

## SQL deployment boundary and ownership

An independent privileged PostgreSQL schema owner installs `provider.sql` into
the selected database. The caller must explicitly provision a nonprivileged login
manager, a non-login application group and its application permissions, grant
only schema usage and the three functions, and enroll manager/group in
`allowed_groups`. Do not grant the manager table mutation, schema CREATE or
membership in a privileged role. Function search paths are fixed to pg_catalog;
relation references are schema-qualified. The installer is deliberately non-
idempotent and refuses an existing schema rather than silently altering its owner.

The ledger binds role and group OIDs, direct membership, privilege flags, expiry
and password-verifier digest. Renewal and revoke reject ownership drift or a
recreated username. Revoke keeps a NOLOGIN role and terminates sessions; it does
not use DROP OWNED or assume DROP ROLE is harmless. Application group inheritance
and operator-controlled group changes are trusted deployment inputs and require
separate review. A database administrator can alter roles or the ledger; this
profile does not protect against the PostgreSQL administrator.

Role/tombstone retention needs an operator-designed archival/retirement policy.
Do not delete a tombstone while delayed operations can still reach that provider.
The SQL contract has not been run against an actual PostgreSQL server in this
execution environment, so syntax, OID/DDL semantics and session termination are
not qualified by the protocol model. Real database acceptance is mandatory.

## Bounds, recovery and operation

The provider allows at most one-day TTL. Service bounds are 64 namespaces, 64
mounts/namespace, 16 connections/mount, 64 roles/mount and 128 leases/mount;
the stricter existing encrypted Service-state size limit still applies first.
Manager passwords are bounded ASCII; issued passwords are 32 random bytes encoded
as hex. No caller-supplied username is used for dynamic accounts.

TLS uses an absolute 3-second connection/I/O budget; the PostgreSQL profile sets
2.5-second statement and 1.5-second lock timeouts. Query text is fixed, parameters
use Bind messages, response frames are bounded and only the expected one-column
one-row result shape is accepted. A malformed SCRAM/server/error frame is never
included verbatim in public errors. These are admission limits, not a performance
SLA or a proof of availability under load.

Each lifecycle tick examines existing local state but attempts at most one
external operation. A round-robin advisory cursor prevents one unavailable
provider from always starving another. Expired or invalidated owners trigger
revocation; the worker commits pending intent and readback through the same
leader/ReadIndex fence and writer. Token revocation is therefore not a synchronous
promise to terminate every database session in that HTTP response. Disabling idle
maintenance requires explicit reconcile calls; PostgreSQL expiry alone does not
terminate already established sessions.

Database-state snapshot restore is blocked rather than resurrecting credentials
from an old Service snapshot without consulting the provider ledger. Mixed-
version HA, database PITR/ledger rollback, operator key rotation, dynamic provider
reconfiguration and full migration remain unimplemented qualification scope.

## Verification and exact evidence classes

```sh
cargo test --locked -p heptabao-server service_database
cargo test --locked -p heptabao-server postgres_wire
python qa/openbao-acceptance/postgres_pipeline_simulated.py --binary <server> --output <new-json>
python qa/openbao-acceptance/postgres_pipeline_ha.py --binary <server> --output <new-json>
python qa/openbao-acceptance/postgres_live.py --binary <server> --postgres-bin <pg17-bin> --output <new-json>
```

The first two Python runners use an explicitly labelled in-memory wire model
behind real TLS/SCRAM, including lost replies and real HeptaBao process restart/HA.
They do not execute SQL. The last runner requires real `postgres`, `initdb` and
`psql`, creates a new private loopback database with fsync and SCRAM/TLS enabled,
installs the SQL, checks actual login/renew/revoke, SIGKILL/restart and provider
side denial. Missing prerequisites produce **exit 77 and blocked_prerequisite**;
it must never be replaced by a mock, counted as pass or hidden as an ordinary skip.
