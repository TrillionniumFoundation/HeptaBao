# HeptaBao Valkey database provider

The Service database engine has a real, bounded Valkey 7.2 ACL provider.
Configure `plugin_name: valkey-database-plugin` and a connection URL
`valkeys://host:port/0`. The matching origin (without `/0`) must be enrolled in
`outbound_endpoints` with a fixed address, server name and CA. All traffic uses
verified TLS and RESP2 with a 3-second absolute deadline, a 256 KiB aggregate
response bound and at most 1,024 response nodes. There is no cleartext fallback,
DNS lookup, redirect or implicit network retry. Only database zero is admitted:
Valkey 7.2 ACLs cannot isolate credentials to a selected nonzero database.

Configuration verifies `PING`/`PONG` and `ACL WHOAMI`. The manager must also be
operator-authorized to use `WATCH`, `MULTI`, `EXEC`, `GET`, `SET` and the ACL
`GETUSER`, `SETUSER`, `DELUSER`, `SAVE` subcommands. A writable, durable ACL file
is required. Missing privileges or failed persistence leave a durable pending
intent and return 503; configuration verification alone does not prove these
capabilities. Configuration readback never returns the manager password.
PostgreSQL connections retain their old serialized shape; a missing provider
field means PostgreSQL.

Roles accept `db_name`, `provider_role`, `default_ttl` and `max_ttl`.
`readonly` grants PING, GET, MGET, EXISTS, TTL, PTTL and TYPE. `readwrite` also
grants SET, DEL, UNLINK, EXPIRE, PEXPIRE and PERSIST. Every lease has a generated
password and a single generated key pattern returned with its credentials.
FLUSHALL, FLUSHDB, KEYS, SCAN, arbitrary categories, selectors and Pub/Sub are
excluded. Readback checks the complete command set, flags, key/channel rules,
absence of selectors and one password hash; issuance also checks the exact
returned password hash. Renewal requires an existing user with the same bounded
policy and never recreates or re-enables a disappeared/disabled account.

Before external entry, the engine persists its lease intent. Each remote effect
uses WATCH/EXEC to atomically publish both the user change and an off,
passwordless ACL marker containing the lease sequence and request digest.
The WATCH key serializes concurrent connections; the ACL marker is the durable
fence. `ACL SAVE` persists the marker and user in the same ACL file before
readback and local completion. Replayed equal sequences must have the same
request digest; lower or conflicting sequences fail. A later revoke invalidates
an older watched transaction. Provider restart closes all watchers and restores
the marker from the ACL file. Revoke deletes the user (including its existing
connections), saves the ACL file and verifies absence. Uncertain outcomes retain
the local intent for reconciliation after restart. Markers and WATCH keys are
retained indefinitely to prevent old operations from resurrecting users; bounded
marker retirement is still required for sustained production churn.

Lease expiry is enforced by the HeptaBao lifecycle worker, not a native Valkey
ACL expiry timestamp. If every HeptaBao process is down/sealed, already-issued
Valkey credentials can remain usable until the worker resumes. ACL-file
rollback, provider failover/replication, physical power loss, disk-full, complete
HeptaBao HA races and migration/downgrade require further qualification.

Run `qa/openbao-acceptance/valkey_live.py` with an absolute candidate binary,
a new private `--work-dir` on the test volume and an absolute `--output` path.
It starts a disposable loopback Valkey TLS process with synthetic credentials
and verifies real ACL effects, key/command isolation, dual restart, expiry,
existing-session termination, stale WATCH rejection and outage reconciliation.
The fixture is repository-controlled evidence, not an independent Oracle run.
Static/root rotation, OpenBao creation-statement semantics, arbitrary ACL roles,
RESP3, Valkey 9.x ACL extensions and full OpenBao 2.6.2 provider parity remain
open. No production or full-compatibility claim follows from this profile.
