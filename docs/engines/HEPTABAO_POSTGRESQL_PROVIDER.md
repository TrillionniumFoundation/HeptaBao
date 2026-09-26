# PostgreSQL dynamic credentials, statement templates, password authentication, static roles and manager rotation

Status: implemented development profile with source-bound real PostgreSQL 17.11
provider and batch-lease execution receipts below. TLS/SCRAM protocol models
remain separate from SQL, database login and external revocation evidence.
These scoped runs do not establish full OpenBao PostgreSQL plugin compatibility;
changed candidates require their own runs. Production, migration and independent
compatibility authority remains false.

## Long-lived lease retirement invariant

The persisted lease map is bounded by concurrently retained provider work, not by
the lifetime number of credentials ever issued. A successful synchronous revoke
must first observe the PostgreSQL-side disabled/session-drained result, publish a
provider retirement tombstone bound to the global monotonic `provider_fence`,
read that retirement back, and only then remove the local lease row. The fence
survives row removal and restart, so delayed work from an older incarnation cannot
become fresh merely because its detailed local lease row was retired.

The repository regression
`retired_database_leases_do_not_create_a_lifetime_128_issue_ceiling` exercises
more than the historical 128-row bound while retaining a monotonically increasing
provider fence. The 128-row validation bound therefore remains a simultaneous
retained-work safety limit; it is not a 128-credential lifetime ceiling. Real
PostgreSQL acceptance remains responsible for proving the corresponding remote
retirement/readback behavior.

## Ownership and source

`crates/heptabao-server/src/service_database.rs`,
`service_database_statements.rs` and `service_database_rotation.rs` own encrypted
connection, dynamic lease, statement-template, static-role and manager-rotation
intent records inside the existing Service state. `postgres_wire.rs` owns bounded
PostgreSQL TLS/SCRAM/extended-query transport. `bootstrap/postgresql/provider.sql`
owns the separate provider-side transaction and idempotency ledgers.
`upgrade_v2_static_credentials.sql`, `upgrade_v3_statement_templates.sql` and
`upgrade_v4_password_authentication.sql` are owner-only forward extensions for an
already installed provider-v2 schema.
`outbound.rs` owns host-enrolled network destinations.
No component may infer an external transaction's success from local persistence.

The ordinary Service request admission, live Identity/ACL, pre-entry audit,
encrypted durable writer and Raft commit remain mandatory. A database mutation
never installs a second local authoritative store. The original dynamic provider increment introduced schema 4; retained static/root
rotation state requires schema 53, persisted statement templates require
schema 54, and an explicit non-default PostgreSQL password-authentication mode
requires schema 55. Read-only opening of valid older state does not upgrade it. Any real mutation
publishes the current discriminator defined in `../architecture/HEPTABAO_CURRENT_STATE_FORMAT.md`. An old executable must refuse the new state; changing the
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
LIST database/config                             configured connection names
DELETE database/config/local                     delete only when unreferenced
POST database/roles/reader                      bounded role configuration
LIST database/roles                              configured role names
DELETE database/roles/reader                     stop future issuance for that role
GET  database/creds/reader                       creates real provider intent
POST sys/leases/lookup                          {"lease_id":"..."}
POST sys/leases/renew                           {"lease_id":"...","increment":120}
POST sys/leases/revoke                          {"lease_id":"..."}
POST sys/leases/revoke-prefix/database/creds/reader {}
POST sys/leases/reconcile/<exact-lease-id>        {}
LIST sys/leases/lookup/database/creds/reader
```

Connection configuration accepts `plugin_name` equal to
`postgresql-database-plugin`, `connection_url`, `username`, `password`,
`allowed_roles`, optional `verify_connection=true`, and optional
`password_authentication`. The latter is `password` by default or
`scram-sha-256` for the native PostgreSQL provider. The manager credential is
sealed by existing Service persistence, never returned by config read. Successful
configuration requires a verified current-user and provider-contract query.

Role configuration has two mutually exclusive modes. The retained provider-role
mode uses `db_name`, **`provider_role`**, `default_ttl` and `max_ttl`;
`provider_role` is a separately approved non-login PostgreSQL group. The bounded
statement mode uses `creation_statements`, optional `renew_statements`,
`revocation_statements` and `rollback_statements`, plus `credential_type=password`
and an empty `credential_config`. Both modes retain the same `db_name` and TTL
bounds. A role cannot mix `provider_role` and statement templates, and statement
roles currently require the native PostgreSQL provider.

Role deletion removes only the issuance configuration: existing provider leases
remain independently owned and must still be renewed, revoked or reconciled
through their lease IDs. Connection deletion is stricter and fails while any role
or retained lease still references the connection. Collection `LIST` operations
are read-only projections of the persisted configuration names; manager passwords
remain non-exportable.

Config and role mutation plus system lease operations require `sudo` in addition
to their operation capability. Issue requires read authority on the real creds
path. A body lease ID conflicting with an authorized URL is rejected before any
provider request. Database response wrapping and automatic unmount remain
explicitly unsupported, not acknowledged as success. Database prefix revoke is a
bounded synchronous batch: the Service persists every selected `PendingRevoke`
transition first, then performs provider effects outside the global writer and
publishes only exact readback-confirmed retirements. A provider failure stops new
external entries; attempted or not-yet-attempted leases remain pending for
authoritative reconciliation rather than being blindly retried. Connection
replacement is still fenced while active or unresolved lease records exist.
Terminal revocations are not capacity-evicted: provider v2 first proves the
external revoke, advances a cluster-bound monotonic fence, retires the generated
role and per-lease provider row, and confirms that retirement before the Service
removes the local lease record. Root enumeration is not a union of all engine
classes.

## Explicit PostgreSQL password authentication

Connection configuration accepts OpenBao 2.6.2's `password_authentication`
selection. `password` preserves the historical path and PostgreSQL's enrolled
server policy. `scram-sha-256` requires the separately installed
`heptabao-postgresql-password-authentication-v1` provider extension. The Service
derives a canonical PostgreSQL SCRAM-SHA-256 verifier locally from the generated
raw client password and a persisted random salt. The raw password remains only in
the encrypted pending intent and authorized response; SCRAM-mode SQL receives the
verifier, never the raw login secret. Provider readback hashes PostgreSQL's stored
verifier and remains bound to the existing operation digest.

The same dynamic, statement-template, static-role and root-rotation functions
remain the only mutation owners. The owner-only extension atomically replaces
those four function bodies under their existing signatures, preserving function
OID, owner, ACL, SECURITY-DEFINER flag and search path while expanding only the
credential validator from legacy 64-hex input to legacy input or one strict,
canonical SCRAM verifier. Thin SCRAM wrappers reject raw or malformed material
before delegating to those owners. Advisory locks, sequence/fence checks, payload
digests, role identity and provider readback are unchanged. Same-sequence retry
therefore uses the exact persisted verifier bytes. Static and manager rotations
reconnect with the raw pending client password while provider mutation receives
only its paired verifier.

Fresh installs contain the strict verifier helpers, upgraded owner bodies and
wrappers. Existing provider-v2 installations must first have the static/root and
statement extensions, then be backed up and extended by the schema owner with
`upgrade_v4_password_authentication.sql`. The forward upgrade is repeatable,
uses bounded lock/statement timeouts, preserves the four owner functions' OID,
owner and ACL, and creates new helpers/wrappers with PUBLIC execution revoked.
The API manager cannot install the extension; the operator must grant only the
new protocol/wrapper entrypoints needed by that enrolled manager.

Persisted `scram-sha-256` selection requires schema 55. Each unresolved dynamic,
statement, static or root password mutation also retains the paired verifier in
the encrypted database owner and binds it into the request digest. Missing,
extra, malformed or digest-substituted verifier state is rejected. Verifiers are
cleared with the pending raw password after terminal publication. Absent/default
`password` selection retains schema-54 serialization and historical digest bytes.

`postgres_password_authentication_live.py` runs all four credential mutation
paths on a private PostgreSQL 17 cluster, verifies raw client login and the
actual `pg_authid` SCRAM verifier, rejects raw/malformed input at SCRAM wrappers
before any fence or role is created, rotates the manager, restarts HeptaBao and
executes the v2→static→statement→password-auth forward path twice. It compares
owner function OID/owner/ACL/security configuration before and after upgrade.
Password-policy generation, `username_template`, non-PostgreSQL providers,
multi-host faults and independent admission remain open.

## Bounded OpenBao statement-template roles

The statement profile persists the exact template arrays in encrypted Service
state and copies them into each durable lease intent. A statement-backed lease is
domain-separated from the legacy provider-role digest, so old pending intents
reopen byte-stably while a template or ordering change cannot adopt an existing
operation. Supported placeholders are `{{name}}`, `{{username}}`, `{{password}}`
and `{{expiration}}`. Each phase permits at most 16 configured entries, each entry
is at most 16 KiB, aggregate configured text is at most 64 KiB, and one provider
operation may execute at most 64 split statements. Single/double/dollar-quoted
strings, PostgreSQL escape strings, line comments and nested block comments are
tracked before semicolon splitting. Unknown or unmatched placeholder delimiters,
unterminated strings/comments and excess comment nesting fail before intent
publication.

The Service renders only fixed generated usernames, one mode-selected provider
credential and UTC expirations. Historical `password` mode renders the 32-byte
hexadecimal client password. `scram-sha-256` renders the paired canonical verifier
while retaining the raw password only for the encrypted intent and authorized
response. It serializes the normalized statement array once, binds its exact
SHA-256 digest into provider readback, and passes the original bounded JSON text
to the selected statement owner. The privileged provider parses that text,
verifies array/type/size bounds, records only digests and role identity, and runs
all statements inside one PostgreSQL transaction. Readback must match fence,
lease, username, sequence, action, expiry, request digest and the exact statement
digest before Service may publish completion. A same-sequence retry with different
bytes is a semantic conflict; a later global fence does not invalidate exact
read-only replay of the already recorded operation.

Empty renewal statements use a bounded `ALTER ROLE ... VALID UNTIL` default.
Empty revocation statements call the non-public `default_statement_revoke`, which
sets NOLOGIN, terminates sessions, revokes bounded schema/database privileges and
drops the generated role. Custom revocation may leave a NOLOGIN role only when no
session remains. Creation statements and provider-ledger publication share one
transaction, so a late SQL failure rolls back the generated role and ledger row.
`rollback_statements` are persisted and digest-bound for OpenBao field fidelity,
but are not separately executed after PostgreSQL has already rolled back the
transaction; templates that cause non-transactional external side effects remain
outside this bounded profile.

Fresh installs include the statement extension. An existing provider-v2 plus
static/root installation must be backed up and extended by the privileged schema
owner with `upgrade_v3_statement_templates.sql`; the API manager cannot install
or mutate the extension. Fresh and forward-install extension blocks are kept
byte-identical. The manager gets explicit execution grants only and never table
mutation or schema creation.

`postgres_statement_templates_live.py` runs a fresh PostgreSQL 17 cluster and an
independent v2→static/root→statement forward-upgrade database. It exercises field
readback and partial updates, real generated-role login and grants, denied writes,
renewal, restart, custom and default revoke, exact retry after a later global
fence, transactional failed creation, ledger retirement and plaintext scans. The
profile is mandatory in replacement CI and remains repository-controlled scoped
evidence, not complete OpenBao database-plugin admission.

## Bounded static roles and manager-password rotation

The same database mount now exposes a bounded PostgreSQL-only profile:

```text
POST/GET/LIST/DELETE database/static-roles/<name>
GET                  database/static-creds/<name>
POST                 database/rotate-role/<name>
POST                 database/rotate-root/<connection>
```

A static role names an existing operator-created LOGIN role and one configured
database connection. The API role name must remain in the connection's
`allowed_roles`, while the physical PostgreSQL username must be independently
enrolled by the provider owner in `allowed_static_roles`. The manager itself,
privileged roles, recreated role OIDs and identity rebinding are rejected. Rotation
periods are bounded to 5–86,400 seconds. Static passwords are generated as 32
random bytes encoded in lowercase hex; configuration reads never return manager
or pending credentials.

Every manual, scheduled, delete or root rotation first persists its sequence,
semantic digest and pending secret in the encrypted Service transaction. Provider
I/O occurs outside the writer. Completion installs the exact current intent only
after provider readback and current request authority; lifecycle recovery never
reconstructs an HTTP authority. Manager-password rotation first attempts exact
readback with the pending secret, so a committed effect with a lost response can
be recovered without replaying the old-password mutation. If the old secret still
authenticates and the provider ledger proves that a later global fence overtook an
unapplied root intent, Service commits a fresh sequence and digest around the same
pending password before any retry. Exact applied state, verifier drift, newer root
state or identity rebinding never satisfy that negative proof.

Provider retirement keeps one bounded tombstone per owner-enrolled static identity
instead of treating an absent row plus a global counter as proof. The tombstone
binds fence, static ID, username, sequence, request digest and internally computed
payload digest. A wrong digest, different username or recreated PostgreSQL OID is
not terminal evidence. Recreating the same API role reactivates the same provider
identity under a higher global sequence. Provider storage is fail-closed at 4,096
static identities per manager and database; exhaustion is checked before `ALTER
ROLE`, so capacity failure cannot mutate the existing password. Tombstones are not
automatically discarded because doing so could readmit a delayed old effect. Exact
applied retries remain observable after unrelated later effects advance the global
provider floor. Root rotation similarly keeps one manager-bound ledger row and
refuses identity rebinding.

Fresh installs use the eighteen-function provider contract. An existing provider-v2
installation must be backed up and extended only by the privileged schema owner
with `upgrade_v2_static_credentials.sql`; the API manager cannot install or modify
its tables. The forward script and fresh-install block are byte-aligned for these
eight functions and three tables. Grants remain explicit: the manager receives
schema usage and function execution only, never table mutation or schema create.

`postgres_static_rotation_live.py` executes fresh install and forward upgrade on
real PostgreSQL 17, automatic/manual rotation, old-password denial, global-fence
overtaking, digest-bound delete/recreate, two manager rotations, encrypted restart,
provider-capacity saturation before password mutation, plaintext scans and
restricted-manager negative cases. It also disables lifecycle,
retains a root intent through provider outage and process restart, overtakes it with
an unrelated dynamic effect, then proves lifecycle readmission and completion. It is
mandatory in the replacement workflow. This scoped profile does not implement connection password-policy generation,
username-template/password-authentication option parity, complete OpenBao
field/error parity, generic database-plugin capability negotiation,
non-PostgreSQL static roles or multi-host database failover. OpenBao 2.6.2's
native PostgreSQL plugin is password-based; RSA and client-certificate credential
types are generic plugin capabilities, not attributed to this provider.

## Native username contract and recovery of the short-name regression

New native PostgreSQL and Valkey credentials retain `hbp_` followed by 32 lowercase
hexadecimal digits. The generic plugin path retains its separate 28-digit form
for MySQL's 32-character account limit. Every durable lease ID retains all 128
random bits. These formats do not change existing lease IDs, usernames, sequence
numbers or request digests on reopen.

The shared MySQL naming change once affected native PostgreSQL too: the Service
persisted a short-name `PendingIssue`, but deployed PostgreSQL provider v2 rejected
it before creating the role. Fixing future names alone does not retire those
pending obligations. After taking a normal operator backup, the existing
privileged function owner can explicitly apply
`bootstrap/postgresql/upgrade_v2_username_recovery.sql` using `psql -X -v
ON_ERROR_STOP=1 -f` and their existing protected connection configuration. Do not
put credentials on the command line or rerun the fresh-install `provider.sql`.
This upgrade is not applied automatically by the Service or by an API caller.

The forward-only transaction replaces the three existing v2 cleanup/apply
functions, preserving their identity, owner and grants. It leaves tables, live
roles, leases and fences intact. Only revoke/retire/readback admit the historical
28-digit form: issue and renewal still require the original 32-digit native
contract. Existing ownership checks reject a colliding foreign role. Restart or
explicit `sys/leases/reconcile/<lease-id>` still stages a higher-sequence revoke;
it never rewrites a pending identity or blindly reissues a secret. Existing
short-name work remains pending until the provider upgrade and authoritative
cleanup succeed. The v2 protocol label is retained because the forward change
only extends cleanup of previously rejected requests.

`postgres_live.py` installs the checksum-frozen historical v2 SQL first and proves
normal new credentials work against it. It then tests owner-only upgrade,
unchanged function owners/grants, live credential preservation, rejected new
short-name issuance, short-name revoke/retirement, stale replay rejection and
foreign-role protection, followed by the full existing provider lifecycle. Its
report binds the historical, fresh-install and upgrade SQL digests. This remains
a scoped native-provider qualification, not general OpenBao statement or full
database-plugin compatibility.

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

Within one Service process, every staged provider plan holds a process-local
in-flight marker for its namespace, mount and lease. Lifecycle reconciliation
skips that pending row while the marker is live, and a second foreground
renewal, revocation or prefix revocation for the same row receives a 503
reconcile response instead of starting a duplicate provider effect. The marker
is deliberately not persisted: after a process restart, the durable pending
intent is eligible for the recovery path below.

A timeout, SQL error, lost response, mismatched readback or failed local completion
never means "not issued" or "revoked". It returns a safe pending/reconcile error
and retains the encrypted intent. Restart or explicit reconciliation does **not**
retry credential issuance: it stages a higher-sequence revoke. Pending renewal is
also resolved by revocation rather than silently extending authority. A provider
that returns an ownership conflict remains pending until operator diagnosis; no
forced takeover or deletion of an unowned role exists.

A pending revoke can be overtaken while a different lease advances the admitted
global provider fence. Recovery does not relax PostgreSQL's old-sequence check.
With no live plan for that lease, the current Service writer re-admits only the
subtractive cleanup under a fresh locally admitted sequence and semantic digest,
commits it, and then enters the provider. Lease ID, provider ID and username stay
unchanged. A pending revoke already at the current frontier retains its sequence
across retries/restarts; counter exhaustion is an atomic rejection. Delayed
completion of the old plan cannot publish over the replacement intent. This does
not adopt an untrusted remote counter or make an old-backup writer current.
The real PostgreSQL profile induces a controlled role-ownership mismatch, leaves
the first revoke pending, successfully issues another lease, restores the role,
and requires authoritative cleanup without disabling the unrelated credential.

The provider serializes operations with a fence-scoped advisory transaction lock
and row locks. Same-sequence retries must have the same internally computed
payload digest as well as the supplied request digest while a per-lease row still
exists. Provider v2 additionally binds every effect in the cluster to one durable
monotonic fence. A higher-sequence revoke may cancel an uncertain earlier request.
After verified retirement the provider retains only the compact fence floor, so a
delayed lower/equal-sequence issue or renew is rejected even after its per-lease
row and generated PostgreSQL role have been removed.

## SQL deployment boundary and ownership

An independent privileged PostgreSQL schema owner installs `provider.sql` into
the selected database. The caller must explicitly provision a nonprivileged login
manager, a non-login application group and its application permissions, grant only schema usage and the five dynamic, eight rotation and five statement
functions, and enroll manager/group in
`allowed_groups`. Do not grant the manager table mutation, schema CREATE or
membership in a privileged role. Function search paths are fixed to pg_catalog;
relation references are schema-qualified. The installer is deliberately non-
idempotent and refuses an existing schema rather than silently altering its owner.

The ledger binds role and group OIDs, direct membership, privilege flags, expiry
and password-verifier digest. Renewal and revoke reject ownership drift or a
recreated username. Revoke first keeps a NOLOGIN role and terminates sessions.
Provider v2 then retires that generated role only after the global fence and exact
revoke readback make every older operation stale. Retirement never uses
`DROP OWNED` or `REASSIGN OWNED`; object/grant dependencies or identity drift
therefore fail closed and keep the durable pending intent for reconciliation.
The per-lease provider row is deleted only in the same successful retirement
transaction, while the compact global fence row remains. Application group
inheritance and operator-controlled group changes are trusted deployment inputs
and require separate review. A database administrator can alter roles or the
ledger; this profile does not protect against the PostgreSQL administrator.
The baseline `0ddbb3a3abae30f14d9267fa56c6dd67d8de08f5` ran real PostgreSQL
acceptance in GitHub Actions run `34924284502` (head and prospective merge).
This is repository-controlled execution, not independent provider qualification.
Every changed candidate must execute the real runner again; the wire model cannot
substitute for SQL, OID/DDL semantics, login or session-termination evidence.

The SSD Lima guest provider run bound to source head `45c7edc` used PostgreSQL
17.11 from the arm64 PGDG package and candidate binary SHA-256
`e389be313be0c5240a2dadd33cd866ae215e28f4c2f2ec7a95dba26de6b1e72a`. Its
[54-check receipt](../../qa/openbao-acceptance/evidence/postgresql-live-45c7edc.json)
covered the current provider-role profile, including exact fence blocking,
restart/outage reconciliation, active-session termination and more than 128
issue/revoke lifecycles. The receipt predates the separate static/root profile and remains scoped
repository evidence; it does not admit full OpenBao statement/template/error parity,
multi-host provider faults or independent qualification.

A later `eeab30a` binary passed [46 real PostgreSQL batch-lease checks](../../qa/openbao-acceptance/evidence/batch-postgres-lease-eeab30a.json),
including actual generated-role login, lease retirement and parent revocation.
Its exact binary and runner identities are recorded in that receipt; it does not
transfer provider qualification to later binaries.

## Bounds, recovery and operation

The provider allows at most one-day TTL. Service bounds are 64 namespaces, 64
mounts/namespace, 16 connections/mount, 64 roles/mount and 128 simultaneously
active or unresolved leases/mount. Successfully retired leases no longer consume
that lifetime budget; one compact monotonic provider-fence value persists instead.
The stricter existing encrypted Service-state size limit still applies first. The
real PostgreSQL acceptance profile churns more than 128 issue/revoke lifecycles
and requires the per-lease provider ledger plus generated-role set to return to a
bounded terminal footprint while the global fence keeps increasing.
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
python qa/openbao-acceptance/postgres_static_rotation_live.py --binary <server> --postgres-bin <pg17-bin> --work-dir <new-private-dir> --output <new-json>
python qa/openbao-acceptance/postgres_statement_templates_live.py --binary <server> --postgres-bin <pg17-bin> --work-dir <new-private-dir> --output <new-json>
```

The first two Python runners use an explicitly labelled in-memory wire model
behind real TLS/SCRAM, including lost replies and real HeptaBao process restart/HA.
They do not execute SQL. The last runner requires real `postgres`, `initdb` and
`psql`, creates a new private loopback database with fsync and SCRAM/TLS enabled,
installs the SQL, checks actual login/renew/revoke, SIGKILL/restart and provider
side denial. Missing prerequisites produce **exit 77 and blocked_prerequisite**;
it must never be replaced by a mock, counted as pass or hidden as an ordinary skip.

## Completion publication failure precedence

After PostgreSQL has applied an operation and returned matching readback, a local
state/capacity/validation failure is HTTP 503 with the original lease identity,
`reconcile_required=true`, `retry_allowed=false` and any local recovery reference.
It cannot be presented as HTTP 507/400 failed-before-entry. The encrypted pending
intent is retained; no credential is returned and no fresh issuance is retried.
`provider_completion_publication_failure_is_never_before_entry_rejection` tests
this response boundary and secret redaction. This unit regression is not actual
PostgreSQL SQL acceptance, which still needs a real server for each candidate.
