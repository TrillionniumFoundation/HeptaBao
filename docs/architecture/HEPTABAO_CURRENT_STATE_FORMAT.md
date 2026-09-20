# Current Service state format and upgrade boundary

Current plan: `HEPTABAO-PLAN-2026-09-07-V2.1`. This is the current format contract,
not a new project plan. It supersedes current-tense schema-2/schema-3 descriptions
in retained increment notes. Exact source remains authoritative.

## Source and authoritative ownership

The current Service state schema is **12**. Its source constant is
`CURRENT_STATE_SCHEMA` in `crates/heptabao-server/src/service.rs`; admission is
`State::validate_format` in `service_identity.rs`. The Service owns one encrypted
state transaction. Auth, engines, database intents and Raft administration are
internal owners, not competing independent stores. Schema 5 introduced encrypted
Kubernetes config/role maps, OIDC config/role/session/clock maps and the replicated
replay epoch. Schema 6 adds the durable monotonic PostgreSQL provider fence used to
retire terminal external-effect tombstones without allowing delayed old effects to
resurrect. Schema 7 adds LDAP group-search configuration and local group-to-policy
mappings. Schema 8 adds the bounded Kubernetes **secrets-engine** TokenRequest
provider state inside its mount: encrypted provider bearer/configuration, roles,
pre-entry issuance intents and terminal lease metadata. This is distinct from the
schema-5 Kubernetes **authentication method** state. Old binaries must refuse newer
state rather than authenticate or issue credentials while silently dropping live
authorization/provider semantics. Schema 9 adds the explicit namespace catalog: durable
namespace IDs/incarnations and custom metadata are bound into application state while
namespace sealing remains a separate, still-open surface. Schema 10 adds durable
authentication-plugin mount bindings: the deployment plugin id is paired with
server-owned policy and token-lifetime limits. The external plugin can return only
an authentication decision plus a bounded alias; token authority and Identity
binding remain inside the Service transaction. Schema 11 adds structured direct
AppRole renewal provenance. It binds a token to its issuing namespace, mount and
role name so renewal re-reads live role and mount limits; token-API children do
not inherit this issuer authority. Old binaries must reject this state rather
than use display names or stale issuance limits. Separate seal metadata uses
schema 1; the application schema must never be inferred from that number.

## Read admission and mutation promotion

| Stored application schema | Read/unseal admission |
|---|---|
| 1 | No live-identity, wrapping, lease or remote-JWT state; no database mount/records; default Raft-admin state. |
| 2 | Live Identity is permitted; no wrapping, lease or remote-JWT state; no database mount/records; default Raft-admin state. |
| 3 | Wrapping/local leases are permitted; no remote-JWT state; no database mount/records; default Raft-admin state. |
| 4 | No online Kubernetes/OIDC method registry or state and no replay epoch; normal scope, lease, wrapper, database and Raft-admin validators still apply. |
| 5 | Online methods and replay epoch are admitted, but the PostgreSQL `provider_fence` must remain absent/zero. |
| 6 | Online methods, replay epoch and durable PostgreSQL provider fencing; LDAP group synchronization state must be absent. |
| 7 | LDAP group synchronization/group-to-policy mappings are admitted; Kubernetes secrets-engine mounts must be absent. |
| 8 | Kubernetes TokenRequest secrets-engine state is admitted; the explicit namespace catalog must still be absent. |
| 9 | Explicit namespace IDs/incarnations and custom metadata; authentication-plugin state must still be absent. |
| 10 | Durable server-owned authentication-plugin mount bindings; AppRole renewal provenance must be absent. |
| 11 | Structured direct AppRole renewal provenance; RADIUS state must be absent. |
| 12 | Current format, adding bounded RADIUS PAP mount state with a schema fence. |
| Other or contradictory version/content | Fail closed; do not repair the discriminator or drop unknown state. |

Every schema 1–4 record additionally rejects online authentication state or a
new online method registry entry. Schemas below 5 reject a nonzero replay epoch;
schemas below 6 reject a nonzero database provider fence. Schemas below 7 reject LDAP group-search configuration or group-to-policy
mappings. Schemas below 8 reject Kubernetes secrets-engine mounts/state. Schemas below 10 reject durable authentication-plugin mount bindings. Schema 11 is required when any token carries AppRole renewal provenance. Schema 12 is required when any RADIUS mount state is present. Fields omitted from
legacy records are default-empty/zero only for explicitly admitted legacy
semantics, not evidence of equivalent future state.

Opening a valid older record for a pure read is not permission to silently rewrite
it. Initialization and committed mutations use schema 12. An authenticated
finite-use token decrement is itself a mutation, even when the requested action
is later denied. Such a request can promote the stored format. Failure before
publication does not make the candidate transaction authoritative.

Source tests in `identity_service_tests.rs` cover legacy and contradictory format
admission. Wrapping/SSH/database tests cover their additional owned state.
`python scripts/validate_runtime_doc_truth.py` detects selected documentation
regressions; it does not replace native execution or prove all prose complete.

## Rollback and storage envelopes

The application discriminator is separate from HBS2/HBJ2/HBL2/HBA1 storage and
HA framing. An old binary must refuse unsupported state, not deserialize only
fields it happens to know. Keep a schema-12-capable rollback binary with compatible HA and provider formats.

V4 owner publication derives an authenticated write set from the next manifest:
changed and reused owners are classified by content digest, and staged or retired
owner chunks must belong to a changed owner. The only exception is the explicit
one-time cleanup of legacy `state-chunks/*` resources during format migration.
The service validates this write set before the durable batch is admitted. This
protects the local owner boundary; HA still serializes the complete logical state
and therefore remains outside the record-oriented scalability gate.
A schema-11 binary must fail closed once bounded RADIUS mount state has been committed;
A schema-9 binary must fail closed once authentication-plugin mount state has been committed;
A schema-8 binary must fail closed once explicit namespace catalog state has been committed;
a schema-7 binary must fail closed once Kubernetes secrets-engine state has been
committed; a schema-6 binary must fail closed once LDAP group synchronization
state has been committed. Never lower `State.schema`, delete new fields, reset
revocation/tombstone state or restore an old snapshot to make a binary start.

A schema-1→2 or schema-2→3 rehearsal only proves its tested historical pair. It is
not a schema-12 rolling upgrade receipt. Mixed-version cluster operation, source
format conversion and production disaster recovery require separate exact-binary
rehearsals. Backup export uses HeptaBao's encrypted format, not OpenBao `raft.snap`.
Local restore is refused in HA mode. Restoring database provider records is also
refused: a local snapshot cannot revoke or reconcile an external database role.

## External state and uncertainty

OIDC code flow removes its encrypted, independently client-proven session before
upstream exchange, then commits token and live Identity together. Expiry denial
is durable; uncertain exchanges are not retried. Kubernetes login performs one
verified online TokenReview per attempt and commits only a bounded nonrenewable
local token. Read [online authentication](../auth/HEPTABAO_ONLINE_AUTHENTICATION.md).

The separate Kubernetes secrets-engine profile commits an issuance intent before
calling the host-enrolled Kubernetes TokenRequest API outside the global Service
writer. The returned JWT is checked for the requested ServiceAccount subject,
audience and bounded expiration before the terminal lease metadata is committed
and the token is released. A lost/ambiguous provider response or a post-provider
local failure retains the intent and forbids automatic retry because another valid
token may already exist. Pre-existing ServiceAccounts are supported in this
profile; automatic ServiceAccount/RBAC creation and full lease-revocation parity
remain outside schema-8 completion.


Database issue/renew/revoke commits a pending intent before TLS/SCRAM provider
entry, verifies independent readback and commits the terminal local result before
releasing a credential. Schema 6 also persists one cluster-bound monotonic provider
fence. PostgreSQL provider v2 advances the corresponding compact external fence
before acknowledging each effect. A confirmed revoke is retired only after a
separate provider-side retirement and readback remove the generated role and
per-lease provider row; the monotonic fence remains, so delayed lower-sequence
traffic cannot resurrect that authority. Missing or ambiguous responses retain the
local pending intent and are never blindly retried. Database PITR or provider-ledger
rollback is outside this format contract.

Raft membership and persisted snapshots are native consensus facts, distinct from
Service configuration. Read [the Raft administration contract](../operations/HEPTABAO_RAFT_ADMINISTRATION.md).
No local schema or authenticated snapshot is an external monotonic rollback anchor.

## Verification and release distinction

Build the exact candidate with the locked toolchain and dependencies. Execute all
workspace tests, strict lint, documentation checks, real TLS, real PostgreSQL,
loopback HA and fixed-binary differential profiles separately. Record source head,
tree, tool and binary digests, process outcomes and applicable unmet prerequisites.
Do not inherit an earlier head's result. A failed or missing prerequisite remains
blocked; two failed implementations do not demonstrate compatibility.

This contract grants no full OpenBao compatibility, independent qualification,
production, migration or release authority. Hardware custody, independent review,
multi-host destructive tests and operational admission remain external evidence.
