# Current Service state format and upgrade boundary

Current plan: `HEPTABAO-PLAN-2026-09-07-V2.1`. This is the current format contract,
not a new project plan. It supersedes current-tense schema-2/schema-3 descriptions
in retained increment notes. Exact source remains authoritative.

## Source and authoritative ownership

The current Service state schema is **40**. Its source constant is
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
namespace state. Schema 10 adds durable
authentication-plugin mount bindings: the deployment plugin id is paired with
server-owned policy and token-lifetime limits. The external plugin can return only
an authentication decision plus a bounded alias; token authority and Identity
binding remain inside the Service transaction. Schema 11 adds structured direct
AppRole renewal provenance. It binds a token to its issuing namespace, mount and
role name so renewal re-reads live role and mount limits; token-API children do
not inherit this issuer authority. Old binaries must reject this state rather
than use display names or stale issuance limits. Separate seal metadata uses
schema 1; the application schema must never be inferred from that number. Schema
13 adds bounded namespace seal flags and ancestor request-routing fences. The flag
is encrypted by the existing global barrier; independent per-namespace key
custody, rotation and parent/sibling key separation remain open.

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
| 12 | Adds bounded RADIUS PAP mount state with a schema fence. |
| 13 | Bounded namespace seal flags and routing fences; independent per-namespace key custody remains open. |
| 14 | Adds bounded OpenLDAP dynamic-secret intents, owner/expiry fences, retained-DN tombstones, and local snapshot rollback fences. |
| 15 | KV v2 metadata CAS requirements and independent metadata versions; RADIUS renewal and explicit token-API provenance must be absent. |
| 16 | Direct RADIUS renewal credentials and explicit token-API provenance; LDAP renewal and external identity membership evidence must be absent. |
| 17 | Direct LDAP renewal credentials and provider-verified external identity membership evidence; JWT direct-role provenance and nonzero JWT periodic/explicit-max role fields must be absent. |
| 18 | Direct JWT role provenance and distinct periodic/explicit-max JWT role limits; native-claim marker, optional trust extensions and role leeways must be absent. |
| 19 | Native reusable JWT assertions, optional explicit trust extensions, role time leeways and retired legacy JWT replay enforcement. New AppRole tokens also persist only their issue-time explicit maximum. Kubernetes renewal provenance and extended role limits must be absent. |
| 20 | Direct Kubernetes role provenance and native role/mount TTL, periodic and explicit-maximum limits. OIDC renewal provenance and extended role limits must be absent. |
| 21 | Direct OIDC role provenance and native role/mount TTL, periodic and explicit-maximum limits. Nonzero RADIUS period/explicit-maximum configuration and direct periodic RADIUS tokens must be absent. |
| 22 | RADIUS periodic and explicit-maximum configuration, direct periodic token snapshots and empty configured RADIUS policy sets. Native LDAP state must be absent. |
| 23 | Native LDAP manager-search configuration, optional user mappings, direct-token credentials bound to the issued alias and opaque Identity aliases. Native RADIUS configuration, user-map mount entries and provenance must be absent. |
| 24 | Native RADIUS host/secret/NAS/timeout configuration, optional user mappings and direct-token credentials with issued metadata. LDAP API-owned transport and extended RADIUS default-policy state must be absent. |
| 25 | Native LDAP URL/CA/timeout transport authority and native RADIUS default-policy semantics; RADIUS API transport authority must be absent. |
| 26 | Administrator-configured RADIUS target authority without process endpoint enrollment; token source CIDR constraints must be absent. |
| 27 | Native RADIUS source CIDR configuration and issued-token source constraints; JWT/OIDC API-owned HTTPS transport and nonempty inactive JWT CA readback fields must be absent. |
| 28 | Administrator-configured JWT/OIDC HTTPS transport and source-specific CA fields; native LDAP CIDRs and Kubernetes API HTTPS authority must be absent. |
| 29 | Native LDAP source constraints and administrator-configured Kubernetes authentication HTTPS transport; JWT bound-claim predicates and native LDAP default-policy metadata must be absent. |
| 30 | Native JWT bound-claim rules and native LDAP default-policy and policy-list-presence semantics; Kubernetes role and direct-token source constraints must be absent. |
| 31 | Kubernetes role source constraints and their issued-token snapshots; zero JWT role TTL or maximum must be absent. |
| 32 | JWT role zero-value TTL and maximum inheritance; system default and Token API grant metadata must be absent. |
| 33 | Persisted system lease defaults and the last granted Token API lease duration; zero AppRole token TTL/max and SecretID issuance metadata must be absent. |
| 34 | Native AppRole token TTL inheritance and SecretID issuance facts; native userpass limits, configured policy semantics and direct issuer provenance must be absent. |
| 35 | Userpass TTL/max inheritance, period/explicit maximum, configured policies without implicit default, and direct issuing-account provenance; KV1 record roots must be absent. |
| 36 | Adds authenticated KV1 record graphs and the V5 publication root. Legacy inline KV1/V4 state remains admitted until its explicit write-side transition. PackedLeaf pages must be absent throughout the graph. |
| 37 | Adds PackedLeaf object kind6: small KV1 values can reside directly in authenticated leaf pages. Prior kind1–5 encodings remain unchanged. |
| 38 | Explicit native userpass password input semantics and imported bcrypt credentials. An absent marker retains historical exact-byte PBKDF credentials; newly written plaintext credentials use the first 72 bytes at login. Imported bcrypt uses a mutually exclusive credential representation. |
| 39 | Native userpass CIDR constraints, default-policy/list-presence semantics, and HA native restore as a new publication. Restore advances the live replay epoch and does not rewind local or Raft durability. Userpass name modes must be absent. |
| 40 | Fresh native userpass mounts persist ASCII-lower account-name mode. Absent modes preserve historical exact accounts and issued-token provenance; old mounts and Identity aliases are never silently folded. |
| Other or contradictory version/content | Fail closed; do not repair the discriminator or drop unknown state. |

Every schema 1–4 record additionally rejects online authentication state or a
new online method registry entry. Schemas below 5 reject a nonzero replay epoch;
schemas below 6 reject a nonzero database provider fence. Schemas below 7 reject LDAP group-search configuration or group-to-policy
mappings. Schemas below 8 reject Kubernetes secrets-engine mounts/state. Schemas below 10 reject durable authentication-plugin mount bindings. Schema 11 is required when any token carries AppRole renewal provenance. Schema 12 is required when any RADIUS mount state is present. Schema 13 is required when any namespace seal flag is present. Schema 14 is required when any OpenLDAP secrets-engine mount or durable dynamic-secret intent is present. Schema 15 is required when KV v2 has a metadata CAS requirement or a nonzero metadata version. Schema 16 is required for direct RADIUS renewal credentials or explicit token-API provenance. Schema 17 is required for direct LDAP renewal credentials or external identity membership evidence. Fields omitted from
legacy records are default-empty/zero only for explicitly admitted legacy
semantics, not evidence of equivalent future state.

Schema 35 keeps old positive userpass settings, configured default policies and
issued caps unchanged. New direct tokens record the issuing username separately
from display names, and renew from that account's current limits and policies.
Old parentless tokens without issuer provenance retain their active permissions
but require login again to renew; the account is never guessed from display names.
Read-only reopen does not migrate these fields or rewrite old application bytes.

Schema 18 is required for direct JWT role provenance or nonzero JWT role period
and explicit maximum fields. JWT time claims are checked at login admission; a new
JWT service token is bounded independently by its role and mount. Its stored
absolute maximum represents only the explicit maximum captured at issuance;
ordinary role/mount maxima are reread at renewal and measured from issue time.
Old JWT tokens keep their recorded expiry and maximum. Old parentless JWT tokens
without provenance must log in again to renew; old children with a parent keep
their ordinary token-API renewal. New token-API children do not inherit JWT roles.

Schema 19 is required for native JWT state. Stored legacy trust-limit numbers
remain explicit constraints; absent values in new configurations select native
role time semantics. A successful native login clears only that JWT mount's old
assertion replay entries and watermark, and marks their retirement in the same
transaction as token/identity issuance. Failed logins do not perform this migration.
This does not retire OIDC sessions, MFA proofs or the durable operation ledger.
Old AppRole absolute maxima remain conservative because the stored value cannot
distinguish a former ordinary maximum from a true explicit maximum; a fresh login
uses current role/mount maxima and freezes only the true explicit cap.

Schema 20 is required for direct Kubernetes renewal provenance, empty configured
Kubernetes role policy sets, zero/default or
greater-than-one-hour Kubernetes role TTLs, and nonzero role maximum, period or
explicit maximum fields. New Kubernetes tokens renew locally against the current
issuing role without another TokenReview. Policies and the explicit maximum remain
their issue-time values. Legacy Kubernetes tokens remain nonrenewable; a fresh
login is required to obtain native renewal provenance. Token-API children and
orphans do not inherit it. JWT, AppRole and Kubernetes share lifetime arithmetic,
while each method retains its own issuer validation.

Schema 21 is required for direct OIDC renewal provenance, empty configured OIDC
role policy sets, zero/default or greater-than-one-hour OIDC role TTLs, and
nonzero role maximum, period or explicit maximum fields. New OIDC service-token
leases are independent of the ID token's remaining lifetime and renew locally
against the current role. Old tokens remain nonrenewable. Omitted new role fields
preserve old serialized role/config bindings so valid pending sessions can finish
after upgrade; session consumption remains durable and one-use.

New finite RADIUS and LDAP tokens no longer store ordinary provider maxima as
fixed absolute caps. Renewal rereads current limits from issue time. Legacy
absolute caps remain conservative; a fresh login is required to benefit from a
raised maximum. Their existing credential provenance and provider-revalidation
requirements are unchanged.

Schema 22 is required for nonzero RADIUS configuration period or explicit maximum,
empty configured policy sets, and direct RADIUS tokens carrying an issued period.
The token marker remains required even if configuration is subsequently reset.
New logins capture only the explicit maximum as an absolute cap. Provider-checked
renewal uses the current period and ordinary maximum while token lookup retains
the period recorded at issuance. Configured policy readback contains only the
configured list; login adds the implicit default policy. Legacy nonempty policy
lists and existing absolute caps are preserved when omitted from an update.

Schema 23 is required for native LDAP configuration, nonempty native user mappings
or direct native LDAP token provenance. Manager passwords and direct user renewal
credentials remain encrypted and zeroize when dropped. Native mapping absence is
valid authority and participates in the concurrency check. Old bounded LDAP
configuration and its required local user/MFA mappings retain their behavior;
switching either profile in place is rejected. A fresh mount selects the new
profile. Native renewal retains the issued alias while rechecking current
directory credentials, groups and configured token policy/lifetime limits.
Identity entity/group aliases now preserve provider names, including spaces and
Unicode, up to 1024 bytes without control characters. Their mount-scoped index
encoding is unchanged. Alias shapes outside the old identifier grammar require
schema 23, including aliases created directly through the Identity API. Entity
names, group names and identifiers retain their existing grammar; directory group
observations retain their 256-byte name budget.

Schema 24 is required for native RADIUS configuration, direct native provenance
or a native user-map mount entry, including an empty entry left after deleting
the last mapping. That entry permits users to be configured before the provider
and prevents a later silent switch to the old URL profile. Native configuration
retains an encrypted, zeroizing shared secret; runtime endpoint registration
grants a fixed socket address but need not carry that secret. Issued username and
policy metadata survive renewal and lookup. Children and orphans retain their
own token-API provenance without provider credentials or metadata.

Schema 25 is required for native LDAP API-owned transport. New native mounts
use configured LDAPS URLs, optional certificate roots and connection/request
timeouts without process endpoint enrollment. Old native records with no
`transport` field retain the process-enrolled authority until an administrator
explicitly writes `certificate`, `connection_timeout` or `request_timeout`.
Unrelated partial updates preserve the old transport mode. The owned config
snapshot participates in login/renewal revision checks; late observations cannot
publish after a URL, CA or timeout change. Reading an old record does not migrate
its transport or storage. Old binaries must reject this state after mutation.

Schema 25 also records native RADIUS `token_no_default_policy` and whether new
configuration explicitly supplied `token_policies`. The latter preserves the
upstream difference between nil and an explicit empty list during zero-policy
token renewal. Missing presence state in old schema-24 records retains its prior
normalized-list behavior; no guessed reconstruction occurs. A direct native token
without `default` also requires schema 25 even if configuration later resets the
flag, since issued policies remain unchanged during renewal.

Schema 26 is required for native RADIUS API-owned transport. Fresh configuration
uses the administrator's host, port and shared secret directly, including DNS
and IP targets. Old records with no internal `api_transport` marker remain
process-enrolled. An explicit host or port write promotes the configuration even
when the stored target text is unchanged; secret, token-policy and timeout-only
updates preserve the old transport authority. Neither login nor read performs
this promotion. The marker participates in existing configuration revision checks,
so an in-flight provider success cannot cross the promotion boundary.

Schema 27 is required if a native RADIUS configuration or any issued token has
nonempty source CIDRs. Missing fields deserialize as empty and remain omitted
from stored JSON. A token retains its issuance-time constraints when current
configuration changes or clears them; this keeps the schema fence active after
configuration reset. Ordinary token children inherit constraints, while orphan
and nonexpiring root-token children follow the existing independent authority
rules. Request peer addresses are transient trusted inputs, not stored tokens.
HBFQ3 carries the accepted client socket address inside authenticated HA frames.
Older frames remain readable without a peer; constrained tokens reject missing
peers, and forwarding never retries by stripping source information.

Schema 28 is required for JWT or OIDC configuration containing API-owned HTTPS
transport, or a nonempty inactive JWT CA readback field. Fresh remote configuration
selects API transport: the active `jwks_ca_pem` or `oidc_discovery_ca_pem` field is a
replacement trust store, while empty, null or omitted CA selects system roots.
An older record with no internal `transport` field remains `None` and serializes
without that field. A complete config rewrite that omits its active CA preserves
that old enrollment authority; an inactive CA field alone cannot promote it.
Only an explicit active CA write, including empty or null, selects API transport
for such a record. Once promoted, later omitted CA follows full configuration
replacement and selects system roots. Static-key JWT configuration has no remote
transport. Pure reads and login do not perform this authority migration.

The owned URL/CA snapshot participates in remote configuration and login fences.
Successful OIDC configuration publication clears pending sessions atomically;
failed preflight or stale authority preserves both the old config and its sessions.
Unchanged old config/role serialization preserves a pending session's existing
binding digest on reopen. No service token is reissued by transport migration,
and the one-use OIDC callback protocol is unchanged. A schema-27 binary must
reject schema-28 application state rather than ignore this authority.

Schema 29 is required for nonempty native LDAP source constraints in config or
direct-token snapshots, and for Kubernetes authentication config with API HTTPS
transport. The existing schema-27 gate still covers general token CIDRs and
RADIUS config; it does not retroactively require schema 29 for valid old RADIUS
state. LDAP config clear cannot remove the fence while a constrained direct
LDAP token remains. Ordinary children retain their existing token-API format.
Old LDAP records omit the empty field and preserve their serialized shape.

New Kubernetes authentication config requires explicit nonempty
`kubernetes_ca_cert`; it is a replacement trust store, never a request for system
roots. Old records without internal `transport` retain startup enrollment and
their required reviewer when a full config rewrite omits CA. Explicit valid CA
promotes them; reads, login and renewal do not. Once promoted, each full rewrite
must include CA. The optional native reviewer uses the presented JWT when empty,
without persisting that JWT or retrying after a configured reviewer fails.
The Kubernetes secrets engine keeps its separate transport and state contract.

Schema 30 is required for a JWT role carrying a typed bound-claims rule, including
an explicitly cleared map. Old roles omit the optional field and retain their
exact serialized shape. The original signature-verified claims are checked at
login; assertions or arbitrary claim maps are not saved with issued tokens.
Existing token renewal continues to use role limits without rechecking claims.

Native LDAP config also requires schema 30 when it records policy-list presence
or enables `token_no_default_policy`. New config distinguishes omission from an
explicit empty/null policy list. Old absent metadata retains the normalized
historical behavior because the original input cannot be recovered. Non-default
direct LDAP token snapshots retain the format fence even after config changes.
Issued policies remain fixed; config toggles affect future logins only.

Schema 31 is required for nonempty Kubernetes role `token_bound_cidrs` or direct
Kubernetes tokens with issued source constraints. Empty fields remain omitted
from old serialized roles. Clearing a role's constraint changes future logins;
it cannot remove issued token constraints or their format fence. Token-API
children retain inherited source constraints under the existing token format.

Schema 32 is required for a JWT role with zero TTL or maximum, which selects the
current mount's corresponding setting. Existing positive role values are not
reinterpreted as defaults. Null and omitted duration updates preserve existing
values; explicit zero changes the role to inheritance. Issued token policies,
period lookup snapshots and absolute explicit caps remain unchanged.

Schema 33 is required when system lease defaults or a Token API token's last
granted lease metadata is present. Fresh state records a 32-day system default
and maximum. Older missing defaults retain the historical one-hour default;
a successful Token API issue or renewal records that legacy default without
rewriting old roles or issued deadlines. Read-only access adds no metadata.
Mount tune reads resolve inherited values, while issuance clips them to the
live maximum. Ordinary Token API renewal without a positive increment uses its
previous grant, including after restart. Old tokens lack grant history and
retain the conservative historical one-hour renewal request until their next
successful grant is recorded. Ambiguous old absolute caps remain unchanged.
An old record's missing metadata is not evidence of native historical defaults.

Schema 34 is required for an AppRole token TTL or maximum of zero, or any
SecretID issuance metadata. New roles inherit token limits dynamically and
default SecretID lifetime and uses to zero. Historical positive values are
preserved. SecretID zero lifetime/uses alone never imply schema 34: older
versions already supported explicit zero. New issuance stores the original
requested TTL and creation/update times separately from the mount-clipped
expiry. Old records with missing facts retain their known expiry and remaining
uses without fabricated timestamps or TTL. Finite successful uses update the
record, and exhaustion removes it atomically with token issuance.

Schema38 requires an explicit `bcrypt_72` comparison marker for newly created or
replaced native userpass passwords. It describes input equivalence, while the
verifier remains PBKDF2-HMAC-SHA256 with 600,000 rounds. Older absent markers retain
complete-byte comparison and their 1024-byte login bound. Pure reads, empty/null
password updates and logins do not invent a credential marker. A successful login
still commits a token and can promote the application schema. The marker is
rejected under earlier schemas or outside a live userpass mount; unknown values
fail decoding. Startup, HA materialization, publication and prepared restore share
this validation.

An `imported_bcrypt` credential also requires schema38 and a live userpass mount.
Its presence requires empty PBKDF salt/verifier, zero PBKDF rounds and no input
marker. Admission revalidates the bounded Go-compatible cost header; malformed
salt/hash data never enables fallback to a second credential. The imported string
is encrypted with its owner and zeroized when dropped. Resetting to a plaintext
password removes it and installs a fresh PBKDF credential with `bcrypt_72`.

Opening a valid older record for a pure read is not permission to silently rewrite
it. Initialization and committed mutations use schema 40. An authenticated
finite-use token decrement is itself a mutation, even when the requested action
is later denied. Such a request can promote the stored format. Failure before
publication does not make the candidate transaction authoritative.

Schema39 fences nonempty userpass CIDR configuration and constrained direct-token
snapshots, default-policy/list-presence metadata and direct userpass tokens
without `default`. Fresh native accounts record whether a policy list was
omitted; older absent metadata retains its known normalized list without guessing
nil versus empty. Explicit policy writes, including null, establish list presence.
HA native restore publishes the current schema with the current live epoch plus one,
even when the archive predates these fields. Old readers reject the new root.

Schema40 requires the `ascii_lower_v1` userpass name mode only on fresh system
defaults, newly created namespaces and new userpass mounts. Under that mode,
stored account keys and explicit Userpass token provenance must be canonical;
unknown modes and mode-bearing non-userpass mounts fail admission. Omission
preserves legacy exact matching, including separate Alice/alice accounts and
renewal provenance. Reading, remounting or updating an old mount does not adopt
the new mode. Schema promotion alone cannot rename accounts or Identity aliases.

Source tests in `identity_service_tests.rs` cover legacy and contradictory format
admission. Wrapping/SSH/database tests cover their additional owned state.
`python scripts/validate_runtime_doc_truth.py` detects selected documentation
regressions; it does not replace native execution or prove all prose complete.

## Rollback and storage envelopes

The application discriminator is separate from HBS2/HBJ2/HBL2/HBA1 storage and
HA framing. Schema36 pure reads, exact no-op writes and rejected writes retain
their existing references and schema. A successful mutation promotes to the current schema;
schema36 binaries reject it. PackedLeaf detection includes every descendant,
so a Branch root cannot conceal a packed page under an older discriminator.
Local reopen, HA materialization, JSON/native prepared restore and publication
share this complete authenticated-graph check. An old binary must refuse unsupported state, not deserialize only
fields it happens to know. Keep a rollback binary compatible with the actual committed schema, HA and provider formats; a schema-35 binary cannot read schema-36 state or its V5 root.

Direct RADIUS and LDAP tokens retain bounded provider credentials inside encrypted Auth
state for provider-checked renewal. Credentials are zeroized on drop and are not
copied into token-API children. Old RADIUS/LDAP-associated tokens with a parent remain
ordinary token-API children. Old parentless tokens without issuer provenance
cannot be distinguished from old orphan children: only their renewal is rejected
with a request to log in again, leaving their existing permissions and expiration
unchanged. New token-API provenance removes this ambiguity for new orphan tokens.

External group membership evidence binds the entity alias, group alias and auth
mount accessor observed during successful provider authentication. Legacy or
manually supplied external member indexes are not provider evidence and do not
grant identity policies. LDAP login and renewal publish membership reconciliation,
identity projection and token changes together. Alias removal/rebinding invalidates
its evidence; disabling the auth mount removes its membership evidence. Another
mount accessor remains independently authoritative for its own observations.

V4 owner publication derives an authenticated write set from the next manifest:
changed and reused owners are classified by content digest, and staged or retired
owner chunks must belong to a changed owner. The only exception is the explicit
one-time cleanup of legacy `state-chunks/*` resources during format migration.
The service validates this write set before the durable batch is admitted. This
protects the legacy V4 owner boundary. Its HA representation still serializes
the complete logical state; the V5 KV1 path below uses a separate typed root.
A schema-23 binary must fail closed once native RADIUS configuration, user-map intent or token provenance has been committed;
a schema-22 binary must fail closed once native LDAP authority or opaque Identity aliases have been committed;
a schema-21 binary must fail closed once current RADIUS periodic or explicit-maximum semantics have been committed;
a schema-20 binary must fail closed once current OIDC renewal or role lifetime semantics have been committed;
a schema-19 binary must fail closed once current Kubernetes renewal or role lifetime semantics have been committed;
a schema-18 binary must fail closed once native JWT or current AppRole lifetime semantics have been committed;
a schema-17 binary must fail closed once JWT direct-role provenance or new role lifetime semantics have been committed;
a schema-16 binary must fail closed once LDAP renewal credentials or external membership evidence has been committed;
a schema-15 binary must fail closed once RADIUS renewal or token-API provenance has been committed;
a schema-14 binary must fail closed once KV metadata CAS state has been committed;
a schema-13 binary must fail closed once OpenLDAP mount or durable dynamic-secret state has been committed; a
schema-12 binary must fail closed once namespace seal state has been committed; a
schema-11 binary must fail closed once bounded RADIUS mount state has been committed;
A schema-9 binary must fail closed once authentication-plugin mount state has been committed;
A schema-8 binary must fail closed once explicit namespace catalog state has been committed;
a schema-7 binary must fail closed once Kubernetes secrets-engine state has been
committed; a schema-6 binary must fail closed once LDAP group synchronization
state has been committed. Never lower `State.schema`, delete new fields, reset
revocation/tombstone state or restore an old snapshot to make a binary start.

A schema-1→2 or schema-2→3 rehearsal only proves its tested historical pair. It is
not a current-format rolling upgrade receipt. Mixed-version cluster operation, source
format conversion and production disaster recovery require separate exact-binary
rehearsals. Backup export uses HeptaBao's encrypted format, not OpenBao `raft.snap`.
Local restore is refused in HA mode. Before changing durable files, the service
authenticates and inspects the incoming backup's system records in both the
V5 record-root, V4 owner-manifest and bounded legacy formats. V5 inspection
validates the complete referenced graph before examining external-effect owners. A backup
containing database provider records or OpenLDAP mount/dynamic-secret state is
rejected before restore, because a local snapshot cannot revoke or reconcile
those external identities. The same guard applies to the current durable state:
restoring database provider records is refused, and restore is refused while any
OpenLDAP mount exists. OpenLDAP dynamic credentials use a retained-DN tombstone
profile; this is an explicit bounded compatibility surface, not OpenBao delete
semantics.

## Schema 36: KV1 record publication

`state_records` owns the immutable ordered KV1 index; keys include namespace,
mount, incarnation and path. `EngineState` stores only `Kv1Records` mount metadata
in its serialized owner. The runtime graph is not serde state and cannot be
reconstructed from that owner alone. `state_record_root` authenticates the five
opaque owner descriptors, KV1 root, cluster, schema and replay epoch using a
persisted nonzero address key. That key and canonical root remain encrypted.

A valid V4 pure read or reopen does not convert storage. The first proven
mutation through ordinary logical dispatch converts the actual candidate to
`heptabao-state-records-v5`. Provider/lifecycle-only writes can remain V4 until
that transition. Once V5, those writers also use the record publication path;
they cannot publish a legacy JSON image that omits the runtime KV1 graph.

`service_records` preflights cumulative local capacity before HA authority.
At most 95 new objects and the root share one 96-mutation batch; larger closures
stage bounded object batches before the final root publication. Partial staging
is not application state. HBSM5 uses typed Stage/Publish/Prune commands and a
`RecordsV5` identity distinct from the legacy image digest. Reopening validates
canonical owners, object authentication and shape, the complete graph and mount
incarnations. Corruption or missing objects never select a legacy fallback.

Initial HA anchoring of an existing V5 installation supplies its full validated
closure, even though reopen has no pending delta. This is restricted to the
existing authenticated Absent-anchor path; anonymous health cannot create it.
Normal writes carry only changed values/pages and changed opaque owners.
Current readers pin complete Arc graphs. Periodic unreachable-object collection
uses the published root and bounded delete batches; failed publication never
clears a candidate's pending objects as if it had committed.

KV2, authentication/provider state and the other owners remain opaque JSON under
the shared 16MiB owner budget. Record layout is not a claim of unrestricted
capacity, full backup support or measured write scaling. The independent logical,
local durable and HA limits are specified in the [capacity contract](../operations/HEPTABAO_CAPACITY_AND_GROWTH.md).

## External state and uncertainty

OIDC code flow removes its encrypted, independently client-proven session before
upstream exchange, then commits token and live Identity together. Expiry denial
is durable; uncertain exchanges are not retried. Kubernetes login performs one
verified online TokenReview per attempt and commits only a bounded nonrenewable
local token in legacy formats. Current Kubernetes logins issue renewable service
tokens with role provenance; renewal does not contact the reviewer. Read
[online authentication](../auth/HEPTABAO_ONLINE_AUTHENTICATION.md).

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
