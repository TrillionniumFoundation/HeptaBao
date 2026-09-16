# Identity: current server state and development contract

This document describes the service-internal implementation in
`crates/heptabao-server/src/engines/identity.rs` and `identity_runtime.rs`,
composed through `service_identity.rs`, `auth_identity.rs` and
`engine_identity.rs`. Structural endpoints are now joined to bounded login and
live internal-group authorization in the actual Service. This is **not** the
separate `heptabao-identity` library's API or complete Identity/MFA/OIDC parity.
It supplements the V2.1 plan and current server module guide.

## Ownership and transactions

`NamespaceState.identity: IdentityState` belongs to `EngineState`. The actual
path is canonical HTTPS -> request audit -> Service authentication and ACL ->
`EngineState::handle` -> `identity::handle` -> isolated namespace candidate ->
Service encrypted commit -> response audit. For login, credential verification
precedes alias/entity association; auth and engine candidates publish in one
encrypted Service transaction. On authenticated requests, Service projects the
current entity/internal-group policies before ACL dispatch. The standalone
identity crate is not a runtime dependency and cannot authenticate a principal.

`IdentityState` contains an allocation counter and authoritative entity, alias,
group and group-alias maps with reverse name/key indexes. Namespace isolation
comes from the outer namespace map. Existing namespace state defaults an absent
identity field to an empty store. Entity/alias/group records reject unknown
persisted fields; the enclosing legacy IdentityState uses its existing serde
default behavior. This document does not add or claim schema hardening absent
from the source.

Mutation is serialized by the Service owner. EngineState clones a namespace,
publishes only a response marked mutated, and discards failed candidates. A
merge additionally stages its own IdentityState clone before atomic
replacement. A rejected cycle, conflict or malformed merge cannot partially
publish aliases, names or group membership through the Service. Persistence,
unknown-outcome fencing, response-audit withholding and HA state propagation
remain owned by the surrounding Service, not by an independent identity DB.

## Record schemas and limits

Entity fields are `id`, `name`, `disabled`, metadata, a policy-name set, alias-ID
set, direct group-ID set, merged-entity lineage and creation/update seconds.
Alias fields are `id`, `canonical_id`, `name`, `mount_accessor`,
`custom_metadata` and timestamps. Old alias serialized `metadata` can be read
as `custom_metadata`. Groups contain `id`, `name`, `type` (internal/external),
metadata, policy names, member entity IDs, member group IDs and timestamps.
Group aliases contain a canonical external-group ID, name, mount accessor and
timestamps.

The shared monotonically allocated identifier is `<prefix>-<32 hex digits>`:
`e` for entity, `a` for entity alias, `g` for group, `x` for group alias. Treat
IDs as opaque. They are not claimed to have OpenBao's UUID format. Exhausting
the counter returns 507. Name/identifier length is 1–128 bytes with the current
ASCII alphanumeric and `- _ . : @` alphabet; leading/trailing `.` is rejected.
Metadata permits 64 entries, keys up to 128 bytes and values up to 1,024 bytes.
Policies are bounded to 64 names. Membership/merge inputs are bounded to 256
IDs, and nested-group traversal has a depth bound of 32.

These input limits do not replace the aggregate Service state bounds (16 MiB local chunk/manifest persistence and the tighter 768 KiB HA proposal boundary)
or qualify a production-scale entity index. Live projection rejects more than
4,096 group records, 256 reached groups, depth greater than 32, or 256 effective
policy names. Login-created entity/alias maps each have a 4,096-record ceiling.
These are fail-closed development limits. Complete argument, normalization and
count-limit parity remains work for this surface.

## Route map

Routes below omit `/v1/`. Reads return 200/data, missing records 404, malformed
requests 400, duplicate names/alias keys 409 and unsupported methods 405.
Caller authorization may reject earlier. Explicit entity/group ID updates and
empty/idempotent deletes return 204 with no response body; creates return 200.
POST/PUT are the normal write methods. The internal Identity handler also
recognizes PATCH in its write helper; its presence is not a promise that every
HTTP/ACL/endpoint PATCH permutation is independently qualified.

| Resource | Current routes and behavior |
|---|---|
| Entities | `identity/entity` create/update by optional ID; `entity/id/<id>` and `entity/name/<name>` read, delete and update; list at `entity/id` and `entity/name` |
| Entity aliases | `identity/entity-alias` create; `entity-alias/id/<id>` read/update/delete; list at `entity-alias/id` |
| Groups | `identity/group` create/update; `group/id/<id>` and `group/name/<name>` read/update/delete; list at `group/id` and `group/name` |
| Group aliases | `identity/group-alias` create; `group-alias/id/<id>` read/update/delete; list at `group-alias/id` |
| Lookup | POST/PUT `identity/lookup/entity` or `identity/lookup/group`; choose exactly one selector |
| Merge | POST/PUT `identity/entity/merge`; atomic alias/membership/lineage rewrite |

Lookup selectors are `id`, `name`, `alias_id`, or the pair `alias_name` and
`alias_mount_accessor`. More than one selector is an error. Lists return sorted
keys; ID entity/group lists additionally expose the currently implemented
`key_info` projection. Empty list behavior and all accepted parameter
permutations require the full differential corpus, not extrapolation from a
successful create/read pair.

Entity reads report `direct_group_ids`, transitively inherited group IDs and
their union. Timestamps are rendered by the existing RFC3339 formatter.
`merged_entity_ids` is null when empty. Entity/group updates preserve omitted
name, metadata, policies, disabled/type and membership fields; initial manual
creation requires a name. Supplied IDs must identify an existing record, body
and path IDs must agree, unknown fields are rejected, and group type is
immutable. This prevents recreating deleted identifiers to revive old tokens.
Alias update dialects and complete endpoint parameter parity remain separate
work; entity/group preservation must not be generalized to every endpoint.

## Alias and group invariants

The `(mount_accessor, alias name)` reverse key is unique. One entity cannot
hold two aliases for the same accessor. A canonical entity must exist before
an alias is attached. Reassignment removes the old entity/index reference and
updates the new one within the candidate. Entity deletion removes aliases and
references from direct groups. Group aliases require a canonical group of
type `external`; they are not executable external authentication providers.
Service additionally requires supplied alias accessors to name a current auth
mount in that namespace. Only a successfully verified login creates the private
`LoginIdentity` used by Service; arbitrary alias JSON is never a credential.

Group writes verify referenced entities and groups, reject self-membership,
and run depth-bounded cycle detection. Direct memberships update entity
reverse links. Inherited memberships are computed from parent relationships.
The current code's alias/group cardinality and update dialect must be compared
against OpenBao before claiming the broader surface complete.

## Merge algorithm and failure semantics

The request requires `to_entity_id` and nonempty `from_entity_ids`. All entities
must exist; destination-as-source is rejected. `conflicting_alias_ids_to_keep`
is a bounded explicit set of alias IDs. `force`, when supplied, must be boolean.

The implementation stages a complete identity candidate. It moves
nonconflicting source aliases to the destination and rewrites canonical IDs.
Where a source and destination have aliases for the same mount, exactly one
of the two IDs must be selected to survive. A conflicting merge with multiple
sources is explicitly rejected; perform qualified one-source steps instead.
An unconsumed/irrelevant keep-ID is also rejected. The losing alias and reverse
key are removed only in the staged candidate.

After validation, source names/entities are removed, group membership is
rewritten to the destination, and direct groups plus transitive
`merged_entity_ids` lineage are retained. Destination timestamps advance; the
candidate replaces state only after success. This does not claim a union of
all source policy names or metadata. A lost successful response requires
readback/reconciliation, not blind automatic resubmission of a now-missing
source entity.

**`force` does not currently merge MFA secrets.** Identity-owned MFA secrets are
not part of this state model. Existing bound tokens follow only explicit
`merged_entity_ids` lineage to the current destination. Missing entities or
multiple possible successors fail closed; display-name reuse cannot rebind a
token. Deletion or disabling blocks future requests. Disabling itself does not
revoke the token, so enabling that same entity may restore a nonrevoked token.

## Operations, evidence and open integration

The inherited source tests are
`entity_alias_group_lifecycle_is_deterministic`,
`entity_merge_moves_aliases_groups_and_records_lineage`, and
`nested_group_cycles_are_rejected_without_committing_candidate` in the server
engine. Run them together with all Service, auth, durable and HA regressions:

```sh
cargo +1.98.0 test --locked -p heptabao-server --all-targets
python scripts/validate_repository_v2.py
python scripts/validate_current_documentation_semantics.py
```

These are commands/test anchors, not stored pass receipts. Safe audit events
come from the outer Service and must not include credential-like metadata.
The implementation does not create a separate metrics exporter or index
recovery daemon. State inspection and migration must preserve counters,
records and reverse indexes together with encrypted Service state.

## Bounded live login and policy projection

A successful Userpass login uses its verified name, AppRole its verified role ID,
and the pinned-key JWT profile its verified subject. The identity key is
namespace + mount accessor + alias name. JWT subjects and custom role IDs must
fit the present 128-byte Identity alphabet; broader mappings are unsupported.
Login resolves an existing alias or atomically creates an entity and alias.
Disabled identity, inconsistent alias index or capacity failure aborts issuance.
Token creation and alias/entity writes share the existing Service commit and
result-audit withholding rules. No independent entity writer is introduced.

A persisted token carries optional `entity_id`. Every admitted request projects
entity and transitive **internal** group policy names from current authoritative
group records, not reverse indexes or a frozen token grant. Root policy names,
cycles, missing entities, excessive expansion or ambiguous lineage reject.
The winning ACL pattern is selected across token and live identity policies;
deny at the selected pattern dominates. Child tokens retain the entity binding,
but cannot promote identity policy names into durable token-policy grants.
Responses distinguish `token_policies` and `identity_policies`.

Mounts persist optional `accessor`. Legacy missing fields produce a deterministic
namespace/mount/type-separated value without a read-side write. New/re-enabled
mounts receive random accessors, so a replacement mount cannot silently inherit
a previous identity. Old tokens lacking `entity_id` remain unbound; no alias/name
heuristic upgrades them. Operators must treat re-enrollment as a separate action.

The current HA request path synchronizes state under ReadIndex before Service
admission, after which live projection uses that one snapshot. No cache permits
a revoked group policy to survive a later synchronized snapshot. This is a
source design, not destructive multi-host invalidation qualification.

Actual caller cases in `identity_service_tests.rs` cover existing-token
policy removal, disable/re-enable, restart, nested groups and group-membership
removal, child attenuation, merge/deletion/name reuse, namespace and remount
isolation, and token/alias nonpublication when a login commit exceeds capacity.
The `identity_runtime.rs` tests cover corrupt cycles, ambiguous lineage and
partial-update rejection. Run `cargo +1.98.0 test --locked -p heptabao-server
--lib identity_` (one shell line). No test command here is a pass receipt.

Open work includes external-group login synchronization, complete subject and
claim mapping, templated policy expansion, alias update/parameter semantics,
MFA enrollment/merge, OIDC provider/JWKS/key rotation, full endpoint/error/list
parity, migration formats and destructive HA invalidation evidence. The frozen
60-surface corpus is unchanged: targeted native tests do not close a broad
compatibility surface or manufacture an independent observation. Compatibility
and production admission remain unqualified.

## Selected official-binary differential profile

`qa/openbao-acceptance/identity_live.py` starts fresh, verified local TLS servers
using the exact OpenBao 2.6.2 archive/executable pins in the existing Oracle
launcher. Its ordered profile compares status/semantic observations: alias
binding, repeat login, live entity/internal-group grants, disable/re-enable,
child binding without copied policy grants, metadata-preserving updates,
policy definition changes and entity deletion. It validates exact HTTP status,
not a permissive union of success codes, and compares normalized booleans rather
than random IDs or credentials. Initial development observations identified the
204/no-body contract for explicit existing entity/group-ID updates; the server
now uses that contract rather than its previous 200/data reply on those routes.

This profile is separate from the frozen full-surface acceptance corpus. It
cannot establish complete error precedence, all Identity routes, independent
observation, the full 60-surface denominator, production or migration admission.
Results bind both binary digests, the source commit/tree, dirty state and runner
hash. Failed prefixes and equal empty traces must not be accepted. The harness
stops both processes and removes synthetic private fixture roots on exit.

## State-format migration and downgrade fence

Identity-aware writes are committed with Service `State.schema = 2`. Valid
schema-1 state with no new bindings remains readable without rewriting its
canonical bytes. The first durable mutation (including finite-use admission)
publishes version 2 in the same transaction; initialization also uses version 2.
A schema-1 payload with new bound-identity/accessor fields and any unknown
version are rejected. The pre-integration binary's schema-1-only reader then
refuses upgraded state, rather than silently discarding identity enforcement.

`qa/openbao-acceptance/identity_upgrade.py` compares a supplied, checksum-bound
legacy executable with the current binary using only private local fixtures:
old state is initialized, read by the new process, mutated by a bound login,
refused by the old process, then reopened by the new process with the disabled
entity still enforced. An old binary refusing a new format is a downgrade
fence, not a supported rollback procedure. Preserve binaries capable of the actual persisted schema,
current token revocations and full encrypted state. Rollback by restoring a
stale backup, external monotonic anchoring, mixed-version HA and general OpenBao
migration remain separate, unqualified capabilities.

### Subsequent runtime format

The current wrapping/SSH-OTP increment writes Service schema 3 and preserves
read-only access to valid older identity-aware schema 2 state. It extends the
same old-reader rejection rule; it does not make schema downgrade or mixed-version
rolling HA upgrades safe. See `../auth/HEPTABAO_RESPONSE_WRAPPING.md`.
