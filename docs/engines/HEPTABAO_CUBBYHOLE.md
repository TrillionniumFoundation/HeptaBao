# Cubbyhole: current service implementation

This is the current implementation contract for the built-in token-private
storage in `heptabao-server`. It supplements the V2.1 plan, the server module
guide, and `HEPTABAO_SINGLE_NODE_AUTH.md`; it does not replace those authorities.
It does not implement the full OpenBao response-wrapping and cubbyhole
surface. A bounded wrap/create/unwrap/replay fixture is now wired into the
fixed compatibility corpus; the combined surface remains partial.

## Ownership and actual call path

The HTTPS parser creates a canonical request. `Service::handle_at_mode` writes
the request audit, `handle_inner` authenticates and durably admits any finite
use, and `Service::dispatch` calls `AuthState::handle`. The latter dispatches
`cubbyhole` and `cubbyhole/*` to `AuthState::cubbyhole_route` in
`crates/heptabao-server/src/auth_cubbyhole.rs`. It is an actual Service route,
not the standalone KV or token model crate. No new workspace dependency exists.

`AuthState::Token` owns a private `TokenCubbyhole`. Its serialized map is
`namespace -> canonical relative path -> JSON object`. Namespace and path are
separate dimensions, not a string joined with an ambiguous delimiter. The
outer token index is the existing bearer digest. A caller cannot choose the
owner through a JSON field, path prefix, root permission or a mount descriptor.
Even a root token reads its own map rather than another token's map.

Namespace permission is checked before access. A non-root principal cannot
select another namespace. A root token using multiple namespaces receives
separate maps. Tokens issued by the token API, userpass, AppRole, JWT and
initialization start with empty private storage; issuance never copies a
parent's storage. Persisted pre-increment tokens deserialize an absent
`cubbyhole` field as an empty map through `serde(default)`.

## HTTP operations

Paths below include `/v1/`; the internal method receives paths without it.
Successful reads use the normal `data` envelope. Unknown/invalid tokens and
policy denials return 403. Missing values or an empty list return 404.

| Method and path | Request and response | Required capability |
|---|---|---|
| `POST` or `PUT /v1/cubbyhole/<path>` | A nonempty JSON object replaces the entire existing object; success 204 | `create` for a new path, `update` for an existing path |
| `GET /v1/cubbyhole/<path>` | 200 and `data` containing the stored object | `read` |
| `HEAD /v1/cubbyhole/<path>` | Existence/status through the HTTP layer, without response bytes | `read` |
| `DELETE /v1/cubbyhole/<path>` | Exact-path deletion, including missing-path idempotence; 204 | `delete` |
| `LIST /v1/cubbyhole[/<folder>]` | Sorted immediate child names; subdirectories end with `/`; 200 | `list` |
| `GET /v1/cubbyhole/<folder>?list=true` | Same list behavior; the canonical parser translates the query | `list` |

LIST authorization uses a directory prefix ending in `/`. Listing a file does
not read its value or return the file itself. Deleting a folder name is not
recursive deletion. Empty read/write/delete paths are rejected. Read/delete
control objects reject unknown fields; LIST accepts only its optional true
`list` selector. Write objects are secret data rather than control arguments;
a field named `token`, for example, cannot redirect ownership.

Canonical path and namespace validation remains in the shared Service/HTTP
boundary. Traversal, encoded separators and other noncanonical paths never
become storage selectors. Unsupported methods return 405. Oversized encoded
values return 413; per-token entry exhaustion returns 507 without publishing a
new value. The outer HTTP body limit may reject earlier.

`sys/mounts` and `sys/mounts/cubbyhole` expose a built-in descriptor. The mount
cannot be replaced, disabled, relocated or instantiated as another mount. This
increment does not add full Cubbyhole mount-tuning compatibility.

## ACL selection and default policy

The built-in default policy now contains
`path "cubbyhole/*" { capabilities = ["create", "read", "update", "delete", "list"] }`
in addition to token lookup-self, renew-self and revoke-self. Explicit namespace
`default` policy content overrides the built-in definition. A token issued with
`no_default_policy=true` has no implicit Cubbyhole access.

`auth_acl.rs` chooses the highest-priority matching pattern. It combines
capabilities only for that identical pattern across attached policies, with
`deny` prevailing within the selected union. Priority is determined by later
first wildcard, absence of a terminal glob, fewer whole-segment `+` wildcards,
longer path and then lexical order. The default policy goes through the same
selection logic. A broad grant therefore cannot override a more specific
read-only policy. This is a deliberate behavior change from the previous
all-matches union; review policies before any candidate rollout, including a
broad deny and narrower grant. Parameter constraints and identity templating
remain outside this implemented ACL dialect.

## Admission, final use and durability

The Service already commits finite token use before dispatch, including a
request later denied by ACL. Authentication creates one private request-local
`Principal`; it cannot be supplied by an external caller or reused for another
request. On the token's last permitted use, authentication also clears its
stored Cubbyhole in that same admission transaction. The current Principal
retains a transient copy sufficient for the admitted final read. A final write
or delete may return success but cannot recreate values under the exhausted
token. A final request to another route or a final denied request also leaves
no current values for that token in the admitted state.

Non-final mutations are applied to the existing isolated auth candidate. The
Service compares/persists complete encrypted authoritative state before
releasing a response. Failure of persistence withholds the response and retains
the existing recovery/unknown-outcome handling. Response audit failure likewise
withholds plaintext. No new automatic retry is introduced; a failed or lost
nominal read may still have consumed a finite use.

There is one Service transaction mutex and the existing durable writer fence.
Two concurrent requests cannot independently spend the same final use through
that boundary. Optional HA uses the same committed Service state, current
leader routing and ReadIndex path. The increment does not by itself qualify
cross-host failover, stale leader recovery, rolling upgrades or the operating
system storage profile.

## Revocation, expiry and retention

Explicit token revocation removes the token and its private map; descendant
revocation uses the existing token-tree behavior. Expired, revoked-parent and
exhausted tokens cannot authenticate. Expiry cleanup uses the existing bounded,
explicit `auth/token/tidy` operation. There is no new autonomous expiry worker
in this increment: expired data can remain encrypted in current state until a
tidy pass removes the corresponding token. Descendants of an exhausted parent
are inaccessible but may likewise await cleanup.

Removing current state is not forensic deletion of older journal records,
snapshots, backups or allocator/provider copies. Existing encrypted retention,
compaction, rollback-protection and backup obligations remain. A host clock
rollback is not solved by this backend and requires the existing trusted-time
and external-anchor qualification work.

## Bounds, memory and observability

One token can hold at most 256 entries across its namespaces. Each encoded
value is limited to 256 KiB. The outer normal HTTP body ceiling and the
inherited **768 KiB aggregate Service state** ceiling still apply. This
increment does not lift the development-scale storage bottleneck or claim a
production throughput target. Serialization, cloning and policy evaluation
must be included in later capacity measurements.

Owned replaced/deleted JSON values, map keys and namespace strings are cleared
before release where ownership permits. Serialized value-size buffers use
`Zeroizing`. Lookup/renewal responses never include the private map. Audit
retains safe keyed fingerprints and status rather than bearer tokens, path
content or stored values. No new metrics exporter is added.

## Executable verification

`auth_cubbyhole_tests.rs` checks token/root/namespace isolation, shallow listing,
replace/delete behavior, create versus update, final-use snapshots, old-schema
loading, expiry/tidy, revocation and bounds. `cubbyhole_service_tests.rs` enters
only through public `Service`, including encrypted restart, finite-use denial,
parent revocation, mount protection and ACL narrowing. `auth_acl.rs` includes
order-independent winning-pattern/deny tests.

Run the workspace Rust gates plus:

```sh
cargo +1.98.0 test --locked -p heptabao-server --all-targets
python qa/openbao-acceptance/core_isolation.py \
  --binary /absolute/heptabao-server --output /private-mode-0700/result.json
```

The comparison script creates new isolated TLS services and synthetic data,
requires the checksum-pinned official binary/archive via `HB_ORACLE_BINARY`
and `HB_ORACLE_ARCHIVE`, compares the same selected behavior on both servers,
and removes its synthetic instance directories. Its report binds binary and
source identities and labels a dirty worktree rather than inventing a clean
receipt. It grants neither independent acceptance nor complete compatibility.

The fixed live acceptance suite also exposes the bounded wrapping lifecycle
through the `wrapping` module (`wrapping.create`, `wrapping.unwrap`, and
`wrapping.replay_denied`). These cases exercise synthetic opaque delivery only;
they do not qualify HA response loss, all wrapping constraints, or complete
OpenBao compatibility.

Remaining work includes response wrapping and wrapping constraints, automatic
expiry qualification, production capacity, full errors/parameter permutations,
client compatibility, migration/retention and destructive HA acceptance. The
60-surface denominator is unchanged.
