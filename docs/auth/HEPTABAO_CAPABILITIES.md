# Live capability introspection

Owner: `heptabao-server` auth policy evaluator and Service identity snapshot.
Source: `auth_capabilities.rs`, `service_capabilities.rs`, `auth_acl.rs`.
This runtime API reports current policy decisions; it does not issue execution
capabilities or make a later operation race-free.

## Requests and results

`POST sys/capabilities-self` inspects the authenticated caller.
`POST sys/capabilities` requires a body `token` selector; the accessor variant
`POST sys/capabilities-accessor` requires `accessor`. The querying principal
must separately have `update` on the inspection endpoint. The built-in default
policy grants the self endpoint only. The subject token never authorizes the
request merely by being named in the body.

Supply `paths` with 1–64 distinct canonical paths, or the legacy singular `path`,
not both. Paths are bounded by the current ACL parser. Empty lists, duplicates,
unknown fields, malformed selectors and unsupported methods fail explicitly.
Responses map each requested path to sorted capabilities; one-path responses also
carry the `capabilities` alias. Entries are available under `data` and the current
OpenBao-facing top-level projection. Root returns `["root"]`, an absent grant
returns `["deny"]`. The envelope's `data` key remains reserved; clients should
use the nested mapping for a requested path literally named `data`.

## Authorization and data ownership

The same `policy_allows` specificity evaluator drives introspection and actual
`authorize_request`. The greatest-priority matching pattern wins; only identical
winning patterns union and deny dominates. Inspection includes current entity and
nested internal-group policy projection after the Service HA ReadIndex boundary,
not a snapshot copied into the token at login. A disabled or deleted subject
identity has no usable grant. Namespace, expiry, parent liveness and accessor
checks are mandatory. Wrapping subjects do not acquire general capabilities.

`InspectionTarget` is private, read-only metadata. It is not serializable as a
Principal and cannot execute another request. Looking up a subject does not call
its authentication-consumption path, so another finite-use token keeps its use
count. The caller itself follows ordinary admission, including durable finite-use
consumption before later argument or ACL rejection.

## State, failure and operations

No new policy store or authoritative writer is created. A response describes one
current snapshot and carries no reservation, lease or authorization for future
execution. Policy edits, identity disablement, token expiry or revocation after
inspection may invalidate that result. Actual operations must still pass the
normal endpoint checks. Do not cache capability results as bearer authority or
assume a reported capability means a currently unimplemented engine is present.

Invalid requests produce safe errors; neither bearer selectors nor arbitrary
response data belong in diagnostics. The transport and Service's existing audit,
payload, concurrency, deadline and encrypted-state recovery limits apply. The API
is synchronous and bounded, and intentionally does not auto-create policies.

## Verification and open boundaries

`cargo test --locked -p heptabao-server capabilities_` covers live policy and
identity changes, default/explicit endpoint permission, other-token nonconsumption,
namespace isolation, root semantics and argument bounds. `capabilities_live.py`
executes selected matching requests against two real TLS services, with strict
nonempty/all-passed observation validation. Its cases are not a full policy corpus.

Template policies, every upstream HCL parameter constraint and the full namespace
administration hierarchy are separate missing work. This API does not implement
MFA, OIDC discovery, external identity synchronization, or an execution capability
issuer. Independent security and full OpenBao compatibility remain open.
