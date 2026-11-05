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

## Request parameter constraints

Schema 58 persists bounded `allowed_parameters`, `denied_parameters` and
`required_parameters` on ordinary ACL path rules. Parameter names are ASCII,
bounded and canonical lowercase in state. Each constraint map is limited to 128 keys, each value list to 128 entries, each encoded value to 16 KiB, and HCL value nesting to 32 levels before constructing nested children. The highest-priority matching path is
selected first; only identical winning patterns merge their maps and required
sets. An empty value list matches every value. A denied `*` rejects any nonempty
request, while an allowed `*` admits otherwise-unlisted fields; a specific field
beside allowed `*` still enforces its value list. Top-level strings support only
the upstream leading/trailing `*` behavior. Bool, null, arrays and maps compare
exactly. Public HTTP numeric values intentionally retain OpenBao 2.6.2's observed
dynamic-type mismatch and do not match numeric HCL/JSON policy literals.

The Service checks the actual request body for logical read, create, update and
patch operations at authenticated top-level routes and workflow subrequests. The
same rule applies to `HEAD` as a read. Matching OpenBao 2.6.2, generic request-body
constraints do not run for delete, list, scan, renew, revoke or rollback; those
operations retain their independent capability, selector and endpoint checks.
GET selectors are normalized to LIST or SCAN before policy admission, so query or
JSON selector framing cannot accidentally turn enumeration into a constrained
read. LIST requires `list`; recursive SCAN requires the independent `scan`
capability, matching OpenBao rather than treating scan as a stronger list. External database, Kubernetes, OpenLDAP, secret and KMS completions retain
the original bounded body and effective operation and recheck current parameter
rules after HA synchronization, policy/identity refresh and activation fencing.
A denied request does not enter backend mutation. Constraints survive encrypted
restart; schema 57 admits policies without constraints but rejects a state that
contains them. `policy_parameters_live.py` compares these bounded HTTP semantics
with the checksum-pinned official OpenBao 2.6.2 binary and includes effect
readback for both denials and operation-specific exclusions.

## Live Identity path substitutions

Schema 60 adds bounded `{{ identity.entity.id }}`, entity name/metadata,
`identity.entity.aliases.<mount-accessor>` id/name/backend metadata/custom metadata,
and `identity.groups.ids.<id>` or `identity.groups.names.<name>` id/name/metadata
selectors to ordinary ACL path rules. This is scalar path substitution, not a
general expression or Go-template engine. The policy is parsed on ingress and
revalidated on reopen. Missing fields omit that rule rather than turning into a
wildcard or an empty grant. A **present but forbidden** substitution instead
fails the complete evaluation with 403, even in an otherwise nonmatching rule;
it must never silently delete a deny rule while retaining another broad grant.
This follows the OpenBao 2.7.0 fix for GHSA-hr5j-3j78-4vh2. Bound/path failures
are also fatal in this bounded implementation. Capabilities, parameter admission,
wrapping constraints and capability inspection propagate that same distinction.
Independent root repair remains possible. This is a runtime security minimum,
not a new wire field; mixed readers and old insecure binaries are not admitted. Substituted `*`, `+`, escaped/traversal paths and nested
templates never manufacture ACL authority. Literal policy wildcards keep the
existing deterministic specificity rules.

The normal Service and capability-inspection paths project only the selectors
needed by the subject's current effective policies, from the same namespace-owned
Identity records. Alias selection requires the live mount accessor and coherent
alias/canonical indexes. Group selection requires the subject's verified direct
or inherited membership; naming a nonmember group is not authorization. Backend
login metadata and administrator-owned custom alias metadata stay separate.
Renaming, metadata edits, membership removal, alias deletion, disabled entities
and restart affect existing service and batch tokens immediately on the next
current-state authorization. Expanded values are request-local and are cleared
when Identity is rebound; they are never durable token permissions.

Limits are 2,048 path bytes, 64 directives per rule, 512 bytes per selector and
4,096 distinct selectors across the effective policy set. Only requested values
are copied. `auth_acl_template.rs`, `identity_acl_templates.rs`,
`identity_acl_service_tests.rs` and `policy_templates_live.py` own implementation,
Service regressions and the separate checksum-pinned native comparison. Generic
parameter admission and capabilities use the same rendered winning path.

## ACL wrapping TTL constraints

Schema 61 adds integer/whole-second `min_wrapping_ttl` and `max_wrapping_ttl`
attributes. A rule with both nonzero bounds rejects a minimum above its maximum.
Zero means an unconstrained bound; absent/zero fields preserve legacy serialized
rules. Bounds select the same highest-priority path as capabilities and parameters.
For identical winning paths OpenBao 2.6.2 merges each bound by its shortest nonzero
value; this is not a maximum-of-minima intersection. A conflict formed by merging
separate policies denies requests that cannot satisfy both resulting bounds.
Broad wildcard rules do not override a more-specific default or explicit rule.

Absence and explicit zero are distinct native request facts:

| Rule | No wrapping header | Explicit `0` | Positive TTL |
|---|---|---|---|
| Minimum greater than zero | Denied | Denied | Must meet the minimum and any maximum. |
| Maximum only | Denied | Allowed without a wrapper. | Must not exceed the maximum. |
| Both zero/absent | Ordinary request | Ordinary request | Existing wrapping envelope applies. |

A maximum-only policy therefore does **not** require confidential wrapped delivery;
use a positive minimum when that is the intended policy. The native comparison
retains both cases instead of collapsing zero into absence. HTTP parsing, audit
fingerprints, request-local Principal metadata and authenticated HA forwarding
preserve the distinction. Only positive TTLs request actual response capture.
An old forwarding peer may refuse explicit-zero context but must never downgrade
it to a context-free request.

Bounds are checked before read/write/delete/list/scan dispatch and again when an
existing retained actor reauthorizes late work. Generic parameter constraints keep
their operation-specific scope and remain independently enforced. An admitted
transactional DELETE may return native 204 with no wrapper because there is no
payload; effect readback still proves deletion. Capability inspection reports
capability names, not satisfaction of wrapping or request-parameter conditions.
`auth_acl_wrapping.rs`, `service_acl_wrapping_tests.rs` and
`policy_wrapping_ttl_live.py` bind these limited semantics to real entry points.
GET body bytes are consumed and bounded but ignored as logical fields; positive
GET parameter tests use query fields, matching the pinned upstream HTTP adapter.

MFA, pagination/response-key attributes, unsupported template forms, complete
path/glob/list/scan combinations, arbitrary duration precision, positive HEAD
wrapping, external-effect wrapping envelopes and the full namespace administration
hierarchy remain separate work. These APIs do not issue reusable execution
capabilities. Independent security and full OpenBao compatibility remain open.

The [composed private three-host profile](../operations/HEPTABAO_MULTIHOST_ACL_QUALIFICATION.md)
adds original-token, explicit-zero, effect, snapshot, failover and revocation
checks to the existing HA lifecycle. It has a separate 118-check denominator and
does not grant full-surface or independent qualification.
