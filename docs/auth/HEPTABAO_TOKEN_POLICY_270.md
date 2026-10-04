# Token API policies and roles against OpenBao 2.7.0

The finite source adds namespace-owned `auth/token/roles/<name>` management and
`auth/token/create/<role>` alongside policy resolution for ordinary token
creation. Roles support partial updates, allowed/disallowed policy lists and
`*` globs, fixed or default token type, orphan creation, role-owned CIDRs and use
limits, and allowed identity aliases. The existing atomic Auth+Engine owner
publishes identity aliases and refuses disabled entities before publication.

The reference is OpenBao tag commit
`ca305a02daa68b203325daa1b25c18d7a252d4b3`, especially
[`internal/vault/token_store.go`](https://github.com/openbao/openbao/blob/ca305a02daa68b203325daa1b25c18d7a252d4b3/internal/vault/token_store.go),
[`sdk/helper/policyutil/policyutil.go`](https://github.com/openbao/openbao/blob/ca305a02daa68b203325daa1b25c18d7a252d4b3/sdk/helper/policyutil/policyutil.go), and
[`sdk/framework/field_data.go`](https://github.com/openbao/openbao/blob/ca305a02daa68b203325daa1b25c18d7a252d4b3/sdk/framework/field_data.go).

| Request / authority | Policy and creation behavior |
|---|---|
| Same namespace; omitted, empty array or empty string policies | Inherit parent token policies |
| Ordinary named policies without route sudo | Require parent-policy subset |
| Actual route sudo | Permit disjoint policies; add default unless disabled |
| Root-containing set | Normalize to root only and require actual root parent |
| Parent namespace issuing into a child namespace | Preserve route sudo requirement; prohibit root policies |
| Role with policy restrictions | Resolve delegated policies and reject disallowed exact/glob matches |
| Role without policy restrictions | Preserve ordinary policy inheritance and subset rules |
| Ordinary `create-orphan` | Require actual create/update route ACL |
| Explicit ordinary `no_parent` or requested positive period | Preserve sudo requirement |

The Token API `policies` field is `TypeStringSlice`; comma-containing strings
remain one literal name. Null inherits policies. Explicit whitespace and
nonempty arrays of empty strings sanitize to an explicit empty set. Unicode
simple lowercase applies before comparison. Shared ASCII policy-definition
name validation is not applied to these token strings. Policy-free creation
can explicitly request `default` with `no_default_policy: true`. The pinned
nonassignable table contains `response-wrapping`; `control-group` is assignable
and acquires no ACL grant merely from its name.

Token-local weak field converters handle scalar number/boolean policy input,
null array elements, empty maps and weak Boolean fields. Compound conversion
failures prevent publication. Unknown-policy warnings derive from the final
normalized set and the authoritative namespace policy map; root collapse,
removed default and rejected subsets do not produce those warnings. Warning
quoting uses the exact Go 1.27.1 Unicode 17 printability table, with the BSD
license retained in `docs/licenses/GO_UNICODE_LICENSE`. Raw numeric lexical
preservation is a separate HTTP/Service transport integration and is not
qualified by this isolated Auth source.

Service tokens issued through a role retain immutable role name and issuance
path provenance. Lookup preserves the creation request's period and explicit
maximum while initial TTL uses effective role limits. Renewal reads the current
role; removing the role keeps an otherwise live token usable, but renewal
returns the reference role-missing error. Namespace role maps and issued-role
provenance require durable schema 80. The writer floor remains 80 after role
and token retirement, and snapshot publication refuses a lower protected floor.
Legacy records without role material retain their previous fields and floors.

Evidence with complete local raw custody includes official HTTPS R03's 54
requests (original SHA256
`a22423b7a5f2f493afaa2c865bd14ea301645296a97abc898272a9fb83657ee9`)
and R04's 27 coercion/internal-policy requests (original SHA256
`4f62f2b683186bce074c01b4d9c445a213ee0dc7376cb0447ade7be1e44b6680`).
Their complete response, permission probes and natural-exit audits are retained;
R01's wrapper-accounting False is retained as well.

R05's 33 weak-input, R07's 88 role and R08's 30 warning/lexical observations
were read before an external X230 custody loss. Their last-observed hashes and
summaries are unqualified: the missing raw artifacts are not reconstructed.
R09's identity/expiry oracle had only a launch PID observed and has unknown
outcome. The c989 candidate comparison also lost raw custody and remains False.
Fresh independent oracle runs and immediate complete copies are required.

This isolated role source has run no Cargo checks or candidate role HTTPS
qualification. Source tests cover namespace ownership, partial-update rollback,
policy delegation, route ACL, root guards, trusted peer CIDRs, use limits,
current-role renewal, expiry, persisted provenance validation, disabled identity
publication, encrypted reopen and active/retired schema floors. They remain
unexecuted here. Fresh ordinary builds, strict whole-workspace checks, complete
candidate/reference responses, schema-79 reader refusal and snapshot/migration
checks are required on the final combined source. Unmeasured weak role-field and
TTL cases and transport fields remain open. This source does not establish full
replacement of OpenBao 2.7.0.
