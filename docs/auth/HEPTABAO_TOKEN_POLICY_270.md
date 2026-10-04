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

Service and stateless batch tokens issued through a role retain immutable role
name and issuance path provenance. Batch provenance is authenticated inside the
sealed claims, validated against the exact path, and read from that marker; the
path alone does not manufacture a role. Role deletion and encrypted reopen
preserve this information. Lookup preserves the creation request's period and explicit
maximum while initial TTL uses effective role limits. Renewal reads the current
role; removing the role keeps an otherwise live token usable, but renewal
returns the reference role-missing error. Namespace role maps and issued-role
provenance require durable schema 80. The writer floor remains 80 after role
and token retirement, including stateless batch retirement, and snapshot
publication refuses a lower protected floor. Service preflight raises this floor
before preparing typed records.
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
These historical custody gaps remain recorded.

Fresh independent official runs now have complete local raw custody: R10
weak inputs 33, R11 roles and authenticated batch provenance 94, R12 warning and
lexical inputs 30, R13 identity/expiry 31, and R14 weak roles/batch 142. Their
original SHA256 values are respectively
`a291f3af07b42e8a818d8cef0b4e99589a0bb8cfd8b5a4449bd0658412b21200`,
`99d8683ddf02db475d5780a427fafc51559c00d300cf67dacd059fa8e06322b7`,
`d4e3292f222527af2923998efba95194121bd9adbc4f493e859beaeed956f597`,
`fe65072f24023686da46bf0a69b3800fee2c734b52accac46bb6f7a795d75616`, and
`842fd7717e2ecde1d5b4defff2f32c174be0fdfca7a332a6aa5627d3959000d1`.
All had natural runner exit 0, post-exit kernel audits, and immediate by-value
copies with every file length and SHA verified. They are reference observations,
not candidate qualification.

R14 confirms that explicit ordinary `no_parent` without actual sudo returns
400 and the precise privilege error. Role batch use limits are applied after
validating request fields: role uses 2 returns issuance `auth.num_uses: 2`, while
stateless lookup reports 0 and four successive authorized reads succeed. An
explicit batch request `num_uses: 1` is rejected with the reference 400 error.
This finite source follows those outcomes without adding per-batch records.

The f2a ordinary candidate's fresh HTTPS control issued an ordinary token with
200, but both role writes returned actual 503 with `Token API role ownership
requires schema 80`. Those failures remain recorded; the preflight fix is not
qualified by the previous build. This isolated role/batch successor has run no
Cargo checks or candidate role HTTPS qualification. Source tests cover namespace ownership, partial-update rollback,
policy delegation, route ACL, root guards, trusted peer CIDRs, use limits,
current-role renewal, expiry, persisted provenance validation, disabled identity
publication, encrypted reopen and active/retired schema floors. They remain
unexecuted here. Fresh ordinary builds, strict whole-workspace checks, complete
candidate/reference responses, schema-79 reader refusal and snapshot/migration
checks are required on the final combined source.

The final supported-format enumeration now admits exactly schema 80; unknown
and lower protected schemas remain refused. R14's Unicode/comma batch names
have an isolated source implementation: role batches use their authenticated
issued-role marker, while ordinary batches with the extended grammar add an
issuer-owned authenticated claim flag. Other login claims retain their existing
ASCII policy grammar. Historical false flags are omitted from the serialized
claim and Auth owner. A sticky Auth flag raises ordinary extended-name batches
to schema 80 before publication, and prevents older snapshot/reader restoration
from discarding that provenance after retirement. Clients cannot request the
marker; path text alone does not confer issuer provenance or role authority.
New cryptographic, Auth and encrypted Service tests remain unexecuted here.

Fresh official R15 retains all 224 role-field observations, raw numeric
lexemes and complete local custody (original SHA256
`46d342d7c65cc732c97e665f4b36b02c7ed90e98eaec899bdb9ce64f3ac2dec0`).
It covers the three role Boolean fields, signed/base-zero weak integers, null
and empty inputs, four native/deprecated duration fields, fractional compound
and subsecond units, day suffixes, signed truncation and overflow diagnostics.
The isolated role converter now follows these reference contracts, including
role-only conversion error prefixes and partial-update rollback. Ordinary
Token API creation retains its own framework error prefix. The role period
getter is explicitly named `effective_period` in issuance and renewal, keeping
the effective native value separate from the persisted deprecated field.

The parser sources are pinned to the reference's
[parseutil v0.2.0](https://github.com/hashicorp/go-secure-stdlib/blob/parseutil/v0.2.0/parseutil/parseutil.go),
[mapstructure v2.5.0](https://github.com/go-viper/mapstructure/blob/v2.5.0/mapstructure.go),
and [Go 1.27.1 duration parser](https://github.com/golang/go/blob/go1.27.1/src/time/format.go).
The role's numeric raw carrier has not yet been composed with this source;
ordinary TTL/period/max conversions, unmeasured role fields and the measured
HTTP envelope/empty identity/permission error differences still require source
and fresh candidate evidence. New source tests have not run here. This source
does not establish full replacement of OpenBao 2.7.0.
