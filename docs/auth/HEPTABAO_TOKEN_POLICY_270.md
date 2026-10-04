# Token API policy resolution against OpenBao 2.7.0

This finite change applies to `auth/token/create` and `create-orphan`. It does
not change policy handling for login methods, user/group mappings, or identity
entities. It adds no persisted fields or schema floor and does not rewrite
previously issued token policies.

The reference is OpenBao tag commit
`ca305a02daa68b203325daa1b25c18d7a252d4b3`, particularly
[`internal/vault/token_store.go`](https://github.com/openbao/openbao/blob/ca305a02daa68b203325daa1b25c18d7a252d4b3/internal/vault/token_store.go)
(`resolveTokenPolicies`, lines 4232–4358 and parent-root checks at 3042) and
[`sdk/helper/policyutil/policyutil.go`](https://github.com/openbao/openbao/blob/ca305a02daa68b203325daa1b25c18d7a252d4b3/sdk/helper/policyutil/policyutil.go).
Fresh verified HTTPS oracle R03 observed 54 requests with the actual official
2.7.0 binary and authenticated parent/child lookup and KV permission probes.
Oracle original SHA256:
`a22423b7a5f2f493afaa2c865bd14ea301645296a97abc898272a9fb83657ee9`.
R01 completion False from wrapper-in-own-session accounting is retained;
R02 and R03 have natural exit 0 and two post-exit empty-session observations.

Fresh oracle R04 added 27 actual coercion and internal-policy cases, natural
exit 0 with post-exit kernel-empty audits. Original SHA256:
`4f62f2b683186bce074c01b4d9c445a213ee0dc7376cb0447ade7be1e44b6680`.
The creation field at token_store.go lines 203–205 is `TypeStringSlice`:
strings containing commas remain one literal policy name. Null inherits parent
policies, while whitespace and nonempty arrays of empty strings represent
explicit sanitized empty policies. Unicode simple lowercase maps Σ to σ,
İ to a single i, and КЛЮЧ to ключ. Unknown resulting names receive no ACL grant.
The pinned `policy_store.go` NonAssignablePolicies table contains only
`response-wrapping`; assignment rejects with the actual 400 error. Root-containing
sets normalize to root before that check, and still require the actual root
parent. `control-group` is assignable in this reference and has no grant merely
because its name is present. Shared ASCII policy-definition name validation is
not imposed on token API strings; outer request and durable-state bounds apply.

| Request / authority | Resulting policy behavior |
|---|---|
| Same namespace; omitted, empty array, empty string | Inherit parent policies |
| `no_default_policy: true` | Remove `default` after policy subset validation |
| Named policies; ordinary parent | Must be a subset; add default only if parent has it |
| Named policies; actual route sudo | May be disjoint; default added unless disabled |
| Any root-containing normalized set | Normalize to root only; actual parent must be root |
| Parent namespace issuing into child namespace | Do not inherit parent policies; root prohibited |
| No route create/update authority | Existing ACL denial remains in force |

Empty policies on a root parent issue a root child. A policy-free token can
instead explicitly request `default` and set `no_default_policy: true`; the
existing cubbyhole denial fixture now uses that actual reference construction
without changing its denial assertion.

This source was frozen before any new Cargo invocation. Candidate qualification,
fresh candidate/reference HTTPS comparison, and whole-workspace checks are still
required. Official token roles select role-allowed policies on empty input and
can allow disjoint parent policies; HeptaBao token-role management and
`auth/token/create/<role>` remain a separate unresolved blocker. This document
does not establish full replacement of OpenBao 2.7.0 or parity for unmeasured
coercions, arbitrary policy names, policy existence warnings, or every token API
response field.
