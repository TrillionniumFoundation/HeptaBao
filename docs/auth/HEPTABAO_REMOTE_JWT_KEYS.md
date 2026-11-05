# Remote JWKS and OIDC Discovery-backed JWT authentication

Status: source implementation and selected real HTTPS behavior tests. This is
**JWT login with remote keys**, not browser OIDC authorization-code login, complete
OpenBao auth-method compatibility or independent qualification.

## Runtime boundary and sources

`auth_remote.rs` prepares owned configuration/login effects, resolves remote keys
outside the Service writer, and validates observations against current state.
`outbound_auth_https.rs` supplies scoped API-owned or legacy enrolled verified TLS.
`federated_auth.rs` and `federated_native_jwt.rs` validate signed JWTs; existing identity bindings, token
persistence and live ACL remain authoritative. `auth.rs` owns configuration and
identity state. Schema 4 introduced source-selection and algorithm constraints;
schema 19 adds native reusable assertions and role time-claim leeways. Schema 28
adds API-owned HTTPS trust without silently migrating older transport authority.

Exactly one source is accepted: existing static keys/inline JWKS,
`jwt_validation_pubkeys`, `jwks_url`, or `oidc_discovery_url`. Mixed sources fail
without committing a changed config.
`bound_issuer` configures issuer matching; `jwt_supported_algs` bounds the selected
algorithms to RS256, ES256 and EdDSA. RSA keys require 2048–4096-bit moduli and
exponent 65537. Private key parameters, symmetric keys, duplicate key IDs,
unsupported algorithms, malformed curves and unknown JOSE headers are rejected.

## Local PEM public-key configuration

`jwt_validation_pubkeys` accepts a string array or comma-separated string of
SPKI `PUBLIC KEY` envelopes. It stores public keys and derived verification
bytes in the existing encrypted Auth transaction. RSA uses RS256 with a
2048–4096-bit modulus and exponent 65537; EC uses ES256/P-256; Ed25519 uses
EdDSA. At most 64 keys are accepted, with at most 16 KiB per envelope and 1 MiB
total input. Unsupported curves, private keys, PKCS1 `RSA PUBLIC KEY`
envelopes, certificates, malformed keys and multiple envelopes in one element
are rejected before the configuration is replaced. Provider parser errors do
not echo input or private-key bytes. Surrounding whitespace is trimmed before
public readback; array normalization still needs its separate pinned API
comparison and is not claimed as exact wire parity.

Only this explicit PEM source tries its bounded set of keys of the JWT header's
algorithm. Configured PEM keys do not have a JWS `kid`, so missing or unknown
`kid` can authenticate after the existing signature and claim checks succeed.
Static-key and inline/remote JWKS sources retain exact `kid` selection. The
algorithm allowlist remains authoritative: a disjoint but valid allowlist can
be configured, then denies login. No remote address, absent key source or
failed signature falls back to another source. The role can supply its audience
when configuration has no audience extension; issuer, namespace, time claims,
selected string user claim and the registered subject remain independently
checked. Optional issuer and assertions without `sub` remain outside this
increment.

The optional persisted PEM source requires conditional schema 69. Old absent
fields preserve their encoded shape and schemas 65–68. State admission
revalidates the public PEM/key-byte binding, trust-policy bounds and containing
namespace. All namespaces participate in writer selection. Schema 69 stays
sticky after replacing or removing the source, and active/retired publication
and local/HA snapshot restore cannot lower that floor. Renewal continues to use
the current role, mount and Identity gates locally. A captured remote result
cannot complete after its configuration is replaced by PEM, even for the same
public key. These source tests do not qualify a new immutable runtime or prove
an actual schema-68 binary's refusal; those remain separate finite live lanes.

The public [JWT API](https://openbao.org/docs/api/auth/jwt/) documents the PEM
source. The pinned 2.7.0, official-only 33-observation preparation also exercised
RSA/P-256/Ed25519 login, missing and unknown `kid`, failed configuration retaining
the previous keys, source conflicts, and a disjoint algorithm allowlist.
PKCS1 configuration returned 400; its following successful login used the prior
valid configuration. These observations are distinct from candidate tests and
do not establish complete JWT/OIDC compatibility.

## Administrator-configured HTTPS and legacy enrollment

Fresh remote configuration uses the standard active CA field: `jwks_ca_pem` for
`jwks_url`, or `oidc_discovery_ca_pem` for discovery. A nonempty PEM bundle replaces
system roots; empty, null or omitted CA uses system roots. Configuration requires
update and sudo on its auth path before any remote work. CA readback is public;
client credentials remain redacted. No startup `outbound_endpoints` entry or
restart is required to configure this new transport.

HTTPS URLs accept DNS names, IPv4 and bracketed IPv6, with port 443 by default.
The bounded resolver uses four fixed workers, a queue of 16 and at most 16
addresses per resolution. Each connection fixes its resolved address list; code
exchange is never retried after sending its POST. TLS verifies both the chain
and server name. Explicit malformed or untrusted roots never fall back to system
roots or a process endpoint. There is no insecure-TLS option, environment proxy,
userinfo, fragment or redirect following. CA input is limited to 64 KiB. Strict
PEM tail validation is narrower than OpenBao 2.6.2, which accepts a valid bundle
followed by otherwise ignored text.

Old stored configuration with no internal transport field keeps its original
process-enrolled address, server name, CA and path prefix. Such origins still
require an explicit port and cannot invoke DNS or system-root fallback. Rewriting
a full old configuration without its active CA preserves that mode. An explicit
active CA field, including empty or null, promotes it to API transport; supplying
only the inactive CA field does not. Reads and logins never promote authority.
After promotion, later full writes with omitted CA select system roots. This
migration rule is distinct from ordinary full configuration replacement; it does
not reissue or change existing service tokens.

Discovery appends `/.well-known/openid-configuration` to the issuer. The returned
issuer must match exactly; `jwks_uri` must use HTTPS on the same normalized origin.
Old enrolled configurations also enforce their registered path prefix. Separate
issuer/JWKS origins remain outside this profile. API URLs permit bounded query
and percent-encoded request targets without decoding them into HTTP headers.
HTTP input remains limited to 16 KiB headers and 128 KiB body, with strict JSON
and framing; bounded chunked bodies are supported, arbitrary streaming is not.

API transport has one 30-second effect budget covering DNS, TLS, discovery, keys
and response processing, with a 10-second connection sub-budget. Both are capped
by the caller's HTTP deadline, normally 15 seconds: this is not a promise of a
30-second HTTP request. Legacy enrollment retains its existing three-second
per-connection cap, additionally bounded by the whole effect/request deadline.
A late result cannot enter finalization after that deadline. A durable commit
already begun before expiry can still complete later; no mid-commit cancellation
or certain outcome after a client timeout is claimed.

## Refresh and authorization semantics

Direct JWKS config preflight fetches and validates keys. Discovery-backed config
preflight fetches verified metadata and checks its issuer and same-origin key URL,
without fetching keys; it preserves an unchanged binding's existing key cache.
Successful preflight publishes only after live authority is rechecked. Failed
native API preflight returns 400 and leaves the previous configuration active;
legacy enrolled transport retains its existing failure status.
Every login fetches the current key set anew; saved resolved keys cannot serve as
an offline or stale-key fallback, including after restart. Issuer unavailability,
TLS failure, duplicate JSON, redirect, oversized document or absent algorithm-
approved key fails closed. Removing a key affects subsequent logins; this does
not revoke existing HeptaBao tokens independently of their normal authority rules.

JWT verifies issuer, role audience, subject, signature and time claims. Ordinary
JWT assertions are reusable: each successful login issues a new service token.
`jti` is optional metadata. At least one nonzero `iat`, `nbf` or `exp` is required;
missing dates are derived with the role's leeway settings. Role type is `jwt`.
Creating a role requires explicit `user_claim`, which selects a literal top-level
string claim. Existing role writes with `role_type=jwt` preserve an omitted
selector; old stored roles retain `sub`. Identity alias/entity binding and live
entity/group policy checks still apply. New keys with the same selected alias
reuse the existing binding within that auth mount and namespace.

Static and remote JWT roles accept `bound_claims` and `bound_claims_type`.
Every configured claim must match; scalar/list alternatives match if any pair
agrees. Missing claims, scalar null and empty alternatives deny login. String
mode preserves boolean/string distinctions. Selectors beginning with `/` use
the pinned JSON-pointer behavior, including escaped keys and Go base-zero array
indexes. Other selectors are literal top-level claim names. Glob mode treats
only `*` as a wildcard, including across `/`; `?`, brackets and backslashes are
literal characters. Glob configuration requires string values or string lists.

Matching uses the same original signature-verified payload as issuer/time
validation. It does not decode another unverified copy or retain arbitrary
claims in token metadata. The pinned upstream verifier converts numeric scalar
claims through f64 and truncates to signed integers, but does not convert numeric
array elements; the matcher preserves this observed distinction. Expected
integer and floating-point JSON categories remain distinct. Out-of-range
float-to-integer conversion and nested object/array equality reject rather than
emulate implementation-dependent behavior.

Role updates preserve an omitted bound map; null or `{}` clears it. An omitted
`bound_claims_type` resets the mode to `string`, including on partial writes;
null or an unknown mode returns 400 without mutation. Readback includes
`role_type:"jwt"`. The selected `user_claim` remains independent of registered `sub` used by `bound_subject`. The new optional role state requires
schema 30; old absent state keeps its serialized shape. Concurrent role changes
invalidate remote login results, and failed matches publish no token or wrapper.
Bound predicates remain separate from the selected user alias. Arbitrary claim
mapping, selectable group claims and OIDC UserInfo merging remain separate work.

The [schema-30 bound-claims comparison](../../qa/openbao-acceptance/evidence/jwt-bound-claims-6de8ab2.json)
records 362 matching observations per side against OpenBao 2.6.2, using static
and remote keys. Separate candidate checks reject a gated late JWKS result after
role changes without publishing keys, tokens or wrappers. The [actual schema-29
upgrade](../../qa/openbao-acceptance/evidence/jwt-bound-upgrade-6de8ab2.json)
passes 110 checks, including unchanged legacy reads, old-token renewal, new
predicates after restart, downgrade refusal and recovery. These scoped results
do not cover arbitrary claim mapping or OIDC UserInfo.

After a fetch, real-clock login samples the host wall clock once after writer/HA
re-admission and verifies time claims with the configured grace window. The same
sample drives token/Identity publication and wrapping; it is never rounded up or
clamped to the batch watermark. Explicit-clock embedders keep their supplied
clock domain plus elapsed time. A client, provider or HA request cannot choose
that internal clock mode. The [single-run concurrency receipt](../../qa/openbao-acceptance/evidence/jwt-completion-clock-live-b56954e.json) reproduces the old false-rollback rejection and verifies corrected wrapper/batch creation and use; [44 remote JWKS regression checks](../../qa/openbao-acceptance/evidence/jwt-remote-batch-live-b56954e.json) also pass. These fixtures do not establish cross-host clock authority. The auth mount incarnation and trust configuration must
still match; a same-path disable/recreate cannot reuse an earlier observation.

Remote configuration preflight and both ordinary and wrapped login I/O execute
outside the Service writer. Completion rechecks active seal generation, namespace,
HA leadership and current mount/configuration. Login also requires the complete
selected role to remain unchanged, then resolves Identity against current state.
Configuration rechecks its original caller's live identity, expiry and update/sudo
authority and merges only the proposed configuration into current state, preserving
unrelated concurrent writes. Identical configuration and keys do not append a
durable transaction. Wrapped login publishes the token, identity, key cache and
single-use wrapper together; wrapping or persistence failure installs none of that
candidate state. An external result arriving after the HTTP finalization deadline
cannot reacquire publication authority merely because the writer is idle. A slow
or unavailable IdP may still deny or delay requests; no production throughput or
offline-availability claim follows.

Native JWT service-token renewal uses the stored role name and current role/mount
TTL limits locally. It neither fetches keys nor revalidates the original JWT's
expiry/signature/claims. Removing a role blocks its direct tokens' renewal; changing
its policies leaves their issued token policies intact. Service-token expiry is
independent of the assertion's expiry. Schema 18 protects this provenance and the
distinct periodic/explicit maximum semantics; see the
[JWT role and renewal contract](HEPTABAO_SINGLE_NODE_AUTH.md#bounded-jwt-authentication).

New JWT roles store zero `token_ttl` and `token_max_ttl` by default, independently
selecting the current mount's default and maximum. Explicit zero restores that
inheritance. Null or omitted TTL, maximum, period and explicit-maximum fields
preserve existing role values; a nonzero maximum must not be smaller than a
nonzero TTL. Older stored positive values keep their exact meaning until an
administrator changes them. Schema 32 fences zero role limits. Renewal keeps
issued policies, period lookup snapshots and absolute explicit caps, while
ordinary limits use current role/mount values. Fresh installations inherit a
32-day system default and maximum; historical stores preserve their one-hour
inherited default. Explicit mount settings override the corresponding value.

New configurations use native role time defaults, with no implicit one-hour JWT
lifetime limit. Explicit legacy `clock_skew_seconds` and
`maximum_token_lifetime_seconds` remain compatibility extensions; the latter
requires real signed `iat` and `exp`. Existing stored constraints remain active
until configuration is replaced. A supplied role `clock_skew_leeway` overrides
the config clock alias; without that override the legacy alias permits future
`iat`/`nbf` grace but retains strict rejection at `exp`. OIDC consumed-session/nonce checks and the public strict
proof verifier retain their separate one-use contracts.

## Explicit non-goals and compatibility limits

`role_type=oidc` is rejected on this JWT mount. Browser authorization-code flows
use the separate OIDC mount profile; remote JWT discovery does not activate them.
JSON-pointer user selection, arbitrary claim mapping, external-group sync and
complete JWT/OIDC API parity remain open. Custom-claim JWTs currently still
require a registered `sub`; this increment does not claim the no-`sub` profile.
A valid authorized absent Identity alias lookup returns an empty 204, following
the separately observed OpenBao 2.7.0 representation. Invalid selectors and
caller authorization remain errors; existing namespace routing is unchanged.
Omitted `role_type` follows the native JWT profile;
the public OpenBao API documents an OIDC default. These independent wire/API
differences remain outside this selector implementation. OpenBao's remote
key cache may retain an old key until refresh; this candidate's per-login fresh
fetch is intentionally stricter and cannot establish full cache-semantics parity.

## Tests and operations

```sh
cargo test --locked -p heptabao-server outbound
python qa/openbao-acceptance/remote_jwks_live.py --binary <server> --output <new-json>
python qa/openbao-acceptance/remote_jwks_compare.py --binary <server> --output <new-json>
```

The first Python runner uses real HTTPS and real RSA/P-256/Ed25519 signatures to
exercise rotation, restart, live identity invalidation and hostile/failing key
sources. The comparison runner separately starts the checksum-pinned official
OpenBao 2.6.2 binary and performs the same selected JWT-key scenarios against both
servers. Historical receipts retain their enrollment-profile adaptation; new
API-CA fixtures identify their own transport explicitly. Neither claims
browser OIDC or immediate key-cache invalidation equivalence. Empty
results, duplicate case identities and two failing sides cannot pass admission.
`jwt_login_claims_live.py` independently compares ordinary assertion reuse and
native time-claim semantics with the pinned official binary; it does not exercise
OIDC authorization codes or the strict proof API.

The schema-28 API-CA implementation passed local Rust tests and strict Clippy.
[The API TLS comparison](../../qa/openbao-acceptance/evidence/jwt-api-tls-856ef3d.json)
passed 141 observations on each binary, including CA replacement, wrong SAN,
no startup endpoint enrollment, real login and restart. The OIDC comparison
explicitly retains the candidate's S256 enrollment and POST callback adaptation.
[The actual 27-to-28 upgrade](../../qa/openbao-acceptance/evidence/jwt-api-upgrade-6b4fed2-to-649c125.json)
passed 121 observations: unchanged legacy reads and pending code, retained old
enrollment until explicit API CA opt-in, no-enrollment operation after promotion,
and refusal by the actual old binary after mutation.
[The seven-phase TLS concurrency run](../../qa/openbao-acceptance/evidence/jwt-split-phase-649c125.json)
passed 36 checks, including OIDC config preflight, independent writes and late
authority changes. These receipts bind production source `649c125` and the
observed binary; they are selected local acceptance, not full compatibility or
independent production qualification.

### Custom JWT identity claim reader fence

Successful static or remote JWT login binds the selected verified string claim
to the Identity alias and display name. Missing, nonstring, empty, control-bearing
or oversized values reject before token publication; `bound_subject` still checks
the signed registered `sub`. A key is a literal top-level JSON member, including
names containing `/`; this increment does not enable JSON Pointer selection,
claim mappings, external group aliases or CEL. Existing group predicates and
bound-claim matching keep their independent contracts.

The role stores only an optional custom selector. Default `sub` retains the old
serialized shape and schema 65. Custom state raises the writer requirement to
schema 68, scans every namespace, and keeps that floor after role retirement.
Old labels, malformed selectors, future schemas, publication downgrade and both
snapshot restore paths reject. AAD-bound schema 66 and typed-PKI schema 67 remain
independent floors. Remote completion compares the captured complete role before
publishing; Identity disable, mount, namespace, activation and Service commit
gates still precede token release. Renewal retains the original issued entity and
policies and reads current role TTL limits without remapping the identity claim.

The implementation uses the existing maintained signature verifier once; it does
not parse an unverified payload to select identity. The source tests include real
RS256 signatures, invalid values/signatures, scoped aliases, disabled entities,
encrypted restart, renewal and active/retired schema boundaries. A separate
fresh pinned OpenBao 2.7.0 observation confirms selected alias binding, wrong
type/signature rejection, new-role selector requirements and existing-role
merge semantics. Its original failed assumptions remain recorded; it is not
native runtime qualification. Actual prior-reader and integrated native
qualification remain pending, with no production or full replacement authority.
