# Remote JWKS and OIDC Discovery-backed JWT authentication

Status: source implementation and selected real HTTPS behavior tests. This is
**JWT login with remote keys**, not browser OIDC authorization-code login, complete
OpenBao auth-method compatibility or independent qualification.

## Runtime boundary and sources

`auth_remote.rs` runs remote key resolution in the existing authenticated config
transaction and login path. `outbound.rs` supplies deployment-owned verified TLS.
`federated_auth.rs` and `federated_native_jwt.rs` validate signed JWTs; existing identity bindings, token
persistence and live ACL remain authoritative. `auth.rs` owns configuration and
identity state. Schema 4 introduced source-selection and algorithm constraints;
schema 19 adds native reusable assertions and role time-claim leeways.

Exactly one source is accepted: existing static keys/inline JWKS, `jwks_url`, or
`oidc_discovery_url`. Mixed sources fail without committing a changed config.
`bound_issuer` configures issuer matching; `jwt_supported_algs` bounds the selected
algorithms to RS256, ES256 and EdDSA. RSA keys require 2048–4096-bit moduli and
exponent 65537. Private key parameters, symmetric keys, duplicate key IDs,
unsupported algorithms, malformed curves and unknown JOSE headers are rejected.

## Deployment-owned TLS enrollment

All remote origins must appear in process `outbound_endpoints`, for example:

```json
{
  "origin":"https://issuer.example:443",
  "address":"192.0.2.10:443",
  "server_name":"issuer.example",
  "ca_pem":"<explicit trusted PEM CA>",
  "path_prefix":"/realm"
}
```

The example uses documentation-only addresses. Origins require an explicit port.
No endpoint is enrolled by default. IP, hostname and CA are operator-controlled
startup input, not supplied by discovery or login. Paths must stay inside the
registered prefix. There is no DNS, redirect, proxy, system trust fallback,
userinfo, query, fragment or encoded-path interpretation. Restart with a revised
host profile is required to change destination or CA. This differs from OpenBao's
per-auth-mount CA configuration and is not normalized into configuration parity.

Discovery requests append `/.well-known/openid-configuration` to the selected
issuer. The returned issuer must match exactly; `jwks_uri` must be HTTPS on the
same origin and remain within host enrollment. An IdP that separates issuer and
JWKS origins is outside this bounded profile. A page cannot widen network scope.
HTTP input is limited to 16 KiB headers and 128 KiB body with strict JSON and
framing; bounded chunked bodies are supported, arbitrary streaming is not.

## Refresh and authorization semantics

Config write validates a fetched document before publishing the transaction.
Every login fetches the current key set anew; saved resolved keys cannot serve as
an offline or stale-key fallback, including after restart. Issuer unavailability,
TLS failure, duplicate JSON, redirect, oversized document or absent algorithm-
approved key fails closed. Removing a key affects subsequent logins; this does
not revoke existing HeptaBao tokens independently of their normal authority rules.

JWT verifies issuer, role audience, subject, signature and time claims. Ordinary
JWT assertions are reusable: each successful login issues a new service token.
`jti` is optional metadata. At least one nonzero `iat`, `nbf` or `exp` is required;
missing dates are derived with the role's leeway settings. Role type is `jwt`, user_claim is `sub` in this profile;
Identity alias/entity binding and live entity/group policy checks still apply.
New keys with the same subject reuse the correct existing identity binding.
After a fetch, login verifies time claims using elapsed request time and the
configured grace window. The auth mount incarnation and trust configuration must
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
Arbitrary JSON-pointer claim mapping, external-group sync and complete JWT/OIDC
API parity remain open. OpenBao's remote
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
servers. It discloses the deployment-configuration difference and does not claim
browser OIDC or immediate key-cache invalidation equivalence. Empty
results, duplicate case identities and two failing sides cannot pass admission.
`jwt_login_claims_live.py` independently compares ordinary assertion reuse and
native time-claim semantics with the pinned official binary; it does not exercise
OIDC authorization codes or the strict proof API.
