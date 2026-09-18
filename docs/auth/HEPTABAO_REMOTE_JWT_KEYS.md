# Remote JWKS and OIDC Discovery-backed JWT authentication

Status: source implementation and selected real HTTPS behavior tests. This is
**JWT login with remote keys**, not browser OIDC authorization-code login, complete
OpenBao auth-method compatibility or independent qualification.

## Runtime boundary and sources

`auth_remote.rs` runs remote key resolution in the existing authenticated config
transaction and login path. `outbound.rs` supplies deployment-owned verified TLS.
`federated_auth.rs` validates signed JWTs; existing identity bindings, token
persistence and live ACL remain authoritative. `auth.rs` owns configuration and
mount-scoped replay state. Service schema 4 protects the new source-selection and
algorithm constraints from older readers.

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

JWT verifies issuer, role audience, iat, exp, sub and jti through the existing
verifier. Its bounded persistent replay ledger consumes a successful assertion
before token release. Role type is `jwt`, user_claim is `sub` in this profile;
Identity alias/entity binding and live entity/group policy checks still apply.
New keys with the same subject reuse the correct existing identity binding.

Remote I/O is bounded but synchronous under the current Service transaction. A
slow or unavailable IdP may deny or delay logins; there is no production throughput
or offline-availability claim. Future caching must specify expiry, revocation,
negative results, concurrency and source identity rather than silently restoring
a stale fallback.

## Explicit non-goals and compatibility limits

`role_type=oidc` is rejected. Authorization URL, browser callback, OAuth code
exchange, PKCE, state/nonce browser binding, redirect validation, client secrets,
userinfo, external-group sync, arbitrary JSON-pointer claims and MFA remain open.
Discovery metadata presence cannot imply these flows execute. OpenBao's remote
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
browser OIDC, jti replay or immediate key-cache invalidation equivalence. Empty
results, duplicate case identities and two failing sides cannot pass admission.
