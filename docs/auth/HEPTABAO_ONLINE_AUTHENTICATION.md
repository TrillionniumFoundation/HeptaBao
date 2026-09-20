# Online Kubernetes and OIDC authentication: current development profiles

Subordinate to `HEPTABAO-PLAN-2026-09-07-V2.1`. These are actual internal
`heptabao-server` handlers, not new Cargo packages or independent admission.
The global OpenBao 2.6.2 denominator is unchanged. Kubernetes and JWT/OIDC remain
**partial runtime** surfaces, not fully verified or independently admitted.

## Owners and request order

| Owner | Current responsibility |
|---|---|
| `auth_kubernetes.rs` | TokenReview configuration, exact ServiceAccount bindings, UID aliases, local token construction and shared online mount lookup. |
| `auth_oidc.rs` | Confidential OIDC client configuration, roles, encrypted PKCE sessions, state/client-proof checks and signed ID-token verification orchestration. |
| `service_online_auth.rs` | Actual request admission, live Identity projection, durable/HA session consumption and token publication. |
| `outbound.rs`, `outbound_auth_https.rs` | Kubernetes/legacy enrolled HTTPS and scoped JWT/OIDC API-owned HTTPS, bounded POST and strict response framing; never ambient proxies or redirects. |
| `federated_auth.rs` | Real RS256/ES256 signatures and issuer/audience/time checks; OIDC additionally checks nonce/azp/at_hash/c_hash. Native JWT assertions are reusable and do not require jti. |
| `clients/python/heptabao/oidc_login.py` | Actual native loopback callback receiver and descriptor-anchored private credential publication. |

The existing Service request audit, finite-token admission, ReadIndex, leader
forwarding, live Identity and final result audit are retained. Online login
returns no public Principal and does not accept a caller-supplied authenticated
identity. An HTTP success never precedes the relevant durable mutation.

All paths below omit `/v1/`. Mount names can contain canonical multiple segments;
namespace, mount accessor and alias jointly determine the current login identity.
Administrative configuration/role mutation requires the real path's ordinary
capability **and sudo**. A `root` policy may not be assigned by either login role.
Config reads redact reviewer/client secrets; credentials belong in protected JSON
bodies or private files, not command-line arguments, reports or log output.

## Transport authority

Kubernetes TokenReview retains startup `outbound_endpoints`: explicit origin and
port, fixed address, matching server name, CA and optional path prefix. Its API
cannot widen that enrollment. Old JWT/OIDC configuration without the new internal
transport field uses the same enrolled authority. Generic outbound APIs and other
providers are unchanged by the JWT/OIDC transport slice.

Fresh OIDC configuration uses `oidc_discovery_ca_pem` through the auth management
API. Nonempty PEM replaces system roots; empty, null or omitted CA uses system
roots. HTTPS supports DNS, IPv4 and bracketed IPv6 with default port 443, verified
chain and SAN, and the shared bounded resolver. No process endpoint entry is
required. See [the HTTPS transport contract](HEPTABAO_REMOTE_JWT_KEYS.md#administrator-configured-https-and-legacy-enrollment)
for URL, CA, DNS and deadline bounds. OIDC metadata endpoints remain on the exact
normalized issuer origin; no redirects, insecure TLS, ambient proxy or stale-key
fallback are enabled.

Old OIDC records remain enrolled when a full configuration rewrite omits the
active CA. Only an explicit `oidc_discovery_ca_pem` field, including empty or null,
promotes them. Pure reads and login cannot do so. An old unchanged config/role
keeps its serialized pending-session binding. API transport uses a 30-second
whole-effect ceiling and 10-second connection ceiling, both capped by the caller
HTTP deadline (normally 15 seconds). Legacy connections keep their three-second
cap as well as the whole-effect deadline. Documents remain bounded to 128 KiB
with duplicate-key rejection; code exchange and TokenReview have no automatic
transport retry. Provider diagnostics are replaced by fixed errors.

## Kubernetes TokenReview profile

Enable `POST sys/auth/<mount>` with `{"type":"kubernetes"}`.

| Route | Method | Current inputs and behavior |
|---|---|---|
| `auth/<mount>/config` | POST/PUT | Required `kubernetes_host` (enrolled origin only) and `token_reviewer_jwt`. Optional `disable_local_ca_jwt` must be true; omitted also has no ambient fallback. |
| Same | GET | Host and secret-present metadata, never reviewer credential. |
| `auth/<mount>/role/<name>` | POST/PUT | Explicit `bound_service_account_names`, `bound_service_account_namespaces`, required `audience`; optional `token_policies`, `token_ttl`, `token_max_ttl`, `token_period`, `token_explicit_max_ttl`, `token_num_uses`, service-token/UID-alias selectors. Updates preserve omitted fields. |
| Same | GET/DELETE | Read the bounded role or remove it. Existing issued tokens require explicit revoke/expiry or mount disable. |
| `auth/<mount>/role` | GET/LIST | Sorted role names. |
| `auth/<mount>/login` | POST/PUT | Exactly `role` and `jwt`; the presented token is not locally decoded into identity or authority. |

The host and role are checked before egress. Each admitted login sends one
`authentication.k8s.io/v1` TokenReview to the enrolled
`/apis/authentication.k8s.io/v1/tokenreviews` endpoint, with an explicit requested
audience and a separate reviewer bearer. Only HTTP 200/201 with the correct
kind/version, boolean authenticated=true, no review error, a returned audience
intersection, a canonical ServiceAccount username and a nonempty bounded UID
can continue. Missing audiences are not treated as a successful resource audience.
Names and namespaces are checked independently. Lists are bounded to 128 and
reject duplicates; `*` is allowed only as an explicitly selected sole value.

`serviceaccount_uid` is the sole alias profile. Recreating an account under the
same name but a different UID produces a different identity. Reviewer-returned
groups, including a claimed administrator group, are **not** converted into
HeptaBao policies. New service tokens are renewable. Zero or omitted role TTL
uses the mount default; role and mount maxima bound the lease. Periodic tokens
use the current role period, while an explicit maximum is fixed at issuance.
Tokens may have a finite use count. Their token and
live Identity association publish atomically. Disabling the auth mount revokes
its issued tokens and descendants under the existing mount provenance rules.

Renew-self, renew-by-token and renew-by-accessor use the current issuing role
locally, retaining issued policies and the explicit maximum. They perform no
TokenReview and do not recheck changed audience or ServiceAccount bindings.
Missing roles or a passed current maximum reject renewal. Response wrapping and
Identity admission use the ordinary token transaction. Legacy tokens without
Kubernetes role provenance remain nonrenewable and require a fresh login.

Reviewer credential rotation preserves the realm. Changing Kubernetes host
requires a new mount/accessor. Repointing a deployment enrollment to a different
cluster is an operator realm change and likewise requires a new accessor, even
when the hostname is reused. No request may implicitly adopt an in-cluster CA,
service-account file or external network target.

**Revocation boundary:** TokenReview checks each login. It does not continuously
revalidate already issued local tokens. ServiceAccount revocation immediately
blocks subsequent logins when observed by the API; a previously issued local
token remains subject to its local TTL, token/mount revocation and live Identity
policy. Reviewer credential rotation or unavailability does not invalidate an
already issued service token or prevent its local renewal.

## OIDC confidential authorization-code profile

Enable `POST sys/auth/<mount>` with `{"type":"oidc"}`. The existing `jwt` mount
continues to mean its bounded bearer-JWT verifier; these are not full OpenBao
jwt/oidc mount aliases. Authentication code flow does not use an API bearer as an
OIDC access token, and the OAuth access token never becomes a local Principal.

| Route | Method | Required/optional inputs |
|---|---|---|
| `auth/<mount>/config` | POST/PUT | Required `oidc_discovery_url` (exact issuer), `oidc_client_id`, `oidc_client_secret`; optional `jwt_supported_algs` (RS256/ES256 only), `oidc_discovery_ca_pem` and `pkce_s256_enrolled`. |
| Same | GET | Public issuer/client/algorithm/CA fields and secret-present flag. No secret echo or metadata fetch on a read. |
| `auth/<mount>/role/<name>` | POST/PUT | Exact `allowed_redirect_uris`; optional `role_type:"oidc"`, `user_claim:"sub"`, `bound_subject`, `bound_groups`, `token_policies`, `token_ttl`, `token_max_ttl`, `token_period`, `token_explicit_max_ttl`, `token_num_uses`. Updates preserve omitted fields. |
| Same, and role collection | GET/DELETE, GET/LIST | Read/remove role; config or role updates invalidate affected pending sessions. |
| `auth/<mount>/oidc/auth_url` | POST/PUT | Exactly `role`, `redirect_uri`, **client_nonce** (canonical base64url of 32 independent random bytes). |
| `auth/<mount>/oidc/callback` | POST/PUT | Exactly `state`, `code`, and the same independent **client_nonce**. No arbitrary redirect override. |

Configuration preparation validates local fields and update/sudo authority without
DNS or network I/O. Its external effect fetches discovery metadata outside the
Service writer, checks the issuer, and does not fetch JWKS or require auth_url
capabilities yet. At publication, current actor identity, token authority, expiry,
update/sudo rights, mount incarnation, prior configuration, namespace, seal
activation and HA authority are checked again. Only the proposed config is merged
into the latest state, preserving unrelated writes. Publication and pending-session
clearing form one durable transaction; failed preflight or a stale result changes
neither. An identical config with no pending sessions needs no durable append.
The actor's finite-use admission is not charged a second time.

Auth-url and callback effects carry owned config/role snapshots and reject stale
bindings. Successful login resolves current Identity before issuing a token;
provider observations cannot restore an old alias or authorization graph. HTTP
finalization rejects results arriving after the request deadline, even with an
idle writer. This does not cancel a durable commit already begun before expiry.

Only code flow, the openid scope, client_secret_basic and S256 PKCE are used.
The issuer string must exactly match verified discovery. Authorization, token
and JWKS URLs must remain on its normalized origin. Old enrolled transport also
enforces host path limits.
Metadata must advertise S256, or the operator must explicitly set
`pkce_s256_enrolled:true` for an independently checked provider that omits that
metadata property. This flag changes no protocol behavior: the client always
sends S256 and the code verifier. It never enables plain or no-PKCE fallback.
The fixed official OpenBao 2.6.2 issuer fixture covers this explicit omission
profile and verifies that an incorrect challenge is rejected in the actual
exchange. That scoped observation is not a blanket provider certification.

HTTPS redirects must be canonical and exactly role-registered. Native redirects
are limited to `http://127.0.0.1:<explicit-port>/oidc/callback`. There are no wildcards,
localhost DNS aliases, dynamic query additions or insecure remote redirects.
Roles cannot switch the subject claim away from sub. Issuer or client-ID changes
require a new mount/accessor; secret rotation can occur within the same realm.

### Durable session and upstream-effect state machine

```text
validated role + redirect + caller's independent client proof
  -> verified discovery and fresh state / nonce / S256 verifier
  -> durable encrypted session (maximum 128 per mount, 300 seconds)
  -> publish authorization URL (not the verifier or client proof)
  -> callback validates state, client proof, lifetime and role/config binding
  -> durable/HA removal of that session BEFORE token-endpoint contact
  -> one Basic-authenticated authorization-code + verifier POST
  -> fresh trusted JWKS, real signature and all ID-token bindings
  -> local token plus live Identity association durably committed
  -> result audit -> private credential response
```

A failed or uncertain exchange never refunds the consumed session. The same
callback after restart or leader change is denied rather than exchanged again.
A wrong client proof cannot consume another session. A correctly proven callback
that observes expiry commits its deletion and monotonic time observation even
though login is denied, preventing clock rollback from reviving observed expiry.
A definite capacity refusal before session-removal commit does not contact the
issuer. An upstream success followed by failed local publication releases no
token, reports no automatic retry, and requires a new login or recovery.

The ID token must have a trusted current kid/algorithm/signature, exact issuer,
client audience, valid iat/exp/nbf and exact nonce. A multi-audience token requires
matching azp; a supplied azp must always match. Optional at_hash/c_hash are
verified according to the allowed SHA-256 signature algorithms. ID tokens need
not contain jti because replay admission belongs to the one-use session. The
separate native JWT method also accepts assertions without jti and permits reuse;
OIDC still consumes each code-flow session once.

New OIDC service tokens use the issuing role and mount lease limits independently
of the ID token's remaining lifetime. Zero or omitted role TTL uses the mount
default. All three token-renewal routes reread current role TTL, maximum and
period locally, preserving issued policies and the issue-time explicit maximum.
Renewal does not require discovery, another ID token or an available issuer.
Missing roles and a passed current maximum reject renewal; ordinary token,
Identity, wrapping and mount-revocation checks still apply. Old tokens without
OIDC role provenance remain nonrenewable and require a fresh login. Token-API
children and orphans do not inherit the role. Provider refresh tokens and access
tokens are never persisted as local session authority.

Discovery and code-exchange completion both compare the captured auth mount
incarnation before publication, preventing a response from the old mount from
issuing authority after deletion and recreation at the same path. Old pending
sessions retain their exact role/config binding when read across an upgrade;
new zero-valued role fields do not rewrite that binding.

### Native callback client

`heptabao-oidc-login` (or `python -m heptabao.oidc_login`) binds only IPv4 loopback,
checks the exact Host/state/query, accepts one body-free GET, rejects duplicate
headers/query values and smuggling, and uses absolute header/callback deadlines.
A confidential client registration and exact redirect already have to exist on
the issuer and server. The CLI does not create them or approve issuer consent.

```text
heptabao-oidc-login --address https://bao.example:443 --ca-file /private/bao-ca.pem \
  --issuer-origin https://issuer.example:443 --mount browser --role application \
  --listen-port 8259 --callback-timeout 180 --output /private/new-login.json \
  --allow-write --open-browser
```

`--display-auth-url` is an alternative explicit presentation choice for a trusted
terminal. That short-lived URL must not enter shared logs. No bearer appears in
stdout, argv or the browser response page. The output is uniquely reserved as a
0600 regular file in an owner-only descriptor-anchored directory **before any
login request**. Failure leaves an incomplete private file; there is no implicit
retry or inference that the upstream code was not consumed. Python allocator and
library copies are not claimed to be zeroized or locked memory. This is a bounded
native login command, not a complete bao CLI, web UI or Agent auto-auth method.

## Persistence, limits and rollback

Read [the current format contract](../architecture/HEPTABAO_CURRENT_STATE_FORMAT.md)
for the current discriminator and exact upgrade boundaries. Schema 5 introduced
encrypted Kubernetes configs/roles and OIDC config/role/session/clock maps;
schema 20 adds native Kubernetes renewal and schema 21 adds native OIDC renewal.
Schema 28 adds optional API-owned HTTPS authority while preserving old absent
transport serialization and pending-session bindings until explicit promotion.
Valid older state can be read without
rewriting it; committed mutations promote to the current schema. Never downgrade
the discriminator or drop new fields.

The current aggregate Service boundary is 16 MiB, with a finite durable operation
ledger and whole-state HA framing. Provider network work runs outside the Service
writer; publication checks the captured authority and activation fences. Local
owner publication does not remove the logical state bound or qualify throughput.
Full snapshot restore/monotonic rollback protection, mixed-version clusters,
external custody and physical-host fault histories remain separate exits.

## Execution and remaining denominator

Run `cargo test --locked -p heptabao-server` for module and Service tests, followed
by the complete workspace, strict lint and document/source validators.

| Executable | What it actually exercises |
|---|---|
| `qa/openbao-acceptance/kubernetes_online.py` | Actual Service and pinned-TLS TokenReview protocol responses, UID/policy/revocation/hostile behavior and restart. **Not actual kube-apiserver, etcd, Kubernetes RBAC or a distribution qualification.** |
| `qa/openbao-acceptance/kubernetes_renewal_live.py` | Official 2.6.2 and candidate renewal with signed short-lived ServiceAccount JWTs, reviewer outage, role changes, periodic/explicit limits, wrapping, child/orphan separation and restart. Uses a controlled TokenReview endpoint, not a real cluster. |
| `qa/openbao-acceptance/oidc_code_live.py` | Pinned official non-dev OpenBao issuer and actual Service, real user login/code/S256/Basic/ID token, native callback subprocess, replays, role/Identity changes and restart. No browser rendering/consent automation. |
| `qa/openbao-acceptance/oidc_renewal_live.py` | Official 2.6.2 and candidate consumers with a real official OIDC issuer, short ID tokens, stopped issuer, current role lease limits, wrapping, children and restart. Callback and transport-profile differences are disclosed. |
| `qa/openbao-acceptance/online_auth_ha.py` | Three real same-host service processes, official issuer, controlled reviewer, leader death, no quorum and concurrent callback consumption. Not physical multi-host or complete distributed fault coverage. |
| `clients/python/tests/test_oidc_login.py` | Callback parsing, deadlines, issuer URL bindings and actual private file/descriptor boundary. |

Reports carry source and binary identities, fixed check names, execution status
and explicit non-admission flags. Missing prerequisites, nonzero exit, empty
results, source drift or failure do not constitute a pass. Runtime credentials,
CA private keys and issuer/service directories are never uploaded.

Still open: real Kubernetes control-plane version/RBAC/Pod-bound token histories;
full alias and field compatibility; arbitrary OIDC scopes/claim mappings/CEL,
UserInfo/refresh/public-client/browser UI and external MFA; distributed login
throttling and large-scale sessions; independent security/custody/admission.

Public specifications used: Kubernetes TokenReview v1 API definition
(https://kubernetes.io/docs/reference/kubernetes-api/definitions/token-review-v1-authentication/),
OpenID Connect Core 1.0 (https://openid.net/specs/openid-connect-core-1_0.html),
and OpenBao's published OIDC provider API and usage documentation
(https://openbao.org/api-docs/2.4.x/secret/identity/oidc-provider/ and
https://openbao.org/docs/secrets/identity/oidc-provider/). The older API description
is not assumed current: the selected interactions are exercised against the
checksum-pinned official 2.6.2 binary, without importing implementation source.

The new fixture reports bind commit, tree, actual tracked/untracked source bytes
and server-binary SHA-256 before and after execution. Incomplete, duplicate,
non-boolean or changed-input observations fail. Output must be new and private;
existing observations are never overwritten. Successful official-issuer login
is recorded separately from mere configuration of a fixture. The underlying
operator-controlled observations are not independent admission.

Schema numbers identify formats in this source lineage. A different branch using
the same number must not be assumed format-compatible; integration requires a
reviewed field/migration contract and exact-source tests.

After proven session consumption, local Identity denial also reports
`oidc_session_consumed:true`, `retry_allowed:false` and `start_new_login:true`;
it is not mislabeled as a reusable authorization code. Expiration evaluation
includes the elapsed durable/HA consumption commit as well as code exchange
and JWKS retrieval, not merely the final network phase.

The cross-node callback race explicitly targets the observed leader and one
follower. Two fixed node indices can both be followers after an election and
hit the inherited one-forward-slot admission limit (503), which is separate
from session replay rejection. The race still requires exactly one 200 with
one token and one 403 without a token; no 503 is relabeled as a pass. Reports
retain only numeric callback statuses and the credential-response count.


## Actual control-plane acceptance

The controlled `kubernetes_online.py` protocol harness is retained. A distinct
`kubernetes_cluster_live.py` gate now provisions a pinned, fresh local KIND node
and exercises actual kube-apiserver/etcd/RBAC, ServiceAccount TokenRequest and
UID deletion/recreation. See `docs/plan/HEPTABAO_SECTION6_INTEGRATION_20260915.md`
for fixed input digests, prerequisites, cleanup and exact evidence boundaries.
A wired gate does not imply it passed; current-head CI must execute it.

The schema-28 API-CA transport changes passed local Rust tests and strict Clippy.
The [API TLS comparison](../../qa/openbao-acceptance/evidence/jwt-api-tls-856ef3d.json)
passed 141 observations per side and the
[actual 27-to-28 upgrade](../../qa/openbao-acceptance/evidence/jwt-api-upgrade-6b4fed2-to-649c125.json)
passed 121 checks. The [OIDC renewal comparison](../../qa/openbao-acceptance/evidence/oidc-renewal-856ef3d.json)
passed 122 observations per side; [online-auth HA](../../qa/openbao-acceptance/evidence/online-auth-ha-856ef3d.json)
passed 34 checks on one host. Provider login wrapping also
[passed 42 observations per side](../../qa/openbao-acceptance/evidence/provider-login-wrapping-649c125.json)
against actual RADIUS PAP, OpenLDAP and controlled TokenReview providers.
These selected receipts do not alter the confidential-client, POST
callback/client-proof, S256, same-origin or role/claim limitations above, nor
qualify a production Kubernetes cluster or multi-host deployment.
