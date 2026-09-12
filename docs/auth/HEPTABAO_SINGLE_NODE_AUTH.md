# Single-node server authentication and policy implementation

This is the authentication supplement to the `heptabao-server` developer guide.
It documents the implemented Rust module `crates/heptabao-server/src/auth.rs`,
not a separate crate or an independent production authority grant.

## Responsibility and durable transaction boundary

`AuthState` owns token verifiers, ACL policies, user password verifiers,
user-bound TOTP MFA enrollments, AppRole configuration and secret-ID verifiers, the auth mount registry and pinned-key JWT trust/role/replay state. It derives `Clone`, `Serialize` and
`Deserialize`; neither this state nor credential-bearing records implements
`Debug`. The surrounding service serializes it inside the encrypted durable
server state. It is not a separate plaintext authentication database.

For an authenticated application request, the service owns this transaction order (initialization and anonymous login have separate admitted paths):

1. Persist the required request-audit record before dispatch.
2. Clone committed state and authenticate on the clone, consuming one token use if limited.
3. Persist changed token consumption before application authorization/handler dispatch; publish only a durably admitted state.
4. Recheck the private principal against live time/state, then invoke the route on a candidate clone.
5. Commit successful handler mutations before publishing the new state or disclosing response data; discard rejected handler changes.
6. Persist the required response audit before releasing the result. A later audit failure withholds it without undoing the durable token use or application mutation.

Authentication consumption survives an ACL rejection or a malformed owned-route
request. A failed storage commit discards the candidate and cannot return a
new token or secret. An uncertain commit requires authoritative recovery;
the HTTP layer must not treat that outcome as a rejected write. Failed handler
validation does not partially change authentication records. All issued tokens
and AppRole secret IDs are generated before their successful state publication.

`Principal` has private fields and no public constructor or deserializer. Only
`authenticate` creates it. Its accessors expose root status, namespace, policies,
the nonsecret token accessor and whether authentication consumed a token use.
Authorization checks the current token record and its ancestor chain, so a
previously authenticated principal cannot bypass revocation. A principal belongs
to one request; the service must authenticate again for a later request.

The following illustrative excerpts show the current **crate-private** declarations; they are not an external Rust API or a standalone program. `lib.rs` declares `mod auth;`, and these methods are `pub(super)`. `authenticate` mutably consumes a token use and returns one non-cloneable request capability; the service persists consumption before dispatch. `authorize_request` borrows that capability and reevaluates expiry, revocation, ancestor and namespace state at the live caller-supplied `now`. Omitting `now` would allow stale authorization and is not this API. `handle` borrows an optional principal because login is anonymous; dispatch consumes the enclosing principal so it cannot escape to a later request.

<!-- CURRENT API: crates/heptabao-server/src/auth.rs#bootstrap -->
```text
pub(super) fn bootstrap(now: u64) -> Result<(Self, String), AuthError>
```

<!-- CURRENT API: crates/heptabao-server/src/auth.rs#authenticate -->
```text
pub(super) fn authenticate(&mut self, raw: &str, now: u64) -> Result<Principal, AuthError>
```

<!-- CURRENT API: crates/heptabao-server/src/auth.rs#authorize_request -->
```text
pub(super) fn authorize_request(
        &self,
        principal: &Principal,
        namespace: &str,
        path: &str,
        capability: &str,
        now: u64,
    ) -> Result<(), AuthError>
```

<!-- CURRENT API: crates/heptabao-server/src/auth.rs#handle -->
```text
pub(super) fn handle(
        &mut self,
        principal: Option<&Principal>,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Result<Option<AuthResponse>, AuthError>
```


Paths omit `/v1/`. The root namespace is the empty string. Namespaces use
slash-separated identifier segments. Empty, `.` and `..` segments are rejected.
Root tokens can administer any valid namespace. All other tokens are bound to
one exact namespace, including their self-service endpoints. Namespace and
record name are separate nested map keys; concatenation cannot alias `a` plus
`b/c` with `a/b` plus `c`.

## Credential construction and lifetime

Tokens contain 256 bits from `ring::rand::SystemRandom`, encoded with base64url
and prefixed `hvs.`. Persistent token map keys contain SHA-256 of that high-entropy
bearer value; the bearer itself is returned only by bootstrap or issuance.
Accessors are independent 256-bit random values, cannot authenticate and allow
administrative lookup or revocation without knowing the bearer.

Bootstrap creates an immortal root token in the root namespace. The `root`
policy is immutable and exclusive. Only an existing root can issue another root
token; userpass and AppRole cannot ever assign `root`. Ordinary token creation
defaults to a one-hour TTL; the service maximum is 32 days. Integer seconds and
integer `s`, `m`, `h`, `d` duration strings are accepted. Compound or fractional
durations are rejected rather than silently rounded.

Tokens support bounded TTL, an explicit maximum lifetime, renewal, periodic
renewal, limited uses, parent/child revocation, orphan creation and accessors.
Periodic renewal resets expiry to the configured period, subject to an explicit
maximum when set. Creating an orphan or periodic token requires both the normal
operation capability and `sudo`. Nonroot token creation requires a subset of
the issuing token's policies. Limited-use tokens cannot create children.

Parents are traversed on authentication and authorization. Missing, expired,
exhausted or cyclic ancestors fail closed. Explicit revocation removes the whole
descendant tree. Orphan login tokens are independent of an administrator's
session token. Expiration is evaluated at `now >= expires_at`. Deleting a user or
role stops new logins but does not implicitly revoke already issued orphan
tokens; those must be explicitly revoked or allowed to expire.

The last permitted use can authorize its current request. Further
authentication fails. `num_uses = 0` represents unlimited use in request and
response formats; internal `Option<u64>` distinguishes unlimited from exhausted.
Token lookups and renewals never return the bearer token because it is not
stored. This is an intentional compatibility boundary.

## ACL dialect

The default is deny. Capabilities are `create`, `read`, `update`, `delete`,
`list`, `patch`, `sudo` and `deny`. `sudo` does not imply any operation capability:
a protected operation requires its normal capability and `sudo`. Every matching
explicit `deny` overrides grants. Policy edits additionally require `sudo` in
this bounded profile. This conservative rule is not an assertion of full
OpenBao ACL priority compatibility.

Literal paths, a whole-segment `+`, and one terminal `*` are supported:

| Pattern | Match | Does not match |
|---|---|---|
| `secret/+/data/*` | `secret/team/data/a/b` | `secret/team/sub/data/a` |
| `secret/data/team/*` | `secret/data/team/a` | `secret/data/team-other/a` |
| `secret/data/team*` | `secret/data/teams/a` | `secret/data/other` |

The parser rejects interior `*`, partial-segment `+`, traversal, URL-encoded
paths, repeated separators and templated identity interpolation. HCL supports
only repeated `path "pattern" { capabilities = ["read", ...] }` blocks, JSON
string escapes, optional array trailing commas, and `#`, `//`, `/* ... */`
comments. Duplicate HCL path blocks, unsupported fields, unknown capabilities,
unterminated comments, extra statements and malformed syntax are errors.

JSON policy input is either a JSON string or object with the exact structure.
The shared recursive JSON decoder rejects duplicate object keys at every depth;
its partial values are cleared on parsing errors. HTTP request decoding uses the
same entry point to preserve duplicate-key rejection for object-form policies.

```json
{"path":{"secret/data/team/*":{"capabilities":["read"]}}}
```

The built-in `default` policy grants only lookup-self, renew-self and revoke-self.
It is automatically attached unless token creation requests `no_default_policy`;
root tokens do not receive it. An explicitly written namespace `default` policy
replaces those defaults. `root` cannot be read, written or deleted, and `default`
cannot be deleted. Unknown policy names grant nothing.

Not supported: parameter constraints, `min_wrapping_ttl`, `max_wrapping_ttl`,
control groups, identity templating, `required_parameters`, legacy `policy =`
HCL attributes or OpenBao's full path-priority resolution. These inputs fail
closed. There is no silently ignored HCL or JSON policy attribute.

## Userpass

User records contain a random 32-byte salt, a 32-byte PBKDF2-HMAC-SHA256 verifier,
the KDF iteration count (600,000 for new passwords), token policies, TTL/use
limits and an optional persistent TOTP MFA enrollment. Passwords must contain 12–1024 bytes. Login uses `ring::pbkdf2::verify`;
the unknown-user path performs an equivalent dummy KDF. Error messages never
contain the password, verifier, bearer token or secret ID. Password rotation
replaces salt and verifier. The plaintext password is never serialized into
`AuthState`. Owned verifier maps, token parent digests, password salt/verifier
buffers and principal digests are explicitly zeroized on drop. Random generation
buffers and intermediate issued bearer strings use `Zeroizing`; the surrounding
service owns response/request JSON cleanup. This does not promise complete
zeroization of every allocator, compiler or cryptographic-provider copy, or
protection against a compromised host.

Assignments cannot include `root`; a nonroot manager can assign only a subset
of their own token policies. User configuration updates accept explicit
`policies`/`token_policies`, `ttl`/`token_ttl` and `max_ttl`/`token_max_ttl` aliases;
specifying both aliases is rejected. Password and policies subroutes enforce
their respective field boundaries.

## Userpass TOTP MFA

`auth/userpass/users/:name/mfa` owns a bounded user-specific TOTP enrollment.
POST/PUT creates a 256-bit random seed and returns its unpadded base32 form only
in that successful response. Re-enrollment refuses to replace an existing seed
unless the caller explicitly sends `regenerate=true`. Enrollment, regeneration
and deletion require both the route's normal capability and `sudo`. GET returns
only status and fixed algorithm parameters; it never returns the seed.

The implemented profile is TOTP with HMAC-SHA-256, six decimal digits and a
30-second period. Userpass login requires `totp_code` whenever the selected user
has an enrollment. The verifier accepts only the current counter and a one-step
clock window, compares fixed-width ASCII codes with a constant-time primitive,
and durably records the greatest accepted counter. The same or an older counter
can never authenticate again, including after restart or wall-clock rollback.
A future-window code, once accepted, fences the current and previous counters.
Password verification succeeds before MFA evaluation, and every MFA failure
returns the same permission-denied class as an invalid credential.

The MFA seed is serialized only inside the barrier-encrypted service state and is
zeroized when its owned record is dropped. This does not make the seed recoverable
through an API. Administrators must retain their enrollment handoff securely;
regeneration invalidates the old seed immediately. There is no recovery-code,
push, WebAuthn or external MFA-provider implementation in this bounded profile.

## AppRole

Each role has an independent random role ID, token configuration, secret-ID
TTL/use ceilings and a map keyed by SHA-256(secret ID). Each secret ID has its
own random accessor, expiry and remaining uses. Login validates role ID and
secret ID within the exact namespace, checks expiry and use limits, decrements
the secret ID and issues an orphan service token in one durable transaction.

`bind_secret_id` is always true; requesting false is rejected. The default
secret ID is valid for one hour and one login. Requested secret-ID TTL/use
overrides may reduce the role's limits but cannot increase or remove a positive
limit. Role configuration may explicitly select zero for an unlimited secret-ID
lifetime or use count. Secret IDs can be listed by accessor, looked up, or
destroyed by bearer or accessor. Role IDs can be changed, but duplicate role IDs
within a namespace and mount are rejected. No secret-ID bearer can be recovered after
its initial successful creation response.

Not supported: custom secret IDs, CIDR binding, response wrapping, general identity/group administration, batch tokens, LDAP, OIDC discovery/browser login, Kubernetes, cloud IAM, certificate auth, WebAuthn/push/external MFA, auth-plugin execution, mount relocation or per-mount tuning. Unknown security-relevant request fields are rejected. The bounded JWT integration below is a configured verifier protocol, not complete OpenBao JWT/OIDC API compatibility. HTTP supplies a bounded per-IP rate limiter; this module has no distributed login-throttling authority.

## Authentication mount registry

`sys/auth` lists the namespace's enabled methods. `sys/auth/<mount>` manages `userpass`, `approle` or `jwt`; administrative mutation requires the operation's capability and `sudo`. Mount paths are canonical and may contain multiple identifier segments. Overlapping routes and replacement of an existing method without disable are rejected. The registry determines dispatch: a configured custom userpass mount uses `auth/<mount>/users/...` and `auth/<mount>/login/<name>`, and an AppRole mount uses `auth/<mount>/role/...` and `auth/<mount>/login`. ACL checks use the actual custom path, not a rewrite into a privileged default path.

Credentials are isolated by namespace and mount. Equal user names, role IDs or secret IDs in different mounts do not share authority. Existing legacy `users`/`roles` maps remain the default `userpass`/`approle` storage so upgrades preserve those credentials; new custom methods use separate mounted maps. Disabling a mount erases its credentials/configuration and revokes tokens issued there plus their descendants. Legacy tokens missing origin provenance are conservatively revoked within the namespace when disabling the legacy default method; newly issued token-API credentials carry known provenance and are not mistaken for those historical login tokens.

The whole registry, credentials and issued-token provenance live in encrypted `AuthState`, share the Service transaction boundary, survive reopen and follow the HA state replication path. A separately constructed federated verifier result does not become the server's private `Principal`.

## Bounded JWT authentication

Enable a mount of type `jwt`, configure its trust, create an explicitly bound role, then submit `POST auth/<mount>/login` with exactly the supported `role` and `jwt` inputs. This is the restored HeptaBao pinned-key profile. It does not accept the OpenBao PEM `jwt_validation_pubkeys` configuration, fetch a JWKS URL, perform OIDC discovery or implement a browser callback.

Trust configuration at `auth/<mount>/config` supports read and POST/PUT update; mutation requires `update` and `sudo`. Inputs are:

| Parameter | Meaning and bounds |
|---|---|
| `issuer` | Exact trusted `iss`; URL-shaped issuer strings are supported |
| `audiences` | Trusted audience string or string array, including URI audiences |
| `required_namespace` | If supplied, equals the configuring request namespace; root empty string is handled as no additional verifier namespace restriction, while route admission still checks the root namespace |
| `clock_skew_seconds` | Default 30, maximum 300; applies to future `iat`/`nbf`, not to accepting an already expired token |
| `maximum_token_lifetime_seconds` | Default 3600, maximum 86400; bounds the JWT's issued-to-expiry lifetime |
| `keys` | 1–64 entries with distinct selected key identities: `kid`, `algorithm`, `key_base64` |
| key `algorithm` | Exactly `EdDSA` (Ed25519) or `ES256` (P-256); algorithm confusion is rejected |
| key `key_base64` | Unpadded base64url raw public bytes: 32-byte Ed25519 or 65-byte uncompressed P-256 point; this is not PEM |

A role at `auth/<mount>/role/<name>` supports GET, POST/PUT and DELETE. `bound_groups` requires every listed group in the verified `groups` claim; `bound_subject` requires exact `sub`; a nonempty `bound_audiences` requires at least one matching JWT audience. Configured trust independently requires an audience intersection. Role POST/PUT and DELETE require `update` plus `sudo` in this profile. `policies` and `token_policies` are aliases but cannot be supplied together. `token_ttl`, `token_max_ttl` and `token_num_uses` configure the issued service token: default TTL is one hour, default maximum equals that TTL, both are positive and bounded by the service maximum of 32 days, and maximum cannot be below TTL. Roles cannot issue `root` or policies beyond the managing actor's authority, and login must satisfy both configured trust and role restrictions. Readback returns configuration, never an issued bearer.

Login strictly checks header algorithm/key identity/signature and claims `iss`, `sub`, `aud`, `exp`, `iat`, optional `nbf`, `jti`, optional `heptabao_namespace` and `groups`, plus role restrictions. `jti` and `iat` are required. `now >= exp` rejects the JWT; future `iat`/`nbf` allow only configured skew, and `nbf >= exp` is invalid. A nonroot namespace requires an exactly matching `heptabao_namespace` claim; an absent claim maps to the root namespace only. The service token's lifetime cannot exceed the JWT's remaining lifetime. Missing trust returns 503 on login (404 on absent config read); wrong role, replay or failed verification returns 403, malformed route input returns 400, and each case denies issuance and does not silently fall back to an unbound login.

Accepted JWT replay identity, verified identity projection and issued token commit together in `AuthState`. Replay is mount/namespace scoped and survives restart/HA replication. A persistent time watermark prevents a clock rollback from reviving replay entries that were pruned after expiry. Failed verification does not consume a valid future replay entry. This protection does not establish a trusted host clock, external identity lifecycle synchronization or full identity API support.

Successful JWT login creates an ordinary bounded HeptaBao token. Subsequent requests authenticate that token through the same private capability/ACL flow as other methods; JWT verifier helper types are not authorization capabilities. Mount disable removes JWT trust/replay state and revokes its issued tokens. Independent OpenBao differential fixtures must still cover this protocol's intended compatibility scope.

## Route inventory

Default userpass/AppRole paths below also project onto the corresponding configured custom mount as described above.

| Route (without `/v1/`) | Implemented operations |
|---|---|
| `sys/auth`, `sys/auth/:mount` | Registry read/list and sudo-gated method enable/disable |
| `auth/:jwt_mount/config` | GET, POST/PUT pinned-key trust |
| `auth/:jwt_mount/role/:name` | GET, POST/PUT, DELETE bounded role |
| `auth/:jwt_mount/login` | Anonymous POST JWT verification and token issuance |
| `auth/token/create`, `create-orphan` | POST/PUT issue |
| `auth/token/lookup-self`, `lookup`, `lookup-accessor` | GET/POST lookup |
| `auth/token/renew-self`, `renew`, `renew-accessor` | POST/PUT renewal |
| `auth/token/revoke-self`, `revoke`, `revoke-accessor` | POST/PUT cascade revoke |
| `auth/token/accessors` | LIST/GET list, requires sudo |
| `auth/token/tidy` | POST/PUT remove inactive tokens, requires update and sudo |
| `sys/policies/acl`, legacy `sys/policy` | LIST/GET list |
| `sys/policies/acl/:name`, legacy `sys/policy/:name` | GET, POST/PUT, DELETE |
| `auth/userpass/users` | LIST/GET list |
| `auth/userpass/users/:name` | GET, POST/PUT, DELETE |
| `auth/userpass/users/:name/password`, `.../policies` | POST/PUT bounded update |
| `auth/userpass/users/:name/mfa` | GET status; POST/PUT enroll or explicit regenerate; DELETE disable; write/delete require sudo |
| `auth/userpass/login/:name` | unauthenticated POST/PUT; enrolled users require `totp_code` |
| `auth/approle/role` | LIST/GET list |
| `auth/approle/role/:name` | GET, POST/PUT, DELETE |
| `auth/approle/role/:name/role-id` | GET, POST/PUT |
| `auth/approle/role/:name/secret-id` | POST/PUT issue, LIST accessors |
| `.../secret-id/lookup`, `.../secret-id/destroy` | POST/PUT |
| `.../secret-id-accessor/lookup`, `.../secret-id-accessor/destroy` | POST/PUT |
| `auth/approle/login` | unauthenticated POST/PUT |
| `auth/approle/tidy/secret-id` | POST/PUT remove expired/exhausted secret IDs, requires update and sudo |

Read requests use an empty JSON object at the module boundary. Query parsing is
an HTTP-layer responsibility. Missing or denied credentials yield 403, invalid
or unsupported input 400, unsupported owned paths 404, and wrong methods 405.
Public success bodies use `data` or `auth` envelopes; 204 has no payload.

## Verification and remaining acceptance gates

`auth_tests.rs` exercises actual credential verification, password rotation,
restart serialization, no persisted bearer/password plaintext, exhausted uses,
TTL boundaries, periodic renewal maximums, token revocation descendants, orphan
survival, accessor revocation, namespace collision candidates, root-policy
escalation rejection, deny precedence, sudo separation, wildcard boundaries,
strict parser rejection, TOTP enrollment secrecy, required second-factor
verification, replay and clock-rollback fencing, restart persistence, explicit
sudo-only reset, secret-ID expiry/consumption/destruction and failed transaction
clone isolation. Administrative tidy tests verify expired/exhausted
credential removal, active-credential survival and exact namespace scoping.

The synchronous tidy operations reclaim stale verifier records in the selected
namespace. Token tidy includes descendants with invalid ancestors. These
operations make bounded state capacity recoverable after repeated logins; no
background cleanup scheduler is currently enabled.

The tests are local implementation evidence. Full OpenBao black-box differential
compatibility, destructive failure qualification beyond the named finite-use and JWT reopen tests, exhaustive
parser fuzzing, KDF resource-exhaustion qualification, trusted-clock policy, auth
background pruning, additional external authentication providers and independent security
review remain separate acceptance gates. No compatibility percentage or
production qualification follows from this module's existence.

## Current mount and JWT executable scenarios

The following functions in `crates/heptabao-server/src/auth_tests.rs` exercise the current integrated auth code, rather than an unrelated contract crate:

- `custom_userpass_mounts_isolate_credentials_namespaces_and_real_acl_paths` verifies mount/namespace isolation and ACL paths.
- `custom_approle_mounts_isolate_role_ids_secret_ids_and_tidy` verifies separate role/secret-ID state.
- `disabling_auth_mount_revokes_its_tokens_and_children_and_erases_credentials` verifies disable effects.
- `legacy_fixed_auth_state_survives_upgrade_and_unmount_fences_unattributed_tokens` verifies legacy state/provenance handling.
- `jwt_login_composes_pinned_signature_policy_token_and_persistent_mount_scoped_replay` verifies bound issuance and persisted replay.
- `jwt_login_denies_invalid_trust_claims_headers_and_roles_without_consuming_replay` verifies hostile inputs.
- `jwt_replay_pruning_cannot_be_reversed_by_clock_rollback_after_restart` verifies the watermark.
- `jwt_es256_login_uses_real_p256_signature_and_rejects_algorithm_confusion` verifies real ES256 and algorithm selection.
- `jwt_service_persists_login_token_replay_and_unmount_revocation_across_reopen` initializes a real Service/disk state, logs in, reads KV, reopens, rejects replay, disables the mount and verifies revocation after another reopen.

Run `cargo +1.98.0 test --locked -p heptabao-server --all-targets`. Named scenarios identify executable evidence; current pass receipts and independent qualification remain separate.
