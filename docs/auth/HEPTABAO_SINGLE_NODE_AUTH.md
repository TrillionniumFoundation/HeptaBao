# Single-node server authentication and policy implementation

This is the authentication supplement to the `heptabao-server` developer guide.
It documents the implemented Rust module `crates/heptabao-server/src/auth.rs`,
not a separate crate or an independent production authority grant.

## Responsibility and durable transaction boundary

`AuthState` owns token verifiers, ACL policies, user password verifiers,
user-bound TOTP MFA enrollments, AppRole configuration and secret-ID verifiers, the auth mount registry and pinned-key JWT trust/role/replay state. The online
extension also owns encrypted Kubernetes reviewer configuration and OIDC
client/session state; see `HEPTABAO_ONLINE_AUTHENTICATION.md`. It derives `Clone`, `Serialize` and
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
uses the token mount default: 32 days in fresh stores, or the preserved one-hour
system default in older stores. The service maximum is 32 days. Integer seconds and
integer `s`, `m`, `h`, `d` duration strings are accepted. Compound or fractional
durations are rejected rather than silently rounded.

A token mount's tune endpoint reports inherited effective defaults. Issuance
clips the requested or default TTL to the current mount maximum. Ordinary Token
API renewal without a positive increment retains the previous granted TTL;
changing the mount default affects new tokens. Current mount maxima still
constrain renewal from issue time, and captured explicit caps remain absolute.
Historical tokens lack the prior-grant field and retain the old one-hour renewal
request until a successful renewal records a grant. Their stored absolute caps
are preserved because old automatic and explicit caps cannot be distinguished.
New tokens capture an absolute cap only when explicit_max_ttl is supplied.
Root tokens with no requested TTL/period remain non-expiring unless explicitly
capped; an expiring root cannot create a non-expiring root. AppRole SecretID
defaults remain separate from service-token defaults.

Tokens support bounded TTL, an explicit maximum lifetime, renewal, periodic
renewal, limited uses, parent/child revocation, orphan creation and accessors.
Periodic renewal resets expiry to the configured period, subject to an explicit
maximum when set. Creating an orphan or periodic token requires both the normal
operation capability and `sudo`. Nonroot token creation requires a subset of
the issuing token's policies. Limited-use tokens cannot create children.

A token-API child's requested and renewed TTL is bounded by its own limits,
including any explicit maximum, and may exceed its parent's remaining TTL.
This reported lifetime does not grant independence: every ancestor must still
be live when the child is used. Renewing an ancestor before it expires can
therefore keep a longer-lived child usable; removing or expiring an ancestor
still invalidates the whole branch. The separate dynamic-secret issuer lifetime
bound remains conservative and is not changed by this token response behavior.
Token lookup omits `period` when it was zero at issue; otherwise it reports the
issue-time period even if an AppRole or JWT role changes its renewal period.

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
a protected operation requires its normal capability and `sudo`. Select the
highest-priority matching path pattern; only identical winning patterns across
policies union their capabilities. `deny` wins within that selected union.
Priority uses later first wildcard, absence of a terminal `*`, fewer segment
`+` wildcards, longer pattern, then lexical order. A broad grant cannot lend
write authority to a narrower read-only match. A broader deny is not a veto on
a different, higher-priority pattern. This changes the earlier all-matches
union and requires policy review before rollout. `auth_acl.rs` implements the
ordering and default rules. Policy edits additionally require `sudo` in this
bounded profile; parameter/template parity remains separately incomplete.

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

The built-in `default` policy grants lookup-self, renew-self, revoke-self and
create/read/update/delete/list on `cubbyhole/*`. All these rules participate in
the same highest-priority pattern selection. It is automatically attached unless
token creation requests `no_default_policy`;
root tokens do not receive it. An explicitly written namespace `default` policy
replaces those defaults. `root` cannot be read, written or deleted, and `default`
cannot be deleted. Unknown policy names grant nothing.

Not supported: parameter constraints, `min_wrapping_ttl`, `max_wrapping_ttl`,
control groups, identity templating, `required_parameters`, legacy `policy =`
HCL attributes. These unsupported inputs fail closed. There is no silently ignored HCL or JSON policy attribute.

## Userpass

User records contain a random 32-byte salt, a 32-byte PBKDF2-HMAC-SHA256 verifier,
the KDF iteration count (600,000 for new passwords), token policies, TTL/use
limits and an optional persistent TOTP MFA enrollment. Native userpass accepts
new passwords of 1–72 UTF-8 bytes; an oversized replacement returns 500, matching
the OpenBao 2.6.2 bcrypt write boundary. Existing long PBKDF credentials retain
their exact-byte verification. The bounded local LDAP profile retains its
12–1024-byte write rule. Login uses `ring::pbkdf2::verify`;
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
native userpass gives the token-prefixed field priority. A null token duration
falls back to its legacy alias, while a supplied null `token_policies` clears
policies. Bounded LDAP still rejects both aliases. A native body `username` is
ignored in favor of the path account, including on password/policy subroutes;
other unrelated fields remain rejected. This does not merge mixed-case accounts.

A general update with an absent, null or empty password preserves its verifier.
New accounts and the password-reset subroute require a nonempty password. Reset
of an unknown account returns 500; missing/empty login passwords return 500,
and wrong passwords or unknown login accounts return 400. These input and status
rules have dedicated tests; bcrypt hash import, bcrypt's 72-byte login truncation
and upstream username case folding remain separate compatibility gaps.

Fresh userpass accounts use zero TTL/max for mount/system inheritance and an empty
configured policy set. Login adds the implicit default policy to the issued token.
Duration omission or null preserves existing limits; explicit zero restores
inheritance. Policy null clears the configured set, and use-count null clears the
count. Positive historical settings and their stored default policies are retained.
Period and explicit maximum are supported; only the issue-time explicit maximum
is captured as a fixed deadline. Ordinary renewal uses current account/mount
limits and equivalent current policies. Password rotation does not revoke an
already issued token or require its password during renewal.

Direct tokens persist issuing-account provenance and username metadata. Missing
legacy provenance is not reconstructed from display names: ambiguous old direct
tokens must log in again to renew. Token API children and orphans retain their own
renewal rules. Removed accounts produce 204 without auth on bearer renewal and
500 on accessor renewal; changed policies produce 500. These responses never
extend the lease. Schema 35 fences the new persisted semantics from old binaries.
CIDR constraints, `token_no_default_policy`, batch tokens, case normalization and
complete password/alias error parity remain outside this profile.
The qualified `0fc7925` candidate records
[279 matching observations per side](../../qa/openbao-acceptance/evidence/userpass-native-0fc7925.json)
and [369 checks using an actual schema-34 binary](../../qa/openbao-acceptance/evidence/userpass-native-upgrade-0fc7925.json).

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

## Certificate authentication (bounded mTLS profile)

The server has a bounded certificate-authentication path. Configure an absolute,
deployment-owned `tls_client_ca_file` outside the encrypted data directory to
turn on mandatory client-certificate verification. An optional
`tls_client_crl_file` is accepted only together with that CA bundle. Rustls's
WebPKI verifier validates the presented chain and client-auth usage before the
request reaches the service; the CRL bundle is checked when configured. A
request cannot supply a certificate through an HTTP header or JSON body.

After mounting `cert` with `POST sys/auth/cert`, an administrator can create
`auth/cert/certs/<name>` with either a single PEM leaf certificate or its
lowercase 64-character SHA-256 digest, plus the ordinary token policy and TTL
limits. `POST auth/cert/login` accepts an empty body and matches the verified
TLS leaf digest. Its optional `name` field selects one named role when a
certificate matches more than one role; an unknown or non-matching name is
denied. A role may additionally set bounded `allowed_names`,
`allowed_common_names`, `allowed_dns_sans`, `allowed_email_sans`,
`allowed_uri_sans`, `allowed_organizational_units`, `required_extensions`
(`oid:pattern`) and `allowed_metadata_extensions` (OID strings). Selectors
use the OpenBao-style case-sensitive `*` glob; `?` is literal. Certificate
attributes and metadata are capped, malformed or duplicate SAN/extensions fail
closed. For a parseable leaf, `auth.metadata` includes OpenBao-compatible
`cert_name`, `common_name`, decimal `serial_number`, and any present
`subject_key_id`/`authority_key_id` (colon-separated lowercase hex), followed by
the selected custom extension values with dotted OIDs converted to dashes. A
synthetic exact-digest role whose leaf is not parseable may still authenticate
when it has no selectors, but receives no certificate metadata; selector roles
fail closed when parsing is ambiguous. Identity binding uses the leaf common
name when it fits the bounded alias grammar; otherwise it falls back to the
configured role name, including for non-parseable exact-digest fixtures.
The verified chain is carried to a leader only inside the authenticated,
bounded HA forwarding frame and is cleared with the request.

This is still a bounded profile, not complete OpenBao certificate parity. It
does not implement OCSP role checks, browser flows or provider qualification.
Certificate-token renewal now requires the same verified leaf certificate to be
re-presented, rechecks its current role selectors, role existence and role
policies, and rejects missing or different certificates before extending the
token. The certificate-auth surface remains outside whole-surface replacement
admission. OpenBao's reference login path performs the
corresponding connection-certificate selection and role validation in
[`path_login.go`](https://raw.githubusercontent.com/openbao/openbao/v2.6.2/builtin/credential/cert/path_login.go).

## AppRole

Each role has an independent random role ID, token configuration, secret-ID
TTL/use ceilings and a map keyed by SHA-256(secret ID). Each secret ID has its
own random accessor, expiry and remaining uses. Login validates role ID and
secret ID within the exact namespace, checks expiry and use limits, decrements
the secret ID and issues an orphan service token in one durable transaction.

`bind_secret_id` defaults to true; setting it to false enables the bounded
role-ID-only login path and ignores an optional SecretID. New roles default
SecretID lifetime and use count to zero (unlimited); existing positive values
remain unchanged. Requested secret-ID TTL/use
overrides may reduce the role's limits but cannot increase or remove a positive
limit. Role configuration may explicitly select zero for an unlimited secret-ID
lifetime or use count. `token_period` can be set up to the service maximum to
issue periodic AppRole tokens; login and renewal use the current role period,
clamped to the current role and mount maxima. A
positive `token_explicit_max_ttl` adds a hard lifetime cap from login time for
both periodic and finite tokens, and periodic renewal is clamped to the
remaining cap. Zero preserves the uncapped periodic behavior. Both fields are
bounded by the 32-day service maximum; the role read response exposes
`token_explicit_max_ttl` and the OpenBao-compatible `period` alias alongside
`token_period`. Secret IDs can be listed by accessor, looked up, or destroyed
by bearer or accessor. Role IDs can be changed, but duplicate role IDs within a
namespace and mount are rejected. No secret-ID bearer can be recovered after
its initial successful creation response.

New role token TTL and maximum default independently to zero, resolving the
current auth mount at login and renewal. Omitted or null duration updates
preserve values; explicit zero restores inheritance or removes that configured
duration. Null count fields select zero. A positive SecretID TTL is clipped to
its own AppRole mount maximum only at issuance; later role/tune changes leave
issued expiry and remaining uses intact. A zero SecretID TTL stays unlimited.

New SecretID lookup includes its original requested TTL, creation time and last
update time, separately from its actual clipped expiration. Finite successful
uses update that time; unlimited uses do not. Exhaustion removes the record:
raw SecretID lookup then returns 204, accessor lookup 404, and login 400.
Historical records lack the new issuance facts; lookup never invents them.
The candidate immediately rejects an expired SecretID. OpenBao 2.6.2 instead
may accept it until periodic tidy runs, so this stricter boundary is tested
separately and is not claimed as identical expiry behavior.

Custom SecretIDs are supported through `role/:name/custom-secret-id` with an
operator-supplied 1–256-byte value plus the role-bounded `ttl` and `num_uses`
limits. The value is returned only in the successful creation response and is
stored as a SHA-256 digest; duplicate active values are rejected rather than
replacing an existing SecretID's uses or expiry. This is a bounded subset: CIDR binding
on authentication methods, LDAP directory search/group-policy synchronization,
batch tokens, cloud IAM, Kerberos auth, WebAuthn/push/external MFA,
auth-plugin execution, complete OpenBao browser/UI semantics, and full
per-method field parity remain unsupported. AppRole roles support both the
default SecretID-bound login and OpenBao's `bind_secret_id=false` role-ID-only
login; the latter intentionally ignores an optional `secret_id` field. Unknown
security-relevant request fields are rejected. JWT/OIDC, Kubernetes, LDAP and
the bounded certificate profile each have runtime limits described below; none
alone is complete OpenBao compatibility. HTTP supplies a bounded per-IP rate
limiter; this module has no distributed login-throttling authority.

Direct AppRole login tokens persist structured issuer provenance containing the
token namespace, mount and role name. Renewal re-reads that exact live role and
mount, so deleting the role or mount denies renewal and current finite TTL/max
settings take effect without changing the token's policies. An omitted or zero
renewal increment uses the current role TTL. Ordinary maxima are measured from
issue time and can be raised for a still-active token; switching to periodic
renewal removes the ordinary absolute age limit. The explicit maximum captured
at issue remains fixed even if the role later adds, removes, reduces or expands
its explicit maximum. A deleted role or a still-active token past the current
finite maximum returns 500, matching OpenBao 2.6.2; already expired tokens remain
403. Old stored absolute caps remain conservative because they cannot be
classified as ordinary versus explicit; log in again to use raised ordinary
limits. Tokens created through `auth/token/create` deliberately do not inherit
AppRole issuer provenance and therefore use ordinary token renewal semantics.
This persisted field requires service state schema 11; older binaries reject it
instead of silently dropping renewal authority. Bounded RADIUS PAP mounts add durable route and token policy in schema 12; the process-enrolled `radius://` UDP endpoint and shared secret stay outside `AuthState`, and schema-11 readers reject the state. The profile supports one-shot IPv4 UDP PAP with strict Message-Authenticator and Response Authenticator checks; CHAP, EAP, IPv6, challenge flows and full OpenBao field parity remain outside this slice.

Schema 16 adds direct RADIUS token provenance and a bounded PAP credential inside
encrypted Auth state. `auth/token/renew-self`, `renew`, and `renew-accessor` stage a
fresh exchange with the current enrolled provider without holding the Service
writer. Access-Reject returns 400; unavailable or unauthenticated provider replies
fail closed with 503. A successful reply is followed by current actor ACL and
Identity checks, target token/accessor/expiry checks, and mount/configuration and
token revision comparisons. A concurrent change rejects the stale observation;
only a successful durable commit extends the token. Current policies, excluding
implicit `default`, must equal the token's issue-time token policies. Current
TTL and maximum settings are reread on renewal; the ordinary maximum bounds total
lifetime from the original issue time. Raising it can extend a still-active new
token beyond its former maximum. Omitted or zero increment uses the current TTL.
A live token past a shortened current maximum returns 500 without changing its
existing lease; an expired token remains 403. New logins do not persist an ordinary
maximum as an explicit cap. Legacy stored absolute caps remain enforced; a fresh
login is required to benefit from a raised limit.
RADIUS configuration also accepts `token_period` and `token_explicit_max_ttl`.
Periodic renewal uses the current period and maximum after provider verification;
the explicit maximum stays fixed at token issuance. Token lookup retains its
issued period even when configuration changes. A zero TTL uses the mount default.
Partial configuration updates preserve omitted fields; null duration fields keep
their values, while `token_policies:null` or `[]` clears the configured policy
list. Login still attaches the default policy. These fields require schema 22;
the existing host-enrolled UDP destination and shared-secret profile remain.
Response wrapping remains available on these renewal endpoints: the token
extension and its single-use response wrapper publish in one durable transaction.
Provider rejection, wrapper capacity failure or a rejected commit cannot publish
the extension separately from the wrapper. Only `renew-self` and `renew` echo
the bearer already supplied on the request; accessor renewal cannot recover it.

The credential is never included in token lookup, response metadata, audit
records or token-API children, and its owned buffers are zeroized on drop. New
token-API children and orphans carry a separate issuer marker. Legacy tokens
with a parent remain ordinary children. A legacy parentless RADIUS-associated
token without provenance might be a direct login or an orphan child, so renewal
is refused with a request to log in again; its existing expiration and other
permissions remain unchanged. This is a bounded PAP renewal profile, not full
RADIUS compatibility. Finite-token renewal defaults follow the current TTL as
described above. The original URL configuration remains available for existing
mounts; new native configuration is described below.

Schema 24 adds native `host`, `port`, `secret`, `unregistered_user_policies`,
`dial_timeout`, `read_timeout`, `nas_port` and `nas_identifier` configuration.
The host is stored lowercase, port defaults to 1812, both timeouts to 10 seconds,
NAS-Port to 10 and NAS-Identifier to empty. Configuration stores the encrypted
shared secret and omits it from readback. Schema 26 lets fresh native
configuration authorize its own host and port without process enrollment.
DNS uses a fixed worker pool and a bounded address list; IP literals bypass DNS.
The selected peer is fixed before the sole PAP request is sent. No provider
response authorizes a new address or credential fallback. Native requests always
use the configured secret.

Old native records retain the enrolled origin and fixed socket until an explicit
host or port write promotes them, even if that field's value is unchanged.
Secret, policy and timeout-only updates preserve the old network authority.
The process credential remains optional for these old native mounts; legacy URL
mounts require their original process credential. Transport changes invalidate
pending login and renewal observations through the existing revision checks.

Native RADIUS and native LDAP accept `token_bound_cidrs` as a list or comma-separated string;
null or an empty list clears future issuance constraints. The bounded profile
accepts up to 128 numeric IP, CIDR or IP:port entries. Containment ignores port,
preserves host bits in readback and normalizes IPv4-mapped IPv6 using the pinned
upstream behavior. Unix socket strings and invalid masks are rejected rather
than reproducing upstream's Unix-address fallback. Login checks the actual
listener socket address before PAP or LDAP Bind/Search. Each issued token stores its constraints;
later config changes do not rebind it. Ordinary children inherit them; orphans
do not. Central token admission checks both immutable reads and mutations before
consuming a finite use, and rechecks the actor after external work. Administrative
lookup/renewal checks the caller token's constraints, not the target token's IP.
Native LDAP partial config updates preserve omitted CIDRs; null/empty clears
future issuance only. Direct LDAP token snapshots and constrained config require
schema 29. Existing legacy bounded LDAP keeps its prior behavior. Wrong-source
login rejects before contacting the directory, while administrative provider
renewal checks the caller's source constraints and retains the target's snapshot.
The [native LDAP CIDR comparison](../../qa/openbao-acceptance/evidence/ldap-cidrs-a14a7fd.json)
passed 134 observations per side with actual OpenLDAP and IPv4/IPv6 socket peers.
The [real 28-to-29 upgrade](../../qa/openbao-acceptance/evidence/ldap-cidrs-upgrade-649c125-to-a14a7fd.json)
passed 70 checks; [same-host HA](../../qa/openbao-acceptance/evidence/ldap-cidrs-ha-a14a7fd.json)
passed 49, including forwarded origin, election, retained snapshots and quorum
loss. These selected runs do not qualify Unix-address semantics, batch tokens or
multi-host faults.
Untrusted forwarding headers cannot supply the peer. HBFQ3 preserves the original
socket peer through authenticated HA forwarding; missing peer information denies
a constrained token. Mixed-version forwarding to older binaries can fail closed
and is not a rolling-upgrade qualification.

`users/:name` stores optional policies and may be written before configuration.
The last mapping's deletion leaves a native-profile mount entry. User writes and
deletes use literal keys; reads and login lookup use lowercase names, matching
OpenBao's asymmetric behavior. LIST supports `after`/`limit` URL query parameters.
An existing user mapping replaces the unregistered-user fallback, including an
empty mapping, and its policies are combined with mount policies. Login adds the
default policy unless `token_no_default_policy` is true; explicitly assigned
`default` is still retained. The flag defaults to false, survives partial updates,
and null resets it to false. Existing tokens keep their issued policies when the
flag changes. Zero-policy tokens do not gain renewal/lookup permission implicitly;
an administrator can renew them. Their auth response omits `token_policies`.
New configurations preserve OpenBao's nil-versus-empty policy distinction:
with no fallback, omitted `token_policies` rejects a zero-policy renewal with 500,
while explicit `[]` or null permits it. Older schema-24 configurations keep their
already-normalized empty-list behavior because the original input is unrecoverable.
These default-policy and policy-presence semantics require schema 25. Deleting a mapping does not necessarily revoke access: renewal
rechecks PAP and compares the resulting policies. A changed effective policy set
returns 500 without extending the token. Raw fallback CSV is preserved in
readback and issued metadata; OpenBao's renewal compares those raw fallback names,
so whitespace or case differences can reject renewal even after login normalized
the issued policies. `auth/.../login/:username` and the body username are supported.
Issued metadata survives all renewal and token lookup routes.

PAP sends NAS-Port as the low 32 bits of the signed stored value and sends a
nonempty NAS-Identifier. There is one request and no retry. Read timeout zero
fails before sending; dial timeout zero has no separate connect limit but remains
bounded by the overall read deadline. Supported timeouts are 0–60 seconds,
shared secrets 1–256 bytes, passwords 1–128 bytes and usernames/NAS identifiers at
most 253 bytes. New native host configuration supports ASCII DNS names and bare
IPv4/IPv6 literals. Read timeouts cover DNS, connect, request and authenticated
response; nonzero dial timeouts additionally bound DNS and local connect. Signed ports can be stored for faithful
readback, but invalid destination ports fail before I/O. The profile requires
strict response and Message-Authenticator verification; CHAP, EAP, challenges,
arbitrary timeout ranges and the full TokenParams surface remain open. Native/legacy configuration mixing returns 400, changing an
existing profile returns 409, and native configuration DELETE returns 405.

## Authentication mount registry

`sys/auth` lists the namespace's enabled methods. `sys/auth/<mount>` manages `userpass`, `approle`, `jwt`, `kubernetes`, `oidc`, bounded `ldap`, bounded RADIUS PAP or the bounded `cert` mTLS profile; administrative mutation requires the operation's capability and `sudo`. Mount paths are canonical and may contain multiple identifier segments. Overlapping routes and replacement of an existing method without disable are rejected. The registry determines dispatch: a configured custom userpass mount uses `auth/<mount>/users/...` and `auth/<mount>/login/<name>`, an AppRole mount uses `auth/<mount>/role/...` and `auth/<mount>/login`, and certificate mounts use `auth/<mount>/certs/...` plus `auth/<mount>/login`. ACL checks use the actual custom path, not a rewrite into a privileged default path.

Credentials are isolated by namespace and mount. Equal user names, role IDs or secret IDs in different mounts do not share authority. Existing legacy `users`/`roles` maps remain the default `userpass`/`approle` storage so upgrades preserve those credentials; new custom methods use separate mounted maps. Disabling a mount erases its credentials/configuration and revokes tokens issued there plus their descendants. Legacy tokens missing origin provenance are conservatively revoked within the namespace when disabling the legacy default method; newly issued token-API credentials carry known provenance and are not mistaken for those historical login tokens.

The whole registry, credentials and issued-token provenance live in encrypted `AuthState`, share the Service transaction boundary, survive reopen and follow the HA state replication path. A separately constructed federated verifier result does not become the server's private `Principal`.

## Bounded JWT authentication

Enable a mount of type `jwt`, configure its trust, create an explicitly bound role, then submit `POST auth/<mount>/login` with exactly the supported `role` and `jwt` inputs. This is the restored HeptaBao pinned-key profile. In addition to the historical explicit `keys` array, configuration can accept an inline public-only RFC 7517 `jwks` object for Ed25519/EdDSA and P-256/ES256 verification. This paragraph describes the static-key profile only. The current remote-key profile supports API-configured `jwks_url` and OIDC Discovery over verified HTTPS; historical records retain their enrolled transport until explicit promotion. See [the remote key contract](HEPTABAO_REMOTE_JWT_KEYS.md). Browser authorization-code callbacks use the separate OIDC mount profile; full OpenBao JWT claim-mapping parity remains open. Static and remote trust sources are mutually exclusive.

Trust configuration at `auth/<mount>/config` supports read and POST/PUT update; mutation requires `update` and `sudo`. Inputs are:

| Parameter | Meaning and bounds |
|---|---|
| `issuer` | Exact trusted `iss`; URL-shaped issuer strings are supported |
| `audiences` | Trusted audience string or string array, including URI audiences |
| `required_namespace` | If supplied, equals the configuring request namespace; root empty string is handled as no additional verifier namespace restriction, while route admission still checks the root namespace |
| `clock_skew_seconds` | Optional legacy extension, 0–300 seconds; grace applies only to future `iat`/`nbf`, while `now >= exp` rejects. A supplied role `clock_skew_leeway` replaces this with native time semantics. Absent in a new config means native role/default semantics |
| `maximum_token_lifetime_seconds` | Optional legacy extension, 1–86400 seconds; requires signed `iat` and `exp` and bounds their difference. New configs have no implicit lifetime cap |
| `keys` | 1–64 entries with distinct selected key identities: `kid`, `algorithm`, `key_base64`; mutually exclusive with `jwks` |
| `jwks` | Inline RFC 7517 public key set; accepts only signature-use Ed25519/EdDSA or P-256/ES256 public material, rejects private/symmetric/duplicate/unknown-key input; mutually exclusive with `keys` |
| key `algorithm` | Exactly `EdDSA` (Ed25519) or `ES256` (P-256); algorithm confusion is rejected |
| key `key_base64` | Unpadded base64url raw public bytes: 32-byte Ed25519 or 65-byte uncompressed P-256 point; this is not PEM |

A role at `auth/<mount>/role/<name>` supports GET, POST/PUT and DELETE. `bound_groups` requires every listed group in the verified `groups` claim; `bound_subject` requires exact `sub`; a nonempty `bound_audiences` requires at least one matching JWT audience. Configured trust independently requires an audience intersection. Role POST/PUT and DELETE require `update` plus `sudo` in this profile. `policies` and `token_policies` are aliases but cannot be supplied together. `token_ttl`, `token_max_ttl` and `token_num_uses` configure the issued service token: new roles default both TTL and maximum to zero, independently inheriting the current mount settings. Explicit zero restores inheritance; omitted or null duration fields preserve existing values. Nonzero values are bounded by the service maximum of 32 days, and a nonzero maximum cannot be below TTL. Older stored positive defaults remain unchanged. Fresh stores inherit a 32-day system default and maximum; historical stores preserve the one-hour inherited default. Roles cannot issue `root` or policies beyond the managing actor's authority, and login must satisfy both configured trust and role restrictions. Readback returns configuration, never an issued bearer.

Static and remote JWT roles also support `bound_claims` and `bound_claims_type`
(`string` or `glob`). Every configured selector must match the original
signature-verified claims; alternatives within a selector use OR. Selectors
starting with `/` use JSON Pointer traversal, and glob matching treats only `*`
as a wildcard. This is an issuance check; local renewal keeps its existing role
and lifetime checks. See the [bound-claims contract](HEPTABAO_REMOTE_JWT_KEYS.md)
for numeric behavior, partial updates and the schema-30 downgrade fence. Claim
mapping and arbitrary `user_claim` selection remain outside this profile.

For OpenBao API readback compatibility, JWT config GET returns both `issuer` and
`bound_issuer`, while role GET returns both `policies` and `token_policies`; each
pair is the same persisted value and does not create a second authorization path.

Login checks header algorithm/key identity/signature, `iss`, `sub`, `aud`, time claims, optional `heptabao_namespace` and `groups`, plus role restrictions. `jti` is optional and does not make an assertion single-use. At least one nonzero `iat`, `nbf` or `exp` is required. NumericDate fractions truncate toward zero; null and zero act as absent dates. Missing `exp` is derived from the later of `iat`/`nbf` plus expiration leeway. Missing `nbf` uses `iat` when nonzero, otherwise `exp` minus not-before leeway. The role's `clock_skew_leeway` applies to all three time comparisons; zero or unset selects 60 seconds and negative disables it. `expiration_leeway` and `not_before_leeway` zero/unset select 150 seconds, negative disables the respective derivation offset. They do not add grace to an existing signed date. These role fields accept signed seconds or durations and are preserved on partial role updates.

A nonroot namespace requires an exactly matching `heptabao_namespace`; an absent claim maps to the root namespace. The issued service token has its own role/mount lifetime and can outlive the JWT. Missing trust returns 503 on login (404 on absent config read); signature, time and claim failures return 400, while core ACL/live-identity rejection remains 403. Config extensions stored by older binaries remain active until a config replacement explicitly omits them; they do not silently become native defaults on upgrade.

Each successful use of a valid JWT issues a distinct service token with the same subject's identity binding, including after restart. Service commits issuance and identity together. On the first successful native login it also retires that mount's legacy assertion replay map and watermark, with schema 19 preventing an older reader from restoring the former behavior. Failed verification leaves the store unchanged. OIDC one-use state/nonce and strict public proof replay checks remain independent. This does not establish a trusted host clock or full identity API support.

Successful JWT login creates a bounded service token carrying its issuing role
name in schema-18 Auth state. `renew-self`, `renew` and `renew-accessor` reread that
role: deletion returns 500 without changing expiry. They do not revalidate the
JWT, fetch JWKS, compare current claim bindings or replace issued token policies.
Live identity, caller ACL, revocation and expiry checks still apply. A finite
token's current role/mount maximum is measured from its original issue time;
raising it can extend an active token beyond its previous role maximum.
`token_period` ignores requested increments and is clipped by the current maximum;
only `token_explicit_max_ttl` captured at issuance imposes an absolute lifetime on
a periodic token. Later changes to that role field do not replace an existing
token's explicit maximum. Both fields default to zero and are bounded by 32 days.
Renewal, identity projection and optional response wrapping commit together.
Token-API children do not inherit the JWT role. Legacy parentless JWT tokens
without role provenance keep their existing permissions and expiry but must log
in again to renew. Mount disable removes JWT trust/replay state and revokes its
direct tokens and ordinary children; independent token-API orphans retain their
own lifetime. Selected static/remote differential cases do not establish full
JWT claim-mapping or configuration parity.

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
| `auth/approle/role/:name/custom-secret-id` | POST/PUT issue an operator-supplied bounded SecretID |
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
- `jwt_es256_login_uses_real_p256_signature_and_rejects_algorithm_confusion` verifies real ES256 and algorithm selection.

The JWT scenarios in `auth_tests.rs` and `federated_native_jwt_tests.rs` cover
reusable native assertions, hostile inputs, explicit legacy trust extensions,
time derivation and persisted identity/token authority. The separate strict proof
and OIDC tests still require one-use admission. The real TLS runners
`jwt_login_claims_live.py`, `jwt_renewal_live.py` and `jwt_native_upgrade.py` exercise
official comparison and a pinned historical upgrade/downgrade/recovery sequence.

Run `cargo +1.98.0 test --locked -p heptabao-server --all-targets`. Named scenarios identify executable evidence; current pass receipts and independent qualification remain separate.

## Integrated token-private storage

The current Cubbyhole backend lives in the server's private Token state, not a
standalone engine crate. See [the Cubbyhole implementation contract](../engines/HEPTABAO_CUBBYHOLE.md)
for routes, ACL selection, atomic final-use clearing, expiry/tidy, bounds,
restart behavior and tests. Built-in default rules do not let a token access
another token's map, including a root token. New tokens never inherit values.
This increment does not add response wrapping or full lease expiration.

The [current Identity runtime contract](../engines/HEPTABAO_IDENTITY_RUNTIME.md)
describes the implemented Service-owned login binding and live authorization
projection, not the separate identity crate. After credential verification,
Userpass uses the authenticated user name, AppRole the verified role ID, and the
pinned JWT profile the verified `sub`, each scoped to namespace and the current
mount accessor. JWT subjects must additionally satisfy the current Identity
alias alphabet/128-byte ceiling; broader JWT/OIDC claim mapping remains work.

New login tokens durably store only `entity_id`, not a frozen copy of identity
policy grants. Each admitted Service request obtains current entity/internal
group policy names, rejects disabled or deleted entities, and applies the same
ACL specificity/deny rules as token policies. Responses separate `token_policies`
from `identity_policies`; child-token policy attenuation uses token policies
only. A policy change therefore affects an already-issued token on its next
request. Disabling is not revocation: enabling the same entity again can restore
its nonrevoked token, whereas a deleted entity name cannot revive old tokens.

`AuthMount.accessor` is persisted. Legacy records missing it use a deterministic,
namespace/mount/type-separated accessor without read-side writes. New or
re-enabled mounts get a fresh random accessor. Old tokens missing `entity_id`
remain readable and unbound; this is an explicit compatibility limitation, not
silent reconstruction from names. Remount/re-enrollment is an operator action.

The `identity_service_tests.rs` suite exercises grants/revocation on existing
tokens, disable/re-enable, nested groups, child attenuation, merge lineage,
namespace/mount incarnation isolation, restart and failed-login publication.
These are source test anchors, not independent OpenBao or production admission.

Identity-aware token bindings use Service state version 2. Old optional fields
are omitted for byte-preserving version-1 reads, but the first durable mutation
promotes the complete state to version 2. Version-1-only binaries must reject
that state; see the server guide and operator runbook before any rollback.

## Current wrapping and introspection APIs

[Response wrapping](HEPTABAO_RESPONSE_WRAPPING.md) and
[live capability inspection](HEPTABAO_CAPABILITIES.md) now run through the actual
Service boundary. Wrapper records are encrypted and single-use; ordinary lookup
metadata does not consume them. The default policy grants wrap/unwrap/lookup and
self capability inspection, but not rewrap or arbitrary subject inspection.
The new state writer emits schema 3; the identity-aware schema-2 baseline remains
readable only without wrapping/SSH-lease state and is upgraded only on mutation.
The SSH engine's CIDR rules are not authentication-method CIDR support.

## Remote key-source extension

The current [remote JWKS / OIDC Discovery JWT implementation](HEPTABAO_REMOTE_JWT_KEYS.md) adds API-configured verified HTTPS, login-time key refresh and RSA/RS256. Historical records retain their enrolled transport until explicit promotion. Static keys remain a separate mutually exclusive profile. Browser authorization-code OIDC, MFA and arbitrary claim mapping are not implied. Newly persisted source/algorithm constraints require schema 4; API-configured transport requires schema 28.

## Online methods and schema 5

The current [online authentication guide](HEPTABAO_ONLINE_AUTHENTICATION.md)
specifies actual Kubernetes TokenReview and confidential OIDC code flow, including
all supported input fields, boundaries and executable tests. Those use distinct
`kubernetes` and `oidc` mount types; the static/remote `jwt` sections retain their
existing verifier scope and jti requirement. Complete JWT/OIDC alias/API parity,
real Kubernetes control-plane qualification and full external MFA remain open.

## Bounded external LDAP authentication

A mount of type `ldap` has a real external authentication path. Root-controlled
`auth/<mount>/config` binds an exact host-enrolled `ldaps://` origin and a
bounded `user_dn_template` containing `{{username}}`. Login performs an LDAPv3
simple bind over rustls with the deployment-pinned address, server name and CA.
The outbound path performs no DNS discovery, redirect, referral, StartTLS upgrade,
SASL fallback or automatic retry. Empty passwords, plaintext `ldap://` login,
unenrolled origins and malformed DN/template inputs fail closed.

The Service prepares the LDAP login under the authoritative writer, releases that
writer for the bounded network bind, and reacquires it before token publication.
A successful provider bind is therefore only authentication evidence: the
mount-local durable user record still owns policies, token limits and optional
TOTP state. Removing that local mapping prevents token issuance even if the
directory continues to authenticate the password. Changing the mount/config while
a bind is in flight is fenced before publication. The local password verifier in
that mapping is deliberately not consulted for LDAP login.

`qa/openbao-acceptance/ldap_bounded.py` exercises the production LDAPS framing
against a strict TLS LDAP fixture. `qa/openbao-acceptance/ldap_openldap_live.py`
launches the host-installed OpenLDAP `slapd`, seeds a synthetic inetOrgPerson,
then verifies real TLS bind, wrong-password denial, provider outage/recovery,
server restart and local-authority revocation. When `group_dn` is configured, the same successfully authenticated user TLS
session performs one bounded subtree search with an equality match on
`group_attr` (default `member`) against the exact authenticated user DN and
returns only `group_name_attr` (default `cn`). Local
`auth/<mount>/groups/<name>` records map those observed directory group names to
token policies. Membership is observed on every login, so removal from the
directory removes those policies from the next token without waiting for a local
cache expiry. Search is capped at 128 groups and rejects referrals, controls,
arbitrary filter syntax and paging.

Direct LDAP tokens retain their bounded original password only inside encrypted
Auth state, with a zeroizing credential owner and schema-17 issuer provenance.
Every `auth/token/renew-self`, `renew` and `renew-accessor` request rebinds that
credential and repeats the live group search outside the Service writer. Bind,
search or transport failure returns 400. The observed groups and current local
user/group mappings must yield the same token policy set (ignoring implicit
`default`); a policy change returns 500 and requires a new login. After provider
authentication, renewal reads the current local-user TTL and local-user/mount
maximum. The ordinary maximum is measured from issue time and can be raised for
a still-active new token. Omitted or zero increment uses the current TTL. A live
token past a shortened current maximum returns 500 without extending or revoking
its existing lease; an expired token remains 403. Legacy stored absolute caps
remain enforced, so a fresh login is required to use raised limits. LDAP
token-period and explicit-maximum configuration remain unimplemented.

LDAP directory group names also refresh external Identity groups selected by
`identity/group-alias` name plus the issuing mount accessor. Login and successful
renewal add/remove that entity's membership for this accessor only; a second
mount's evidence remains independent. Identity-only policy changes therefore
allow renewal and appear immediately in `identity_policies`, effective request
permissions and group membership. Internal ancestor-group policy projection uses
the refreshed membership. Manually supplied or legacy external member indexes do
not substitute for provider evidence. Disabling a mount removes its evidence;
renaming, deleting or rebinding an identity alias invalidates its grants.

The shared provider renewal finalizer rechecks the live actor, target token and
accessor, username/entity alias binding, enabled mount/configuration, local
user/group mapping revisions, namespace, expiry, activation and HA leadership
before publication. The token, membership and optional response wrapper share
one commit. Pre-publication failure cannot publish a partial extension or group
update. A successful remote commit with an unknown local outcome follows the
existing recovery protocol. Bearer echo is limited to the credential supplied
on `renew-self` or `renew`; accessor renewal cannot reconstruct a bearer.

Token-API children and new orphan tokens never inherit LDAP passwords. Legacy
children with a parent keep their ordinary renewal behavior. A legacy parentless
LDAP-associated token without direct-issuer provenance must log in again to
renew, because older direct logins and token-API orphans are indistinguishable;
its existing permissions and expiry are not otherwise changed. Auth and Service
state tests cover persistence, concurrency fences, group synchronization and
atomic wrapping. `qa/openbao-acceptance/ldap_renewal_live.py` compares real LDAPS
Bind/Search, credential/group revocation, identity-only group updates and restart
renewal against pinned OpenBao 2.6.2 with explicit configuration adaptation.

An earlier SSD Linux arm64 run is recorded in the [scoped OpenLDAP receipt](../../qa/openbao-acceptance/evidence/ldap-openldap-live-079e2cb.json).
It is external-provider evidence only; it does not admit full OpenBao LDAP
field/error parity or independent production qualification.

This legacy profile retains its DN template and required local mapping. New
mounts can instead select native manager-search configuration using `binddn`,
`bindpass`, `userdn` and `userattr`; see
[`HEPTABAO_LDAP_RUNTIME.md`](../engines/HEPTABAO_LDAP_RUNTIME.md). Native users and
groups are optional policy mappings. Native login and all three renewal routes
perform manager bind, unique user search, user bind, manager rebind and configured
group search. Current token limits, issued explicit caps, external Identity
groups and wrapping use the existing atomic publication path. Native state
requires schema 23. Mixing configuration vocabularies returns 400; switching an
existing profile returns 409 and requires a new mount.

StartTLS, SASL, referrals, arbitrary filters, nested-group expansion and full
OpenBao LDAP API/error parity remain product work. New native mounts configure
LDAPS through the standard `url`, `certificate`, `connection_timeout` and
`request_timeout` fields. They do not require process endpoint enrollment.
Certificate omission/empty uses system roots; explicit PEM selects only those
roots, with full server-name validation. URLs admit DNS, IPv4 and bracketed IPv6,
with port 636 by default. Connection and whole-exchange budgets default to 30 and
90 seconds, respectively, and are bounded to 1–300 seconds in this implementation.
DNS and system-root loading use four fixed workers and a bounded queue; timeout
does not create a replacement worker for a blocked platform call. No LDAP
referral or server response can select another endpoint or trust root.

Schema 23/24 native records keep their original enrolled transport until an
administrator explicitly writes a certificate or timeout field; normal partial
updates and reads preserve it. API-owned transport requires schema 25. The
configuration snapshot is checked again before publishing login or renewal,
including when the CA or URL changes during directory I/O.

Native LDAP supports `token_no_default_policy`, including preservation of
explicitly mapped `default` and OpenBao's distinction between omitted and empty
token policy configuration. Issued token policies remain fixed during renewal.
The [native LDAP contract](../engines/HEPTABAO_LDAP_RUNTIME.md) describes zero-policy
renewal behavior and the schema-30 state boundary.

## Auth mount revision, tune and remount boundary

Auth mounts expose a persisted `revision` alongside the existing accessor. Tune, disable
and remount accept `cas_revision` and reject stale operators without mutation. A remount
preserves the accessor while atomically moving mount-local users, roles, JWT/OIDC,
Kubernetes and bounded LDAP state and retagging issued-token mount provenance. Disabling
the moved mount retains the existing credential/token revocation behavior; recreating the
path issues a different accessor and revision 1. `sys/remount` cannot cross auth/secret
classes or namespaces. These are repository-local runtime guarantees, not full external
provider or OpenBao compatibility admission.

## Public mounted login and unrelated bearer headers

Exact mounted POST/PUT login paths authenticate their explicit password,
SecretID or verified external assertion rather than an unrelated bearer header.
A stale bearer does not block valid login; a separate finite-use bearer is not
consumed by that login. Namespace, enabled mount kind, method and complete path
shape select this exception. A root bearer does not make a wrong password or
SecretID succeed, and token-management/protected routes still reject invalid
bearers. The same audited durable issuance, MFA and provider checks remain.
The public-login regressions include nested mounts, restart, finite-use
non-consumption, wrong-namespace and protected-route denial.


## Bounded authentication mount migration input contract

`qa/openbao-acceptance/migrate_auth_mount.py` is a separate metadata/re-enrollment
adapter, not a credential transfer. For lockout-capable source methods, live
OpenBao 2.6.2 tune readback uses flat `user_lockout_disable` and
`user_lockout_{threshold,duration,counter_reset_duration}` fields, unlike the
request's nested `user_lockout_config`. The importer requires explicit disabled
lockout for this limited profile and typed bounded counters; nested caller-shaped
configuration is not accepted as proof. Source credentials, accessors and token
authority are not transferred. Consumers must authenticate against deliberately
provisioned destination credentials after migration. The real fixture verifies
mount TTL, old-credential refusal, new login, restart and idempotent resume.
