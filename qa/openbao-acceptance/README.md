# Live OpenBao acceptance and controlled KV-v2 transfer

These Python standard-library tools act on real HTTPS APIs. Their unit tests use
explicit fault-injection doubles to test tool safety; those doubles are never an
OpenBao Oracle, a compatibility corpus, or evidence of a deployed service.

| Entry point | Purpose | Default effect |
|---|---|---|
| `acceptance.py` | Synthetic KV-v2/token/Transit/auth black-box cases, optional independent OpenBao comparison | No writes without `--allow-test-writes` |
| `migrate_kv2.py` | Explicitly selected KV-v2 histories, direct transfer or private export/import | Read-only dry-run |
| `ha_acceptance.py` | Three-or-more-node observation and controlled external failover/readback phases | Observation only; missing nodes are `not_run` |
| `live_migration_rehearsal.py` | Start a supplied verified Oracle and real candidate in one network context; rehearse copy, SIGKILL, acknowledgement loss and resume | Explicit invocation creates synthetic test resources |
| `bao_http.py` | Verified HTTPS, private files, bounded JSON, identity checks | No insecure TLS or bearer-token redirect |

Python 3.10+ and POSIX descriptor/ownership semantics are required for private
files and migration locks. No third-party Python dependency is required. The
service endpoints, CA certificates and provisioned tokens are external inputs.
No token, unseal key, private key, secret value or response body belongs in argv,
test fixtures, result files, logs or the repository.

For every endpoint prefix, configure `PREFIX_ADDR`, `PREFIX_CACERT`, and exactly
one of `PREFIX_TOKEN_FILE` or `PREFIX_TOKEN`. The file option is preferred: it
requires a regular file owned by the effective user with no group/other access,
and rejects symlinks. An optional `PREFIX_NAMESPACE` selects an already-created
namespace; the tools do not create namespaces. Set tokens through an approved
credential source, never a shell command containing a literal secret.

```sh
export HB_CANDIDATE_ADDR=https://candidate.example:8200
export HB_CANDIDATE_CACERT=/secure/qa/candidate-ca.pem
export HB_CANDIDATE_TOKEN_FILE=/secure/qa/candidate.token
python qa/openbao-acceptance/acceptance.py --candidate-only --allow-test-writes
```

Do not disable TLS verification to make this pass. HTTP, user-info URLs,
cross-origin redirects, implicit proxy environment variables and unbounded
responses are rejected. Existing administrative tokens can enable and remove
synthetic mounts and ACL policies; use a dedicated test deployment or an
explicitly delegated test namespace.

Results use bounded classifications and booleans. The acceptance output includes
the observed version, endpoint origin, hashed cluster identity, tool source
digest, case method/path template, HTTP status and asserted side effects. It does
not include token values, KV values, ciphertext, key material or raw errors.
Result files and checkpoints require an existing owner-only directory, normally
mode `0700`, and are atomically published as mode `0600`.

```sh
python -m unittest discover -s qa/openbao-acceptance/tests -p 'test_*.py' -v
python qa/openbao-acceptance/ha_acceptance.py
```

The second command deliberately exits nonzero with `status=not_run`: a local
unit-test pass or an absent HA deployment must never become an HA pass.

Detailed operating contracts and examples:

- `docs/compatibility/HEPTABAO_SINGLE_NODE_ACCEPTANCE.md`
- `docs/migration/HEPTABAO_OPENBAO_MIGRATION.md`

`evidence/live-migration-20260908.json` records the actual scoped migration
rehearsal against the named OpenBao2.6.2 and candidate binary digests. It is not a
receipt for future binaries or full-format migration. Archive additional actual
execution receipts and bind each to the tested deployment and immutable candidate
source identity before making a scoped claim. No live HA pass is bundled.

## Additional selected runtime profiles

`userpass_names_live.py` compares fresh userpass CRUD, login, canonical Identity
aliases, raw ACL paths and restart with pinned OpenBao 2.6.2. Uppercase password
and policy subroutes have separate observations: OpenBao can leave shadow
records, whereas the candidate changes the canonical account. Those observations
are explicit differences and never counted as matching behavior.
`userpass_names_upgrade.py` requires a qualified old schema39 binary and its
committed no-default-policy receipt; the old executable creates distinct
Alice/alice accounts and tokens, and the new executable must preserve their
exact renewal sources through reads, mutations, restart and rejected downgrade.
Only a newly created mount adopts canonical names. `userpass_names_ha.py` uses
three local TLS voters for standby forwarding, raw ACL checks, leadership
transfer, restart and all-voter token readback. It does not cover MFA over HTTP,
PostgreSQL or physical host failures. These profiles create only private fresh
fixtures and do not qualify a full OpenBao instance migration.

`native_snapshot_ha_restore_gated_live.py` tests exact pre-Publish and
post-commit/pre-local-persist crashes using the Linux-only
`fixture-native-restore-faults` feature. It requires a separately built,
default-feature recovery executable from the same source commit and the hashes
of both binaries. Each phase creates a fresh three-voter TLS cluster; an owned
socketpair carries a bounded, nonce-bound event before the controller kills its
child. Recovery must preserve the expected full KV/ACL state at every voter and
after complete restart. Its receipt distinguishes instrumented crash evidence
from ordinary recovery and does not cover power loss or physical hosts.

`response_wrapping.py`, `capabilities_live.py`, `ssh_otp_live.py` reuse the strict
nonempty/all-passed comparison harness with the pinned official binary. They do
not self-advance `complete_surface_corpus_v1.json`. `client_live.py` exercises the
real Python CLI. `wrapping_ha.py` and `ssh_otp_ha.py` include earlier HA profiles,
so their scenario counts are overlapping, not additive coverage. `wrapping_upgrade.py`
requires the exact schema-2 legacy binary hash and exercises actual schema-3
wrapping/OTP mutation, old-reader rejection and recovery. Use absolute binaries,
new output names and an existing mode-0700 evidence directory. All fixture secrets
remain in temporary private directories and are removed by these launchers.

`namespace_seal_live.py` exercises the native server's bounded namespace-seal
profile: durable seal flags, ancestor request fences, parent-controlled unseal,
unauthorized-control rejection and restart persistence. It is bound to the
authenticated global barrier and does not qualify independent namespace key
custody, key rotation or complete OpenBao namespace workflow compatibility.

Capacity saturation/reopen and real metadata preflight use `capacity_live.py` and
`migration_preflight_live.py`. Both create only new synthetic TLS instances;
preflight fixture success never authorizes a full-instance migration. See
`docs/operations/HEPTABAO_CAPACITY_AND_GROWTH.md` and
`docs/migration/HEPTABAO_MIGRATION_PREFLIGHT.md`.

## Online authentication profiles

`kubernetes_online.py` exercises the actual server and pinned-TLS TokenReview
protocol; it explicitly does not qualify a kube-apiserver or Kubernetes RBAC.
`kubernetes_renewal_live.py` compares actual HTTPS service-token renewal with
pinned official 2.6.2 after synthetic TLS TokenReview login. It covers three
renewal routes without another TokenReview, assertion expiry, current role
TTL/max/period and issued explicit max, policy snapshots, wrapping, rejected
renewals without extension, child/orphan tokens, restart, role deletion, zero
TTL defaults and partial role updates. The receipt explicitly separates the
candidate's process-enrolled CA from the oracle's mount CA/key configuration
and records the official request's omitted TypeMeta. This remains a synthetic
TokenReview protocol profile, not a Kubernetes cluster or RBAC qualification.
`kubernetes_native_upgrade.py` creates a fresh store with the receipt-pinned
schema-19 binary, then checks schema-20 reads without application rewrites,
old nonrenewable tokens remaining nonrenewable after role updates, and new
native renewal tokens. It also exercises rejected downgrade and recovery,
including existing child/orphan tokens and encrypted-state credential scans.
Reopen comparisons exclude only the root replay ledger rebuilt before schema
validation; live read/rejection checks compare the entire store. Existing
stores are never accepted as fixture input; this does not qualify rolling or
full-instance migration.
`oidc_code_live.py` uses the fixed official 2.6.2 issuer, actual code/PKCE exchange,
ID-token signatures and the native callback executable. `online_auth_ha.py`
extends the real three-process fixture with leader death, quorum loss and
concurrent code consumption. All need a new report in an owner-only directory;
the latter two also require the existing verified official binary/archive.
These profiles do not alter fixed-corpus surface status, production authority
or independent admission. See `docs/auth/HEPTABAO_ONLINE_AUTHENTICATION.md`.

The compatibility corpus records selected checks from these profiles through
`external_fixture_case_registry_v1.json`. The registry binds every external
case to its executable script and keeps those checks separate from the generic
differential runner; a scoped fixture is evidence of bounded runtime behavior,
never a claim of complete OpenBao auth compatibility or independent admission.

`radius_renewal_live.py` compares RADIUS token renewal against the checksum-pinned
OpenBao 2.6.2 binary using real TLS servers and local UDP PAP responders. It
checks provider acceptance/rejection on self/token/accessor renewal, target-token
echo without accessor bearer leakage, opaque wrapping/one-use unwrap, policy
changes, revocation, and provider revalidation after SIGKILL/reopen. Finite and
periodic cases cover current maximum increases, omitted/zero increments,
mount-default TTLs, config partial updates and null handling, issued explicit
caps, and the period snapshot retained by token lookup. Duration-null updates
preserve settings; a null or empty policy list clears configured policies while
issuance still adds the default policy. Every renewal still requires a fresh
provider decision. Completion requires the provider, lifetime, configuration,
period and explicit-cap milestones; case counts are reported without a fixed
count gate. The receipt
explicitly records the configuration adaptation: candidate URL and host-enrolled
secret versus official host/port/secret fields. The official request may omit
Message-Authenticator; the candidate responder still requires it, and both
responders sign reply authenticators. Only fixed case IDs, statuses and boolean
observations enter the report. This does not establish RADIUS API parity.

`radius_native_live.py` uses the same host/port/secret configuration on both
sides and validates optional user mappings, case-sensitive storage keys, LIST
pagination, raw fallback policies, issued metadata, NAS attributes, secret
rotation, renewal, wrapping and restart against pinned 2.6.2. The candidate
endpoint grants a fixed destination without a process secret; configuration does
not authorize new network destinations. Receipts retain the timeout and strict
Message-Authenticator profile limits instead of claiming full RADIUS parity.
`radius_config_native_upgrade.py` opens a real schema-23 store with the new binary,
preserves old finite/periodic/child/orphan tokens, exercises native configuration
and policy changes, rejects a schema-23 downgrade, and verifies recovery and
credential isolation. Process enrollment is adapted explicitly for the older
binary; the encrypted store is never edited to make downgrade succeed.

`radius_renewal_ha.py` uses three real server processes and gates signed UDP
acceptance across leader SIGKILL, quorum loss and sealing. It reads absolute
token expiry back to detect stale-authority renewal. This is a process-level HA
fixture, not evidence from independent physical hosts.
Its `--native` mode keeps the same fault scenarios while obtaining the shared
secret from encrypted API configuration; the enrolled endpoint has no process
secret and the actual UDP request must carry the native default NAS-Port.

`ldap_renewal_live.py` compares two independent real OpenLDAP stores with pinned
LDAPS certificates and the official 2.6.2 binary. Its provider trace checks fresh
Bind/Search on all three token renewal routes, changed/deleted LDAP passwords,
directory outages, token-policy changes, revocation, wrapping and service restart.
A separate identity trace keeps token policies fixed while external group aliases
add/remove live identity policies. Two auth accessors share one entity and the same
directory group name, so renewal must update only the observed accessor's group
membership; read access, token lookup, renewal output and group membership are
checked together and after restart. Configuration is explicitly adapted: candidate
host enrollment and DN template/local user authority versus official LDAP service
bind/search fields and mount TTL. Deleting `userPassword` tests simple-bind
credential disablement, not Active Directory account flags. Receipts contain fixed
case IDs, statuses and booleans, never directory log contents or credentials.

`ldap_native_live.py` compares native manager-search configuration, optional
user/group mappings, case and alias behavior, filter operations, all renewal
routes, external Identity membership, wrapping and restart with pinned OpenBao
2.6.2 on independent real OpenLDAP stores. CA/address enrollment is explicit;
this does not establish full LDAP API, filter or Active Directory compatibility.
`ldap_native_upgrade.py` requires the committed schema-22 build receipt and binary
hash, then checks the same encrypted store through schema 23, old mapping-based
revocation, native login without a mapping, child/orphan credential isolation,
read-only reopen, downgrade refusal and recovery. Only safe statuses/booleans
enter receipts; store, audit and logs are checked for plaintext credentials.

`ldap_native_renewal_ha.py` holds a real OpenLDAP successful final search response
behind a TLS relay while the leader dies, loses quorum or seals. It checks that
the stale request publishes neither a lease extension, wrapper nor changed
Identity membership. Recovery must reauthenticate with the live directory and
commit the new lease and group membership together. Three local processes use
the journal backend; this is not physical-host or PostgreSQL qualification.

`provider_renewal_upgrade.py` exercises a real schema-15 → schema-17 binary/store
round trip with OpenLDAP. It requires the fixed f31b98e legacy binary and 8f7c907
candidate hashes, checked against their committed clean execution receipts. These
are caller-bound build identities, not inferred from the current checkout or an
independent binary attestation. Old direct LDAP tokens and indistinguishable old
token-API orphans retain read access but must log in again to renew; old children
with a real parent retain ordinary token renewal. New logins acquire durable
provider renewal. The old binary then rejects the upgraded store, and the new
binary recovers. Application snapshots and append journals must stay unchanged
during rejected downgrade; `ledger.hbl` is explicitly excluded across reopen
because both binaries rebuild and re-encrypt that replay checkpoint before
application-schema validation. Pure reads and rejected ambiguous renewals after
unseal must leave the entire store unchanged. This selected upgrade sequence does
not qualify rolling upgrades or arbitrary historical stores.

`jwt_native_upgrade.py` opens a real schema-18 store created with the pinned
`c749caf` binary, then exercises schema-19 native JWT login. Pure reads and failed
logins must preserve the entire opened store. Explicit legacy clock and lifetime
extensions retain their behavior until configuration is replaced; ordinary JWT
reuse then issues distinct service tokens, including after restart. A rejected
old-binary downgrade must preserve application artifacts, with the same explicit
`ledger.hbl` reopen exception as the provider fixture. The candidate build commit
is caller-supplied and kept separate from the executing harness identity. This
historical binary pair does not qualify rolling upgrades.

`jwt_renewal_live.py` compares static ES256 and remote-JWKS service-token renewal
with official 2.6.2. The JWT expires shortly after login; the issued token keeps
its role-based TTL, and renewal consults current local role settings while keeping
issued token policies. It checks three renewal routes, wrapping, role maximum and
period changes, issue-time explicit maximum, deleted roles, token-API children and
orphans, and restart. The remote issuer is unavailable during renewal and its HTTP
request count must not increase. Static public-key configuration and remote CA
enrollment are explicitly adapted. `--build-source-commit` may supply a caller's
binary build identity; the current harness checkout is reported separately and
never treated as proof of binary provenance. This is not complete JWT/OIDC API,
browser authorization, or configuration-update parity.

`jwt_login_claims_live.py` separately compares ordinary static/remote JWT login:
optional or empty `jti`, repeated use of the same signed assertion, distinct
service tokens bound to the same entity, and another login after restart. Its
native time matrix covers single `iat`/`nbf`/`exp` claims, missing-claim synthesis,
zero/null/fractional/negative NumericDates, no implicit one-hour lifetime cap, and
role leeway set to zero/default, negative/disabled, or positive values. Separate
cases distinguish clock-skew grace on present claims from expiration/not-before
leeway used only to synthesize missing claims. It rejects assertions expired
beyond grace and those missing all time claims. Configuration is the native
profile without candidate-only clock/lifetime extensions. This profile does not
change or qualify OIDC code consumption, nonce checking, or state replay rules.

`oidc_renewal_live.py` compares native service-token renewal after real RS256
OIDC code exchange through separate pinned official OpenBao 2.6.2 issuers.
It uses two-second ID tokens, waits beyond their configured lifetime, stops
both issuer processes, and checks three renewal routes, bearer response shape,
current role TTL/max/period, issued explicit caps, policy snapshots, wrapping,
rejected renewals without extension, child/orphan tokens, role deletion and
restart. Role readback preserves explicit policies and partial updates; omitted
or empty policies stay empty in the role and add `default` only at login.
Candidate process CA/S256 enrollment and POST callback are explicitly
adapted to the oracle's mount CA and GET callback query. Issuer termination is
observed; absence of outbound connection attempts is not claimed. This profile
does not qualify browser UI, third-party IdPs, refresh-token exchange or full
OIDC API compatibility. Reports bind observed binary hashes separately from the
caller-supplied build commit and current harness source.

`oidc_native_upgrade.py` creates old nonrenewable tokens and an actual pending
code session using the receipt-pinned schema-20 binary. The current binary must
read the store without changing application artifacts, complete that unchanged
session with its persisted PKCE/proof binding, and issue a new renewable token.
Old tokens remain nonrenewable even after role updates. Downgrade rejection,
recovery, consumed-session replay rejection and credential scans use the same
fresh encrypted store. Only the root replay ledger is excluded from reopen
byte comparisons; live reads and rejected old renewals compare the whole store.
This is bounded upgrade evidence, not rolling or full-instance migration.

`radius_native_upgrade.py` creates finite provider tokens and ordinary
child/orphan tokens with the receipt-pinned schema-21 binary, then checks the
schema-22 configuration update against the same encrypted store. Old finite
tokens reauthenticate through signed UDP PAP and use the current period without
rewriting their original lookup parameters. New periodic tokens retain their
issued period and absolute explicit cap when configuration limits increase.
The profile checks pure reads and provider rejection without store mutation,
rejected downgrade and recovery, generic child/orphan renewal without PAP, and
credential absence from encrypted state and diagnostics. Reopen comparisons
exclude only the rebuilt root replay ledger. Only fresh fixture stores are
accepted; this is not full-instance or rolling-upgrade qualification.

`rabbitmq_live.py` is a Linux-only, real-provider profile for the immutable
RabbitMQ 4.1 management image digest recorded in the script. It configures a
private loopback endpoint, issues an actual AMQP user, verifies vhost and
permission denial, rejects unsupported renewal, restarts both services,
revokes the user, and reconciles a durable pending revoke across a provider
outage. Missing Docker or the pinned image returns 77; macOS execution is
blocked and is never evidence of a Linux pass. Its receipt contains only case
IDs and image identity, never credentials.
