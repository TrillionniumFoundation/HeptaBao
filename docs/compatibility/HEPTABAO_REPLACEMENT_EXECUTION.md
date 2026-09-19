# Per-surface OpenBao replacement execution requirements

Subordinate to `HEPTABAO-PLAN-2026-09-07-V2.1`; not a new global plan.
Edit `planning/HEPTABAO_REPLACEMENT_EXECUTION_V2.json` and run `python scripts/validate_replacement_execution.py --write`.
The fixed corpus remains the denominator; this table neither adds a pass receipt nor reduces its scope.
A listed profile is an executable entry point, not coverage of all requirements in its row.
`RUNTIME_COMPLETE_LOCAL` means repository-local runtime behavior is executable but later migration, physical fault, full differential and independent-admission phases remain open. `PARTIAL_RUNTIME` means real bounded code; `CONTRACT_ONLY` means a separate model/interface; none alone means full compatibility.

## Common acceptance dimensions

### protocol

Positive endpoint/method/parameter and exact status/body/error-precedence differential. Equal failures are not successful behavior.

### authorization

Default-deny, least privilege, namespace/mount/owner and live revocation checks at actual runtime entry.

### effect_readback

Observe actual persisted or provider-side effects; absence of a response is not proof of no effect.

### crash_replay

Before/after intent, publication, commit and response interruption; duplicated/ambiguous requests never repeat effects blindly.

### expiry_revocation

Clock regression, TTL, revoke and idle lifecycle must survive restart and HA without resurrection.

### migration_upgrade

Exact version pair, all owned data and key/tombstone formats, no dropped assets and no unsafe old-binary fallback.

### capacity_operations

Declared capacity, latency/memory/recovery cost, long-run saturation, safe diagnostics and operator recovery.

### independent_admission

Use the existing external-evidence verifier and full declared scope, exact source/artifact identity, freshness and revoked-key checks. Repository CI cannot self-issue this.

## Exact surface requirements

### HB-SURFACE-CORE-REQUEST-PIPELINE

Implementation: `RUNTIME_COMPLETE_LOCAL`. Original work packages: `H07-WP01`, `H07-WP02`, `H07-WP06`, `H07-WP10`.
API families: `/v1/*`.
Runtime source: `crates/heptabao-server/src/http.rs`, `crates/heptabao-server/src/service.rs`.
Separate contracts: none claimed.
Guides: `docs/modules/heptabao-server.md`.

**Positive:** Trace authenticated request through one owner and accepted/result audit.

**Hostile:** Reject duplicate headers, ambiguous paths, expired principals and denied effects.

**Lifecycle:** Recover each intent/state/commit/response failure without blind replay.

**Remaining scope:** Local request framing, authorization-before-effect, pure-read/nonpure-read persistence, unknown-outcome recovery and reopen behavior are executable; migration, real multi-host fault/upgrade, full OpenBao 2.6.2 differential and independent admission remain owned by later ordered phases.

Existing bounded profiles: `qa/openbao-acceptance/acceptance.py`.

### HB-SURFACE-SYSTEM-BACKEND

Implementation: `RUNTIME_COMPLETE_LOCAL`. Original work packages: `H07-WP05`, `H07-WP09`.
API families: `sys/init`; `sys/unseal`; `sys/seal`; `sys/rekey/*`; `sys/health`.
Runtime source: `crates/heptabao-server/src/service.rs`.
Separate contracts: none claimed.
Guides: `docs/modules/heptabao-server.md`.

**Positive:** Enumerate supported methods, request fields and success envelopes for every sys route.

**Hostile:** Verify sealed, missing-root and malformed-field error precedence.

**Lifecycle:** Reopen initialization, lost response and verified rekey without publishing two roots.

**Remaining scope:** Local system endpoint/method/field inventory, sealed/error precedence, initialization reply-loss recovery, threshold unseal and verified rekey/reopen behavior are executable; format migration, real multi-host upgrade/fault, full OpenBao 2.6.2 differential and independent admission remain later phases.

Existing bounded profiles: `qa/openbao-acceptance/acceptance.py`.

### HB-SURFACE-MOUNT-REGISTRY

Implementation: `RUNTIME_COMPLETE_LOCAL`. Original work packages: `H07-WP03`, `H07-WP04`, `H07-WP07`.
API families: `sys/mounts/*`; `sys/auth/*`; `sys/audit/*`; `sys/remount`.
Runtime source: `crates/heptabao-server/src/auth.rs`, `crates/heptabao-server/src/engines.rs`, `crates/heptabao-server/src/service.rs`.
Separate contracts: none claimed.
Guides: `docs/modules/heptabao-server.md`.

**Positive:** Enable, inspect, tune, relocate and disable all declared mount classes.

**Hostile:** Reject overlapping mounts, unauthorized tune and cross-namespace relocation.

**Lifecycle:** Persist mount incarnations and revoke old leases and credentials after disable/recreate.

**Remaining scope:** Local secret/auth/audit mount registry, revision CAS, atomic remount, overlap and reserved-path rejection, restart persistence and disable/recreate incarnation or accessor fencing are executable; full asset migration, real multi-host fault/upgrade, full OpenBao 2.6.2 differential and independent admission remain later ordered phases.

Existing bounded profiles: `qa/openbao-acceptance/acceptance.py`.

### HB-SURFACE-POLICY-ACL

Implementation: `PARTIAL_RUNTIME`. Original work packages: `H08-WP01`, `H08-WP02`, `H08-WP03`, `H08-WP04`, `H08-WP05`, `H08-WP06`, `H08-WP07`, `H08-WP08`, `H08-WP09`, `H08-WP10`.
API families: `sys/policies/acl/*`; `sys/capabilities*`.
Runtime source: `crates/heptabao-server/src/auth_acl.rs`, `crates/heptabao-server/src/service_capabilities.rs`.
Separate contracts: none claimed.
Guides: `docs/auth/HEPTABAO_CAPABILITIES.md`.

**Positive:** Match full ACL specificity, templates and parameter constraints against official behavior.

**Hostile:** Check glob/segment ties, explicit deny and malformed policy without privilege union.

**Lifecycle:** Apply live policy replacement and deletion to existing tokens across HA/reopen.

**Remaining scope:** Security advisories and path/glob/list/scan edge cases require dedicated corpus.

Existing bounded profiles: `qa/openbao-acceptance/core_isolation.py`, `qa/openbao-acceptance/capabilities_live.py`.

### HB-SURFACE-IDENTITY

Implementation: `PARTIAL_RUNTIME`. Original work packages: `H09-WP01`, `H09-WP02`, `H09-WP03`, `H09-WP04`, `H09-WP05`, `H09-WP06`, `H09-WP07`, `H09-WP08`, `H09-WP09`, `H09-WP10`.
API families: `identity/entity/*`; `identity/group/*`; `identity/mfa/*`; `identity/oidc/*`.
Runtime source: `crates/heptabao-server/src/engines/identity.rs`, `crates/heptabao-server/src/service_identity.rs`.
Separate contracts: none claimed.
Guides: `docs/engines/HEPTABAO_IDENTITY_RUNTIME.md`.

**Positive:** Compose entities, aliases, internal/external groups, MFA and provider identity.

**Hostile:** Reject merge cycles, stale mount aliases and cross-namespace policy binding.

**Lifecycle:** Persist merge lineage, disabled entities and group revocation through failover.

**Remaining scope:** Namespace and mount non-interference are release blockers.

Existing bounded profiles: `qa/openbao-acceptance/identity_live.py`.

### HB-SURFACE-TOKEN

Implementation: `PARTIAL_RUNTIME`. Original work packages: `H10-WP01`, `H10-WP02`, `H10-WP03`, `H10-WP04`, `H10-WP05`, `H10-WP06`, `H10-WP11`.
API families: `auth/token/*`.
Runtime source: `crates/heptabao-server/src/auth.rs`.
Separate contracts: none claimed.
Guides: `docs/auth/HEPTABAO_SINGLE_NODE_AUTH.md`.

**Positive:** Cover service/batch/recovery, parent/orphan, periodic/max TTL, finite uses and CIDR.

**Hostile:** Deny policy escalation, accessor leakage and using a consumed token twice.

**Lifecycle:** Observe expiry, cascaded revocation and lost-response creation across restart.

**Remaining scope:** Includes parent/orphan, periodic, explicit max TTL, uses and CIDR semantics.

Existing bounded profiles: `qa/openbao-acceptance/acceptance.py`.

### HB-SURFACE-CUBBYHOLE-WRAPPING

Implementation: `PARTIAL_RUNTIME`. Original work packages: `H10-WP07`, `H10-WP08`.
API families: `cubbyhole/*`; `sys/wrapping/*`.
Runtime source: `crates/heptabao-server/src/auth_cubbyhole.rs`, `crates/heptabao-server/src/auth_wrapping.rs`.
Separate contracts: none claimed.
Guides: `docs/auth/HEPTABAO_RESPONSE_WRAPPING.md`.

**Positive:** Read token-private values and wrap/lookup/rewrap/unwrap exact response envelopes.

**Hostile:** Deny peer/root access to another token cubbyhole and wrapping-token general authority.

**Lifecycle:** Race unwrap across leader failure; verify one release and durable expiration.

**Remaining scope:** Single-use and active/standby response-loss behavior require race fixtures.

Existing bounded profiles: `qa/openbao-acceptance/core_isolation.py`, `qa/openbao-acceptance/response_wrapping.py`, `qa/openbao-acceptance/wrapping_ha.py`.

### HB-SURFACE-LEASE-EXPIRATION

Implementation: `PARTIAL_RUNTIME`. Original work packages: `H11-WP01`, `H11-WP02`, `H11-WP03`, `H11-WP04`, `H11-WP05`, `H11-WP06`, `H11-WP07`, `H11-WP08`, `H11-WP09`, `H11-WP10`, `H11-WP11`.
API families: `sys/leases/*`.
Runtime source: `crates/heptabao-server/src/engine_leases.rs`, `crates/heptabao-server/src/service_lifecycle.rs`.
Separate contracts: none claimed.
Guides: `docs/operations/HEPTABAO_AGENT_PROXY_HELPER.md`.

**Positive:** Issue, renew, lookup and revoke local and external leases using actual provider readback.

**Hostile:** Deny cross-mount prefix revocation, stale owner use and lease resurrection.

**Lifecycle:** Recover ambiguous provider replies, idle expiry and cancellation without orphan effects.

**Remaining scope:** External effect ambiguity must remain indeterminate until evidence.

Existing bounded profiles: `qa/openbao-acceptance/idle_lifecycle_ha.py`.

### HB-SURFACE-AUTH-TOKEN

Implementation: `PARTIAL_RUNTIME`. Original work packages: `H16-WP01`, `H16-WP10`.
API families: `auth/token/lookup*`; `auth/token/renew*`; `auth/token/revoke*`.
Runtime source: `crates/heptabao-server/src/auth.rs`.
Separate contracts: none claimed.
Guides: `docs/auth/HEPTABAO_SINGLE_NODE_AUTH.md`.

**Positive:** Use token bearer authentication with exact public error and response shapes.

**Hostile:** Reject invalid, expired, wrong-namespace and exhausted tokens.

**Lifecycle:** Persist accepted finite-use consumption even when later handler authorization fails.

**Remaining scope:** HTTP/API projection delegates durable token state to heptabao-token.

Existing bounded profiles: `qa/openbao-acceptance/acceptance.py`.

### HB-SURFACE-AUTH-USERPASS

Implementation: `PARTIAL_RUNTIME`. Original work packages: `H16-WP02`, `H16-WP10`.
API families: `auth/{mount}/users/*`; `auth/{mount}/login/*`.
Runtime source: `crates/heptabao-server/src/auth.rs`.
Separate contracts: none claimed.
Guides: `docs/auth/HEPTABAO_SINGLE_NODE_AUTH.md`.

**Positive:** Authenticate salted password records and enrolled MFA with documented lockout.

**Hostile:** Reject wrong password, replayed OTP and another mount's username.

**Lifecycle:** Rotate password and disable/remount while existing sessions and children are active.

**Remaining scope:** Password hashing, lockout and audit require exact profiles.

Existing bounded profiles: `qa/openbao-acceptance/acceptance.py`.

### HB-SURFACE-AUTH-APPROLE

Implementation: `PARTIAL_RUNTIME`. Original work packages: `H16-WP03`, `H16-WP10`.
API families: `auth/{mount}/role/*`; `auth/{mount}/login`.
Runtime source: `crates/heptabao-server/src/auth.rs`.
Separate contracts: none claimed.
Guides: `docs/auth/HEPTABAO_SINGLE_NODE_AUTH.md`.

**Positive:** Configure RoleID, custom/generated SecretID, wrapping, TTL and CIDR restrictions.

**Hostile:** Reject cross-role SecretID, exhausted uses and client-controlled identity fields.

**Lifecycle:** Race SecretID consumption and revoke issuer or auth mount through restart.

**Remaining scope:** Role ID, secret ID, wrapping, CIDR and single-use behavior.

Existing bounded profiles: `qa/openbao-acceptance/acceptance.py`.

### HB-SURFACE-AUTH-CERT

Implementation: `PARTIAL_RUNTIME`. Original work packages: `H16-WP04`, `H16-WP10`.
API families: `auth/{mount}/certs/*`; `auth/{mount}/login`.
Runtime source: `crates/heptabao-server/src/auth.rs`, `crates/heptabao-server/src/http.rs`.
Separate contracts: none claimed.
Guides: `docs/compatibility/HEPTABAO_REPLACEMENT_EXECUTION.md`.

**Positive:** Authenticate real verified client chains and bind allowed certificate identities.

**Hostile:** Reject revoked leaf, bad EKU, unrelated CA and untrusted forwarded certificates.

**Lifecycle:** Refresh CRL/OCSP and rotate CA without resurrecting revoked sessions.

**Remaining scope:** Chain, CRL, OCSP and trusted-forwarded-certificate behavior.

Existing bounded profiles: `qa/openbao-acceptance/cert_auth_live.py`.

### HB-SURFACE-AUTH-JWT-OIDC

Implementation: `PARTIAL_RUNTIME`. Original work packages: `H16-WP05`, `H16-WP10`.
API families: `auth/{mount}/config`; `auth/{mount}/role/*`; `auth/{mount}/login`; `auth/{mount}/oidc/*`.
Runtime source: `crates/heptabao-server/src/auth_remote.rs`, `crates/heptabao-server/src/federated_auth.rs`, `crates/heptabao-server/src/outbound.rs`, `crates/heptabao-server/src/auth_oidc.rs`, `crates/heptabao-server/src/service_online_auth.rs`.
Separate contracts: none claimed.
Guides: `docs/auth/HEPTABAO_REMOTE_JWT_KEYS.md`, `docs/auth/HEPTABAO_ONLINE_AUTHENTICATION.md`.

**Positive:** Verify static/remote keys and complete browser authorization-code callback flow.

**Hostile:** Reject algorithm confusion, bad issuer/audience, nonce/state/PKCE and unapproved egress.

**Lifecycle:** Rotate JWKS, expire browser state and recover token issuance after response loss.

**Remaining scope:** Full jwt/oidc mount aliases and fields, arbitrary scopes/claim mappings/CEL, UserInfo/refresh/public clients, browser rendering/consent, external MFA, independent provider and production qualification.

Existing bounded profiles: `qa/openbao-acceptance/remote_jwks_compare.py`, `qa/openbao-acceptance/oidc_code_live.py`, `qa/openbao-acceptance/online_auth_ha.py`.

### HB-SURFACE-AUTH-KUBERNETES

Implementation: `PARTIAL_RUNTIME`. Original work packages: `H16-WP06`, `H16-WP10`.
API families: `auth/{mount}/config`; `auth/{mount}/role/*`; `auth/{mount}/login`.
Runtime source: `crates/heptabao-server/src/auth_kubernetes.rs`, `crates/heptabao-server/src/service_online_auth.rs`, `crates/heptabao-server/src/outbound.rs`.
Separate contracts: none claimed.
Guides: `docs/auth/HEPTABAO_ONLINE_AUTHENTICATION.md`.

**Positive:** Use real TokenReview and service-account namespace/name/audience binding.

**Hostile:** Reject forged JWT, untrusted API CA and TokenReview identity mismatch.

**Lifecycle:** Rotate reviewer credentials and service-account tokens across API outage and restart.

**Remaining scope:** The actual pinned KIND API/etcd/RBAC fixture must execute on this exact source; no prior protocol pass is inherited. Remaining distribution coverage, TTL/renewal/alias configuration compatibility, external MFA and independent acceptance remain open.

Existing bounded profiles: `qa/openbao-acceptance/kubernetes_online.py`, `qa/openbao-acceptance/online_auth_ha.py`, `qa/openbao-acceptance/kubernetes_cluster_live.py`.

### HB-SURFACE-AUTH-LDAP

Implementation: `PARTIAL_RUNTIME`. Original work packages: `H16-WP07`, `H16-WP10`.
API families: `auth/{mount}/config`; `auth/{mount}/users/*`; `auth/{mount}/groups/*`; `auth/{mount}/login/*`.
Runtime source: `crates/heptabao-server/src/auth.rs`, `crates/heptabao-server/src/outbound.rs`, `crates/heptabao-server/src/service_online_auth.rs`.
Separate contracts: none claimed.
Guides: `docs/auth/HEPTABAO_SINGLE_NODE_AUTH.md`.

**Positive:** Bind/search real directory and map only authorized user/group policies.

**Hostile:** Reject LDAP-filter injection, empty-password bind and invalid TLS identity.

**Lifecycle:** Rotate bind password and reconcile live external-group membership changes.

**Remaining scope:** Real LDAPS user bind, bounded live subtree group-membership search, local group-to-policy mapping, membership revocation on the next login, restart/outage behavior and actual OpenLDAP distribution execution are implemented. Privileged bind-account search, nested groups, arbitrary filters, StartTLS/SASL/referrals, full OpenBao field/error parity, HA/multi-host provider faults and independent admission remain open.

Existing bounded profiles: `qa/openbao-acceptance/ldap_bounded.py`, `qa/openbao-acceptance/ldap_openldap_live.py`.

### HB-SURFACE-AUTH-RADIUS

Implementation: `NOT_IMPLEMENTED`. Original work packages: `H16-WP08`, `H16-WP10`.
API families: `auth/{mount}/config`; `auth/{mount}/users/*`; `auth/{mount}/login/*`.
Runtime source: none claimed.
Separate contracts: none claimed.
Guides: `docs/compatibility/HEPTABAO_REPLACEMENT_EXECUTION.md`.

**Positive:** Authenticate against real RADIUS with response authenticator validation.

**Hostile:** Reject replay, bad shared-secret response and response/request mismatches.

**Lifecycle:** Handle packet loss and credential rotation without granting on timeout.

**Remaining scope:** Shared-secret handling, replay, timeout and fail-closed behavior.

Existing bounded profiles: none bound yet; executable fixtures must be implemented.

### HB-SURFACE-AUTH-KERBEROS

Implementation: `NOT_IMPLEMENTED`. Original work packages: `H16-WP09`, `H16-WP10`.
API families: `auth/{mount}/config`; `auth/{mount}/login`.
Runtime source: none claimed.
Separate contracts: none claimed.
Guides: `docs/compatibility/HEPTABAO_REPLACEMENT_EXECUTION.md`.

**Positive:** Validate real SPNEGO/PAC and constrained realm/service identity.

**Hostile:** Reject replayed tickets, untrusted realm and excessive clock skew.

**Lifecycle:** Rotate keytab and recover replay state across server restart.

**Remaining scope:** SPNEGO/PAC, realm and clock behavior; may be feature-gated but remains v2.6.2 target.

Existing bounded profiles: none bound yet; executable fixtures must be implemented.

### HB-SURFACE-SECRET-KV

Implementation: `PARTIAL_RUNTIME`. Original work packages: `H17-WP02`, `H17-WP03`, `H17-WP04`, `H17-WP05`, `H17-WP06`, `H17-WP11`.
API families: `{mount}/data/*`; `{mount}/metadata/*`; `{mount}/delete/*`; `{mount}/undelete/*`; `{mount}/destroy/*`; `{mount}/subkeys/*`.
Runtime source: `crates/heptabao-server/src/engines/kv.rs`.
Separate contracts: none claimed.
Guides: `docs/engines/HEPTABAO_SINGLE_NODE_ENGINES.md`.

**Positive:** Cover KV1/KV2 history, CAS, patch, metadata, shallow list and pagination.

**Hostile:** Reject partial multi-version mutation and namespace/path ambiguity.

**Lifecycle:** Preserve tombstones, pruning and retention across crash, upgrade and migration.

**Remaining scope:** CAS, versions, metadata, delete/undelete/destroy, list/scan and pagination.

Existing bounded profiles: `qa/openbao-acceptance/acceptance.py`.

### HB-SURFACE-SECRET-TRANSIT

Implementation: `PARTIAL_RUNTIME`. Original work packages: `H17-WP07`, `H17-WP08`, `H17-WP09`.
API families: `{mount}/keys/*`; `{mount}/encrypt/*`; `{mount}/decrypt/*`; `{mount}/rewrap/*`; `{mount}/sign/*`; `{mount}/verify/*`.
Runtime source: `crates/heptabao-server/src/engines/transit.rs`.
Separate contracts: none claimed.
Guides: `docs/engines/HEPTABAO_SINGLE_NODE_ENGINES.md`.

**Positive:** Cover algorithms, derivation, BYOK, context, convergent mode and imported old ciphertext.

**Hostile:** Reject cross-domain key misuse, wrong AAD and unsupported options without silent fallback.

**Lifecycle:** Rewrap persisted OpenBao ciphertext under an explicit verified domain-conversion protocol.

**Remaining scope:** Key lifecycle, encrypt/decrypt/rewrap/sign/verify/HMAC/hash/random.

Existing bounded profiles: `qa/openbao-acceptance/acceptance.py`.

### HB-SURFACE-SECRET-TOTP

Implementation: `PARTIAL_RUNTIME`. Original work packages: `H17-WP10`.
API families: `{mount}/keys/*`; `{mount}/code/*`.
Runtime source: `crates/heptabao-server/src/engines/totp.rs`.
Separate contracts: none claimed.
Guides: `docs/engines/HEPTABAO_SINGLE_NODE_ENGINES.md`.

**Positive:** Use all declared import/algorithm/digits/period and generated-key profiles.

**Hostile:** Reject repeat code, invalid Base32, brute-force budget bypass and clock rollback.

**Lifecycle:** Persist accepted-code and rate-limit state through remount and restart.

**Remaining scope:** Import, generate, code, validate, period and expiry.

Existing bounded profiles: `qa/openbao-acceptance/acceptance.py`.

### HB-SURFACE-SECRET-PKI

Implementation: `PARTIAL_RUNTIME`. Original work packages: `H18-WP01`, `H18-WP02`, `H18-WP03`, `H18-WP04`, `H18-WP05`.
API families: `{mount}/root/*`; `{mount}/intermediate/*`; `{mount}/issuer/*`; `{mount}/roles/*`; `{mount}/issue/*`; `{mount}/revoke`; `{mount}/crl`; `{mount}/ocsp`; `{mount}/acme/*`.
Runtime source: `crates/heptabao-server/src/engines/pki.rs`.
Separate contracts: none claimed.
Guides: `docs/engines/HEPTABAO_SINGLE_NODE_ENGINES.md`.

**Positive:** Cover roots/intermediates/import/issuers, constrained issuance, CRL/OCSP and ACME.

**Hostile:** Reject domain/TTL/key-usage escape, invalid CSR and unauthorized issuer selection.

**Lifecycle:** Rotate issuer and preserve issued certificates/revocations and tidy across migration.

**Remaining scope:** Roots, intermediates, issuers, roles, ACME, CRL, OCSP and tidy.

Existing bounded profiles: `qa/openbao-acceptance/pki_live.py`.

### HB-SURFACE-SECRET-PKIEXT

Implementation: `NOT_IMPLEMENTED`. Original work packages: `H18-WP06`.
API families: `{mount}/(versioned pkiext protocol inventory)`.
Runtime source: none claimed.
Separate contracts: none claimed.
Guides: `docs/compatibility/HEPTABAO_REPLACEMENT_EXECUTION.md`.

**Positive:** Define the separate extension protocol and prove a positive public operation.

**Hostile:** Reject unsupported extension fields and cross-issuer credential access.

**Lifecycle:** Version extension state and test interrupted conversion without modifying source.

**Remaining scope:** Separate compatibility and protocol inventory required.

Existing bounded profiles: none bound yet; executable fixtures must be implemented.

### HB-SURFACE-SECRET-SSH

Implementation: `PARTIAL_RUNTIME`. Original work packages: `H18-WP07`, `H18-WP08`, `H18-WP09`.
API families: `{mount}/roles/*`; `{mount}/creds/*`; `{mount}/verify`; `{mount}/sign/*`; `{mount}/config/ca`.
Runtime source: `crates/heptabao-server/src/engines/ssh.rs`.
Separate contracts: none claimed.
Guides: `docs/engines/HEPTABAO_SSH_OTP.md`.

**Positive:** Issue OTP and real OpenSSH signed certificates with role/user/domain/TTL constraints.

**Hostile:** Reject wrong host, CIDR exclusion and unauthorized certificate principals.

**Lifecycle:** Revoke OTP once across failover and rehearse real sshd/PAM and CA rotation.

**Remaining scope:** Signed certificates, OTP, user/domain constraints and TTL.

Existing bounded profiles: `qa/openbao-acceptance/ssh_otp_live.py`, `qa/openbao-acceptance/ssh_otp_ha.py`.

### HB-SURFACE-SECRET-DATABASE

Implementation: `PARTIAL_RUNTIME`. Original work packages: `H19-WP01`, `H19-WP02`, `H19-WP03`, `H19-WP04`.
API families: `{mount}/config/*`; `{mount}/roles/*`; `{mount}/static-roles/*`; `{mount}/creds/*`; `{mount}/rotate-root/*`.
Runtime source: `crates/heptabao-server/src/service_database.rs`, `crates/heptabao-server/src/postgres_wire.rs`.
Separate contracts: none claimed.
Guides: `docs/engines/HEPTABAO_POSTGRESQL_PROVIDER.md`.

**Positive:** Compose full static/dynamic roles, provider statements and root/static rotation.

**Hostile:** Reject unapproved provider configuration and ownership-changing SQL output.

**Lifecycle:** Reconcile timeout after actual SQL effect, expiry, rollback and lease revocation.

**Remaining scope:** Static/dynamic roles, root rotation, statement templates, renew/revoke and rollback.

Existing bounded profiles: `qa/openbao-acceptance/postgres_live.py`.

### HB-SURFACE-SECRET-KUBERNETES

Implementation: `PARTIAL_RUNTIME`. Original work packages: `H19-WP10`, `H19-WP13`.
API families: `{mount}/config`; `{mount}/roles/*`; `{mount}/creds/*`.
Runtime source: `crates/heptabao-server/src/engines/kubernetes.rs`, `crates/heptabao-server/src/service_kubernetes_secrets.rs`.
Separate contracts: none claimed.
Guides: `docs/modules/heptabao-server.md`, `docs/compatibility/HEPTABAO_REPLACEMENT_EXECUTION.md`.

**Positive:** Create actual service-account/token credentials through constrained Kubernetes API.

**Hostile:** Reject service-account/namespace/role escalation and untrusted API server.

**Lifecycle:** Revoke actual API resources after issuer expiry and reconcile lost creation reply.

**Remaining scope:** A real TokenRequest against the pinned disposable Kubernetes cluster is implemented with durable pre-entry intent, exact namespace/service-account/audience binding, response claim readback, restart persistence and fail-closed unknown outcome. Generated ServiceAccount lifecycle, broader OpenBao role/config fields, provider-side revocation promises, HA/multi-host provider faults and independent admission remain open.

Existing bounded profiles: `qa/openbao-acceptance/kubernetes_cluster_live.py`.

### HB-SURFACE-SECRET-OPENLDAP

Implementation: `NOT_IMPLEMENTED`. Original work packages: `H19-WP11`, `H19-WP13`.
API families: `{mount}/config`; `{mount}/role/*`; `{mount}/creds/*`.
Runtime source: none claimed.
Separate contracts: none claimed.
Guides: `docs/compatibility/HEPTABAO_REPLACEMENT_EXECUTION.md`.

**Positive:** Create actual constrained directory identities and group membership.

**Hostile:** Reject DN/filter injection and unauthorized subtree or group changes.

**Lifecycle:** Reconcile partial directory writes, rotate credentials and prove actual revoke.

**Remaining scope:** Dynamic LDAP credentials, expiry and revoke behavior.

Existing bounded profiles: none bound yet; executable fixtures must be implemented.

### HB-SURFACE-SECRET-RABBITMQ

Implementation: `NOT_IMPLEMENTED`. Original work packages: `H19-WP12`, `H19-WP13`.
API families: `{mount}/config/*`; `{mount}/roles/*`; `{mount}/creds/*`.
Runtime source: none claimed.
Separate contracts: none claimed.
Guides: `docs/compatibility/HEPTABAO_REPLACEMENT_EXECUTION.md`.

**Positive:** Create real broker users with exact vhost permissions and lease metadata.

**Hostile:** Reject admin tag escalation, bad TLS and foreign user ownership.

**Lifecycle:** Remove issued users/permissions after expiry, restart and lost provider reply.

**Remaining scope:** Users, vhosts, permissions, lease and revocation lifecycle.

Existing bounded profiles: none bound yet; executable fixtures must be implemented.

### HB-SURFACE-DB-POSTGRESQL

Implementation: `PARTIAL_RUNTIME`. Original work packages: `H19-WP05`, `H19-WP13`.
API families: `database/config/*`; `database/roles/*`; `database/static-roles/*`; `database/creds/*`.
Runtime source: `crates/heptabao-server/src/service_database.rs`, `crates/heptabao-server/src/postgres_wire.rs`.
Separate contracts: none claimed.
Guides: `docs/engines/HEPTABAO_POSTGRESQL_PROVIDER.md`.

**Positive:** Support documented SQL statements and real static/dynamic/root rotation beyond provider_role.

**Hostile:** Deny SQL/template injection and foreign OID ownership while preserving supported statements.

**Lifecycle:** Reconcile create/renew/revoke/rollback and active sessions against real PostgreSQL.

**Remaining scope:** Real version/TLS/root-rotation/static/dynamic/renew/revoke matrix required.

Existing bounded profiles: `qa/openbao-acceptance/postgres_live.py`.

### HB-SURFACE-DB-MYSQL

Implementation: `NOT_IMPLEMENTED`. Original work packages: `H19-WP06`, `H19-WP13`.
API families: `database/config/*`; `database/roles/*`; `database/static-roles/*`.
Runtime source: none claimed.
Separate contracts: none claimed.
Guides: `docs/compatibility/HEPTABAO_REPLACEMENT_EXECUTION.md`.

**Positive:** Run real MySQL/MariaDB static/dynamic user and root-rotation profiles.

**Hostile:** Reject wrong server identity and privilege-escalating template substitution.

**Lifecycle:** Recover DDL partial effects and prove host/user revocation after restart.

**Remaining scope:** Real service and statement/rollback matrix required.

Existing bounded profiles: none bound yet; executable fixtures must be implemented.

### HB-SURFACE-DB-CASSANDRA

Implementation: `NOT_IMPLEMENTED`. Original work packages: `H19-WP07`, `H19-WP13`.
API families: `database/config/*`; `database/roles/*`; `database/creds/*`.
Runtime source: none claimed.
Separate contracts: none claimed.
Guides: `docs/compatibility/HEPTABAO_REPLACEMENT_EXECUTION.md`.

**Positive:** Run actual role creation, renewal and revocation on declared Cassandra versions.

**Hostile:** Reject unauthorized roles and unverified TLS.

**Lifecycle:** Reconcile partial cluster visibility and revoke under network partition.

**Remaining scope:** Real service, network-partition and revoke matrix required.

Existing bounded profiles: none bound yet; executable fixtures must be implemented.

### HB-SURFACE-DB-INFLUXDB

Implementation: `NOT_IMPLEMENTED`. Original work packages: `H19-WP08`, `H19-WP13`.
API families: `database/config/*`; `database/roles/*`; `database/creds/*`.
Runtime source: none claimed.
Separate contracts: none claimed.
Guides: `docs/compatibility/HEPTABAO_REPLACEMENT_EXECUTION.md`.

**Positive:** Issue real bounded database user/token credentials for declared versions.

**Hostile:** Reject unbound organization/database and excessive permissions.

**Lifecycle:** Revoke issued credentials and reconcile lost responses without duplicate users.

**Remaining scope:** Real service and token lifecycle matrix required.

Existing bounded profiles: none bound yet; executable fixtures must be implemented.

### HB-SURFACE-DB-VALKEY

Implementation: `NOT_IMPLEMENTED`. Original work packages: `H19-WP09`, `H19-WP13`.
API families: `database/config/*`; `database/roles/*`; `database/static-roles/*`.
Runtime source: none claimed.
Separate contracts: none claimed.
Guides: `docs/compatibility/HEPTABAO_REPLACEMENT_EXECUTION.md`.

**Positive:** Create real Valkey ACL users and rotate static/root credentials over verified TLS.

**Hostile:** Reject key/channel glob privilege escape and wrong cluster identity.

**Lifecycle:** Persist ACL revocation and credentials through reconnect and provider restart.

**Remaining scope:** Real version, ACL, TLS, rotate and revoke matrix required.

Existing bounded profiles: none bound yet; executable fixtures must be implemented.

### HB-SURFACE-AUDIT-FILE

Implementation: `PARTIAL_RUNTIME`. Original work packages: `H12-WP05`, `H12-WP10`, `H12-WP11`.
API families: `sys/audit/* (file)`.
Runtime source: `crates/heptabao-server/src/audit_rotation.rs`.
Separate contracts: none claimed.
Guides: `docs/modules/heptabao-server.md`.

**Positive:** Configure real file audit devices with exact field HMAC/redaction semantics.

**Hostile:** Reject unsafe file ownership, symlinks and secret-bearing diagnostic output.

**Lifecycle:** Exercise rotation, partial writes, disk full and retained chain verification.

**Remaining scope:** Real sys/audit list/read/idempotent file enable and fail-closed disable are now exercised against the pinned OpenBao 2.6.2 oracle. Permission/rotation/disk-full/partial-line crash behavior, dynamic option parity and independent admission remain open.

Existing bounded profiles: `qa/openbao-acceptance/audit_file_live.py`.

### HB-SURFACE-AUDIT-HTTP

Implementation: `PARTIAL_RUNTIME`. Original work packages: `H12-WP06`, `H12-WP10`, `H12-WP11`.
API families: `sys/audit/* (http)`.
Runtime source: `crates/heptabao-server/src/service.rs`, `crates/heptabao-server/src/outbound.rs`, `crates/heptabao-server/src/http.rs`.
Separate contracts: none claimed.
Guides: `docs/compatibility/HEPTABAO_REPLACEMENT_EXECUTION.md`.

**Positive:** Deliver actual authenticated audit requests to a host-enrolled HTTPS collector.

**Hostile:** Reject redirects, unapproved destinations and invalid TLS.

**Lifecycle:** Reconcile timeout/collector outage without unaudited effect or unbounded queue.

**Remaining scope:** Process-configured host-enrolled HTTPS delivery, local-file-first durability, redirect denial, bounded timeout, outage fail-closed and restart recovery are executable; dynamic sys/audit enrollment/options, batching/backpressure parity, official differential coverage and independent admission remain open.

Existing bounded profiles: `qa/openbao-acceptance/audit_http_live.py`.

### HB-SURFACE-AUDIT-SOCKET

Implementation: `PARTIAL_RUNTIME`. Original work packages: `H12-WP07`, `H12-WP10`, `H12-WP11`.
API families: `sys/audit/* (socket)`.
Runtime source: `crates/heptabao-server/src/service.rs`, `crates/heptabao-server/src/http.rs`.
Separate contracts: none claimed.
Guides: `docs/compatibility/HEPTABAO_REPLACEMENT_EXECUTION.md`.

**Positive:** Deliver framed audit events to declared socket modes.

**Hostile:** Reject unexpected peers and partial-frame acceptance.

**Lifecycle:** Bound backpressure, reconnect and shutdown while preserving audit-before-effect.

**Remaining scope:** Deployment-owned bounded TCP socket delivery is executable alongside the mandatory authenticated file device, with API rebinding denied, write deadlines bounded and nonblocking failures counted. UDP/Unix modes, API-created devices, complete OpenBao formatting/options, multi-node collector qualification and independent admission remain open.

Existing bounded profiles: `qa/openbao-acceptance/audit_socket_live.py`.

### HB-SURFACE-AUDIT-SYSLOG

Implementation: `PARTIAL_RUNTIME`. Original work packages: `H12-WP08`, `H12-WP10`, `H12-WP11`.
API families: `sys/audit/* (syslog)`.
Runtime source: `crates/heptabao-server/src/service.rs`, `crates/heptabao-server/src/http.rs`.
Separate contracts: none claimed.
Guides: `docs/modules/heptabao-server.md`, `docs/compatibility/HEPTABAO_REPLACEMENT_EXECUTION.md`.

**Positive:** Deliver real facility/tag events through documented local/network modes.

**Hostile:** Reject illegal facility, log injection and undeclared transport.

**Lifecycle:** Handle collector outage and rotation with explicit admission policy.

**Remaining scope:** A process-configured local Unix datagram syslog sink is implemented with bounded facility/tag framing, API rebinding denial, mandatory authenticated-file-first durability, observable delivery failure and recovery. Dynamic sys/audit enrollment, network transports, full OpenBao formatting/options, rotation semantics and multi-host collector qualification remain open.

Existing bounded profiles: `qa/openbao-acceptance/audit_syslog_live.py`.

### HB-SURFACE-STORAGE-POSTGRESQL

Implementation: `CONTRACT_ONLY`. Original work packages: `H04-WP04`, `H04-WP05`, `H04-WP06`, `H04-WP07`, `H04-WP08`, `H04-WP09`.
API families: `storage configuration`; `physical CRUD/list/transaction`.
Runtime source: none claimed.
Separate contracts: `crates/heptabao-storage-api/src/lib.rs`.
Guides: `docs/modules/heptabao-storage-api.md`.

**Positive:** Persist actual encrypted physical records with transactions, locks and paginated lists.

**Hostile:** Reject stale writer, torn record and foreign namespace access.

**Lifecycle:** Prove crash durability, lock recovery, schema upgrade and storage migration.

**Remaining scope:** Transactions, locks, consistency, migration and durability.

Existing bounded profiles: none bound yet; executable fixtures must be implemented.

### HB-SURFACE-STORAGE-RAFT

Implementation: `PARTIAL_RUNTIME`. Original work packages: `H20-WP01`, `H20-WP02`, `H20-WP03`, `H20-WP04`, `H20-WP05`, `H20-WP06`, `H20-WP07`, `H20-WP08`, `H20-WP09`, `H20-WP10`, `H20-WP11`, `H20-WP12`.
API families: `sys/storage/raft/*`; `native consensus transport`.
Runtime source: `crates/heptabao-server/src/ha.rs`, `crates/heptabao-server/src/ha_state.rs`.
Separate contracts: none claimed.
Guides: `docs/operations/HEPTABAO_RAFT_ADMINISTRATION.md`.

**Positive:** Persist logs/FSM, chunked snapshots and voter/nonvoter membership on real nodes.

**Hostile:** Reject stale term, corrupt snapshot and minority writes/read authority.

**Lifecycle:** Test multi-host crash/disk/power loss, long histories and mixed-version upgrade.

**Remaining scope:** FSM, log, snapshot, chunking, membership, non-voter and autopilot.

Existing bounded profiles: `qa/openbao-acceptance/ha_destructive.py`, `qa/openbao-acceptance/raft_membership_live.py`.

### HB-SURFACE-PLUGIN-AUTH

Implementation: `PARTIAL_RUNTIME`. Original work packages: `H13-WP01`, `H13-WP02`, `H13-WP03`, `H13-WP04`, `H13-WP09`.
API families: `sys/plugins/catalog/*`; `sys/auth/*`.
Runtime source: `crates/heptabao-server/src/service_plugin.rs`, `crates/heptabao-server/src/auth.rs`.
Separate contracts: `crates/heptabao-plugin-host/src/lib.rs`.
Guides: `docs/modules/heptabao-server.md`, `docs/modules/heptabao-plugin-host.md`.

**Positive:** Load real compatible external auth plugin and validate its token result contract.

**Hostile:** Reject checksum drift, undeclared capabilities and sandbox escapes.

**Lifecycle:** Handle plugin restart, deadline and reload without duplicated token issuance.

**Remaining scope:** Checksum-bound sandboxed authentication plugins are executable through the real Service with server-owned token policy/TTL authority, digest fencing, restart persistence and mount-disable revocation. OpenBao Go plugin RPC compatibility, plugin reload/deadline parity and independently qualified sandbox containment remain open.

Existing bounded profiles: `qa/openbao-acceptance/plugin_auth_live.py`.

### HB-SURFACE-PLUGIN-SECRET

Implementation: `PARTIAL_RUNTIME`. Original work packages: `H13-WP01`, `H13-WP02`, `H13-WP03`, `H13-WP04`, `H13-WP10`.
API families: `sys/plugins/catalog/*`; `sys/mounts/*`.
Runtime source: `crates/heptabao-server/src/service_plugin.rs`.
Separate contracts: `crates/heptabao-plugin-host/src/lib.rs`.
Guides: `docs/modules/heptabao-server.md`, `docs/modules/heptabao-plugin-host.md`.

**Positive:** Load real external secret plugin and bind lease/effect/rollback callbacks.

**Hostile:** Reject secret output before durable commit and cross-mount capabilities.

**Lifecycle:** Reconcile process death after external effect and preserve lease ownership.

**Remaining scope:** Checksum-bound sandboxed read-only secret plugins are executable through the real Service. Write/issue/renew/revoke effects, dynamic lease ownership, OpenBao plugin RPC compatibility and independently qualified sandbox containment remain open.

Existing bounded profiles: `qa/openbao-acceptance/plugin_secret_live.py`.

### HB-SURFACE-PLUGIN-DATABASE

Implementation: `CONTRACT_ONLY`. Original work packages: `H13-WP01`, `H13-WP02`, `H13-WP03`, `H13-WP04`, `H13-WP11`.
API families: `sys/plugins/catalog/database/*`; `database/config/*`.
Runtime source: none claimed.
Separate contracts: `crates/heptabao-plugin-host/src/lib.rs`.
Guides: `docs/modules/heptabao-plugin-host.md`.

**Positive:** Load actual external database plugin and drive static/dynamic/root lifecycle.

**Hostile:** Reject interface/version mismatch, changed executable and foreign credential ownership.

**Lifecycle:** Restart plugin across uncertain SQL effect and reconcile exactly one lease.

**Remaining scope:** Connection lifecycle, static/dynamic users and root rotation.

Existing bounded profiles: none bound yet; executable fixtures must be implemented.

### HB-SURFACE-PLUGIN-KMS

Implementation: `CONTRACT_ONLY`. Original work packages: `H13-WP01`, `H13-WP02`, `H13-WP03`, `H13-WP04`, `H13-WP12`.
API families: `seal configuration`; `KMS plugin lifecycle`.
Runtime source: none claimed.
Separate contracts: `crates/heptabao-kms-contracts/src/lib.rs`.
Guides: `docs/modules/heptabao-kms-contracts.md`.

**Positive:** Auto-unseal with actual provider and bound key identity/version/context.

**Hostile:** Reject wrong key, disabled version and invented custody evidence.

**Lifecycle:** Exercise provider outage, key rotation and disaster recovery with isolated custody.

**Remaining scope:** Key identity, version, outage and recovery behavior.

Existing bounded profiles: none bound yet; executable fixtures must be implemented.

### HB-SURFACE-CLUSTER-MTLS

Implementation: `PARTIAL_RUNTIME`. Original work packages: `H21-WP01`, `H21-WP02`, `H21-WP03`.
API families: `cluster listener`; `join handshake`.
Runtime source: `crates/heptabao-server/src/ha.rs`.
Separate contracts: none claimed.
Guides: `docs/modules/heptabao-ha-service.md`.

**Positive:** Authenticate node and cluster identity and enroll through the documented challenge.

**Hostile:** Reject unknown node, wrong certificate pin, replay and cross-cluster frames.

**Lifecycle:** Rotate peer certificates and recover admission state across restart.

**Remaining scope:** Cluster ID, node ID, cert rotation, join challenge and replay.

Existing bounded profiles: `qa/openbao-acceptance/ha_destructive.py`.

### HB-SURFACE-CLUSTER-FORWARDING

Implementation: `PARTIAL_RUNTIME`. Original work packages: `H21-WP04`, `H21-WP05`, `H21-WP09`.
API families: `standby /v1/*`; `leader forwarding`.
Runtime source: `crates/heptabao-server/src/ha_forward.rs`.
Separate contracts: none claimed.
Guides: `docs/modules/heptabao-server.md`.

**Positive:** Preserve namespace, token, wrapping and response semantics through real forwarding.

**Hostile:** Reject wrong origin, hop recursion and leaked bearer on redirect.

**Lifecycle:** Lose leader reply and prove no blind mutation retry or double response release.

**Remaining scope:** Token/wrap/namespace/context preservation and origin protection.

Existing bounded profiles: `qa/openbao-acceptance/ha_destructive.py`.

### HB-SURFACE-CLUSTER-READ-STANDBY

Implementation: `PARTIAL_RUNTIME`. Original work packages: `H21-WP06`, `H21-WP07`.
API families: `standby reads`; `ReadIndex`.
Runtime source: `crates/heptabao-server/src/ha.rs`, `crates/heptabao-server/src/service.rs`.
Separate contracts: none claimed.
Guides: `docs/modules/heptabao-server.md`.

**Positive:** Read committed state under declared freshness and non-mutating-read policy.

**Hostile:** Reject stale minority success and treating dynamic-credential GET as a pure read.

**Lifecycle:** Track acknowledged values through partitions, follower catch-up and leader restart.

**Remaining scope:** HTTP GET is not automatically safe; lease-issuing reads remain active-only.

Existing bounded profiles: `qa/openbao-acceptance/ha_network_partition.py`.

### HB-SURFACE-CLUSTER-STEPDOWN

Implementation: `PARTIAL_RUNTIME`. Original work packages: `H21-WP08`, `H21-WP10`.
API families: `sys/step-down`; `sys/leader`.
Runtime source: `crates/heptabao-server/src/ha.rs`, `crates/heptabao-server/src/service.rs`.
Separate contracts: none claimed.
Guides: `docs/modules/heptabao-server.md`.

**Positive:** Transfer leadership after explicit authorization with exact public status.

**Hostile:** Reject non-sudo caller and isolate old leader from new effect authority.

**Lifecycle:** Prove old writer stops before new writer enters under repeated transfer and partition.

**Remaining scope:** Old owner effects must stop before a new owner starts.

Existing bounded profiles: `qa/openbao-acceptance/ha_step_down.py`.

### HB-SURFACE-CLUSTER-AUTOPILOT

Implementation: `PARTIAL_RUNTIME`. Original work packages: `H20-WP10`, `H21-WP11`.
API families: `sys/storage/raft/autopilot/*`.
Runtime source: `crates/heptabao-server/src/service_raft_admin.rs`.
Separate contracts: none claimed.
Guides: `docs/operations/HEPTABAO_RAFT_ADMINISTRATION.md`.

**Positive:** Use actual contact/replication history for stabilization, promotion and cleanup.

**Hostile:** Reject invented health, last-voter deletion and config authority escalation.

**Lifecycle:** Persist policy and reset stabilization after leadership/gap while honoring cleanup grace.

**Remaining scope:** Health, promotion and membership decisions require deterministic evidence.

Existing bounded profiles: `qa/openbao-acceptance/raft_membership_live.py`.

### HB-SURFACE-EDGE-HTTP-TLS

Implementation: `PARTIAL_RUNTIME`. Original work packages: `H22-WP01`, `H22-WP02`, `H22-WP11`.
API families: `TLS listener`; `/v1/*`; `CORS`.
Runtime source: `crates/heptabao-server/src/http.rs`.
Separate contracts: none claimed.
Guides: `docs/modules/heptabao-server.md`.

**Positive:** Serve declared TLS/HTTP versions, Host, forwarding and CORS behavior.

**Hostile:** Reject smuggling, duplicate framing, oversized input and untrusted forwarded certificate.

**Lifecycle:** Bound slow peers, reload certificates and cancel workers without secret leakage.

**Remaining scope:** Smuggling, limits, CORS, Host, forwarded certificate, redirect and HTTP/2.

Existing bounded profiles: none bound yet; executable fixtures must be implemented.

### HB-SURFACE-CLI-ROOT

Implementation: `PARTIAL_RUNTIME`. Original work packages: `H22-WP03`, `H22-WP04`, `H22-WP05`.
API families: `bao-compatible command/flag/env surface`.
Runtime source: `clients/python/heptabao/cli.py`, `clients/python/heptabao/oidc_login.py`.
Separate contracts: none claimed.
Guides: `clients/python/README.md`, `docs/auth/HEPTABAO_ONLINE_AUTHENTICATION.md`.

**Positive:** Execute documented command/output/exit-code and environment precedence against real service.

**Hostile:** Reject secret arguments, unsafe output, ambiguous flags and unintended retries.

**Lifecycle:** Handle signal, broken pipe, token refresh and compatible upgrade of invocation profiles.

**Remaining scope:** Command, flag, env, output, exit code and signal inventory incomplete.

Existing bounded profiles: `qa/openbao-acceptance/client_live.py`.

### HB-SURFACE-AGENT

Implementation: `PARTIAL_RUNTIME`. Original work packages: `H22-WP06`, `H22-WP07`.
API families: `agent auto-auth/cache/templates/sinks`.
Runtime source: `clients/python/heptabao/agent.py`.
Separate contracts: none claimed.
Guides: `docs/operations/HEPTABAO_AGENT_PROXY_HELPER.md`.

**Positive:** Run actual supported auto-auth methods, renewal, templates and private sinks.

**Hostile:** Reject stale/foreign sink, template secret leakage and arbitrary egress.

**Lifecycle:** Reauthenticate and invalidate caches under restart, expiry and unknown renewal reply.

**Remaining scope:** Sink permissions, rotation, stale-cache and secret-output controls.

Existing bounded profiles: `qa/openbao-acceptance/agent_proxy_helper_live.py`.

### HB-SURFACE-PROXY

Implementation: `PARTIAL_RUNTIME`. Original work packages: `H22-WP08`.
API families: `local proxy`; `upstream TLS/cache`.
Runtime source: `clients/python/heptabao/proxy.py`.
Separate contracts: none claimed.
Guides: `docs/operations/HEPTABAO_AGENT_PROXY_HELPER.md`.

**Positive:** Forward supported protocols with exact token replacement and cache semantics.

**Hostile:** Reject credential smuggling, wrong namespace, forbidden routes and proxying ambiguous writes twice.

**Lifecycle:** Invalidate cache and credentials on issuer revocation, restart and upstream outage.

**Remaining scope:** Proxy must not bypass server policy/audit or replay ambiguous requests.

Existing bounded profiles: `qa/openbao-acceptance/agent_proxy_helper_live.py`.

### HB-SURFACE-OPENAPI-UI

Implementation: `PARTIAL_RUNTIME`. Original work packages: `H22-WP09`, `H22-WP10`.
API families: `sys/internal/specs/openapi`; `browser UI`.
Runtime source: `crates/heptabao-server/src/service_openapi.rs`.
Separate contracts: none claimed.
Guides: `docs/compatibility/HEPTABAO_REPLACEMENT_EXECUTION.md`.

**Positive:** Generate supported API schema and provide browser flows reflecting actual handlers.

**Hostile:** Reject XSS/CSRF, schema privilege leakage and undocumented feature claims.

**Lifecycle:** Version browser/client state and invalidate authentication correctly after upgrade.

**Remaining scope:** A bounded authenticated OpenAPI 3.0.2 endpoint is executable and restart-stable. Exact policy-filtered schema parity and browser UI implementation, authentication flows, CSRF/XSS controls and accessibility remain open.

Existing bounded profiles: `qa/openbao-acceptance/openapi_live.py`.

### HB-SURFACE-OPERATIONS

Implementation: `PARTIAL_RUNTIME`. Original work packages: `H23-WP01`, `H23-WP02`, `H23-WP03`, `H23-WP04`, `H23-WP05`, `H23-WP06`, `H23-WP07`, `H23-WP08`, `H23-WP09`, `H23-WP10`, `H23-WP11`.
API families: `sys/health`; `sys/metrics`; `quotas`; `diagnose`; `reload`.
Runtime source: `crates/heptabao-server/src/service_capacity.rs`, `crates/heptabao-server/src/audit_rotation.rs`.
Separate contracts: none claimed.
Guides: `docs/operations/HEPTABAO_CAPACITY_AND_GROWTH.md`.

**Positive:** Expose real capacity/telemetry and qualify quotas, lockout and atomic reload.

**Hostile:** Reject secret labels and reset-style recovery that discards replay or tombstones.

**Lifecycle:** Benchmark growing state/long writes and prove compaction, alerting and bounded recovery.

**Remaining scope:** Atomic reload and no-secret observability are critical.

Existing bounded profiles: `qa/openbao-acceptance/capacity_live.py`.

### HB-SURFACE-NAMESPACE-TREE

Implementation: `PARTIAL_RUNTIME`. Original work packages: `H14-WP01`, `H14-WP02`, `H14-WP03`, `H14-WP04`, `H14-WP05`, `H14-WP06`.
API families: `sys/namespaces/*`; `X-Vault-Namespace`.
Runtime source: `crates/heptabao-server/src/service_namespaces.rs`.
Separate contracts: none claimed.
Guides: `docs/modules/heptabao-server.md`.

**Positive:** Create nested namespaces and isolate every state owner with stable namespace identity.

**Hostile:** Reject traversal, sibling access and delegated cross-namespace policy escalation.

**Lifecycle:** Disable/delete/recreate and restore without binding old tokens or leases to a new namespace.

**Remaining scope:** Ordinary hierarchy, metadata merge patch, restart persistence and delete/recreate incarnation fencing are executable; per-namespace seal, delegated administration, complete owner isolation, migration and independent admission remain open.

Existing bounded profiles: `qa/openbao-acceptance/namespace_tree_live.py`.

### HB-SURFACE-NAMESPACE-SEAL

Implementation: `CONTRACT_ONLY`. Original work packages: `H14-WP07`, `H14-WP08`, `H14-WP09`, `H14-WP10`.
API families: `namespace seal/unseal and key lifecycle`.
Runtime source: none claimed.
Separate contracts: `crates/heptabao-namespace/src/lib.rs`.
Guides: `docs/modules/heptabao-namespace.md`.

**Positive:** Seal namespace independently with separate authenticated key custody.

**Hostile:** Reject parent/sibling key use and unauthorized recovery.

**Lifecycle:** Synchronize seal state under HA, key rotation and delete/recreate/restore.

**Remaining scope:** Delete/recreate/restore and standby synchronization require dedicated state models.

Existing bounded profiles: none bound yet; executable fixtures must be implemented.

### HB-SURFACE-PROFILES-WORKFLOWS

Implementation: `NOT_IMPLEMENTED`. Original work packages: `H15-WP01`, `H15-WP02`, `H15-WP03`, `H15-WP04`, `H15-WP05`, `H15-WP06`, `H15-WP10`.
API families: `profiles/workflow configuration and execution`.
Runtime source: none claimed.
Separate contracts: none claimed.
Guides: `docs/compatibility/HEPTABAO_REPLACEMENT_EXECUTION.md`.

**Positive:** Execute declared CEL/template workflows with explicit internal request authority.

**Hostile:** Reject SSRF, unbounded evaluation, secret echo and caller-forged internal operations.

**Lifecycle:** Persist workflow progress and reconcile partial effects without replaying completed steps.

**Remaining scope:** Internal operation construction, SSRF, secret echo and resource limits.

Existing bounded profiles: none bound yet; executable fixtures must be implemented.

### HB-SURFACE-SELF-INIT

Implementation: `PARTIAL_RUNTIME`. Original work packages: `H15-WP07`, `H15-WP08`, `H15-WP09`.
API families: `declarative initialization`; `transient-root lifecycle`.
Runtime source: `crates/heptabao-server/src/service.rs`, `crates/heptabao-server/src/auth.rs`.
Separate contracts: none claimed.
Guides: `docs/compatibility/HEPTABAO_REPLACEMENT_EXECUTION.md`.

**Positive:** Initialize declared configuration using a bounded transient root.

**Hostile:** Reject repeated initialization and retain no ordinary-output root credential.

**Lifecycle:** Revoke transient root unconditionally after interruption and resume idempotently.

**Remaining scope:** Bounded sys/init recovery, declared policy/token application and explicit transient-root revocation are executable; declarative profile parsing, automatic revocation on runner interruption, namespace/mount-aware enrollment, independent custody and external admission remain open.

Existing bounded profiles: `qa/openbao-acceptance/self_init_live.py`.

### HB-SURFACE-MIGRATION-LOGICAL

Implementation: `PARTIAL_RUNTIME`. Original work packages: `H24-WP01`, `H24-WP02`, `H24-WP03`, `H24-WP06`, `H24-WP07`.
API families: `logical export/import and readback tools`.
Runtime source: `qa/openbao-acceptance/migrate_kv2.py`, `qa/openbao-acceptance/migration_preflight.py`.
Separate contracts: none claimed.
Guides: `docs/migration/HEPTABAO_OPENBAO_MIGRATION.md`, `docs/migration/HEPTABAO_MIGRATION_PREFLIGHT.md`.

**Positive:** Inventory and copy every asset class including version/tombstone/auth/key/lease dependencies.

**Hostile:** Reject omitted unsupported assets and false success when only active KV versions copy.

**Lifecycle:** Reconcile interrupted writes and compare exact source-target version/behavior after reopen.

**Remaining scope:** Preferred path; exact source-target version pair required.

Existing bounded profiles: `qa/openbao-acceptance/live_migration_rehearsal.py`, `qa/openbao-acceptance/migration_preflight_live.py`.

### HB-SURFACE-MIGRATION-SNAPSHOT

Implementation: `CONTRACT_ONLY`. Original work packages: `H24-WP04`, `H24-WP05`.
API families: `snapshot inspection/conversion tools`.
Runtime source: none claimed.
Separate contracts: `crates/heptabao-migration/src/lib.rs`.
Guides: `docs/modules/heptabao-migration.md`.

**Positive:** Inspect declared source snapshot and convert through a reviewed typed adapter.

**Hostile:** Reject unknown format, changed seal, corruption and direct raft.db mutation.

**Lifecycle:** Retain original and prove interrupted conversion/restore and anti-resurrection checks.

**Remaining scope:** Direct raft.db mutation is excluded; parser requires separate qualification.

Existing bounded profiles: none bound yet; executable fixtures must be implemented.

### HB-SURFACE-MIGRATION-CUTOVER

Implementation: `PARTIAL_RUNTIME`. Original work packages: `H24-WP08`, `H24-WP09`, `H24-WP10`, `H24-WP11`, `H24-WP12`, `H24-WP13`.
API families: `shadow/freeze/final-delta/cutover/rollback`.
Runtime source: `qa/openbao-acceptance/live_migration_rehearsal.py`.
Separate contracts: `crates/heptabao-migration/src/lib.rs`.
Guides: `docs/migration/HEPTABAO_OPENBAO_MIGRATION.md`, `docs/modules/heptabao-migration.md`.

**Positive:** Verify all assets, freeze source, apply final delta and switch one writer atomically.

**Hostile:** Reject simultaneous writers, incomplete inventory and operator-supplied unchecked success.

**Lifecycle:** Reconcile unknown switch as no-writer and rehearse fenced rollback without resurrection.

**Remaining scope:** A bounded official-OpenBao-to-HeptaBao KV-v2 cutover rehearsal proves process-level single-writer fencing, target rejection of source bearer/wrapping authority, same-root source rollback after target stop, and no resurrection of a pre-cutover revoked token. Complete all-asset final-delta conversion, post-cutover target-write reconciliation, endpoint/DNS/LB switching, production source fencing and independent migration admission remain open.

Existing bounded profiles: `qa/openbao-acceptance/live_migration_rehearsal.py`.

## Hard-problem exits, without scope reduction

Capacity: local persistence now publishes independently serialized authoritative owners under one authenticated V4 manifest, while the active replay ledger and HA logical-state path remain bounded. The capacity endpoint and before-entry journal compaction do not eliminate those remaining limits. The next scalable-storage exit is to carry owner/record deltas through the HA state-machine boundary, keep replay fences across ledger retirement, reject unsafe old-binary fallback, and measure large-state memory, I/O, latency and recovery costs. See `docs/operations/HEPTABAO_CAPACITY_AND_GROWTH.md`.

Transit: retain current domain/AAD protections. An adapter must explicitly bind the source and destination domains, inventory every key/version/ciphertext, decrypt with authorized source ownership, re-encrypt under the destination, and verify readback. Similar `vault:vN:` text is not interoperability.

Database: the fixed provider-role SQL profile is real but does not replace the OpenBao statement/static-role contract. Extend real providers with durable intent and provider-side idempotency/ownership; test DDL, rollback and session revocation on the actual database. A wire model is not that evidence.

Snapshot: preserve original OpenBao bytes; do not mutate raft.db or reset revocation state. Require a separate typed, versioned conversion and exact source/target/seal binding. Native HeptaBao backups do not become OpenBao snapshots by sharing an endpoint.

Migration and Hepta integration: run the inventory preflight before any planned copy, then the bounded copy/readback and source-freeze/single-writer cutover exits separately. Requalify the real Hepta consumer with both exact binaries before updating its external pin. Never advance the pin from repository CI alone.

External security, isolated custody and physical multi-host/disk/power testing require authentic evidence. The existing external-admission verifier owns that decision; this execution map never issues approval.
