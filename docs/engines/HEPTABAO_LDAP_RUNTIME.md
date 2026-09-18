# Bounded external LDAP authentication profile

The current Service admits an `ldap` auth mount with durable configuration at
`auth/:mount/config`, local policy/token mappings at `auth/:mount/users/*`, and
external password authentication at `auth/:mount/login/:name`.

## Runtime boundary

LDAP password verification no longer delegates to the local userpass verifier.
For an admitted login the Service prepares an immutable bind plan while holding
its state writer, releases that writer, performs one LDAPv3 simple bind over the
deployment-enrolled `ldaps://` endpoint, then reacquires the writer and publishes
the token/Identity result only if the mount configuration and local policy mapping
are still unchanged.

The outbound endpoint is pinned before unseal by origin, socket address, TLS server
name and CA. Runtime configuration cannot add DNS discovery, change the enrolled
address/CA, follow referrals, disable TLS verification or retry an ambiguous
network exchange. Plain `ldap://` and StartTLS are rejected by the current
external-login profile.

The configured `user_dn_template` must contain `{{username}}`. User names are
already restricted to the server's canonical bounded name grammar before
substitution. The resulting DN and password are bounded and NUL/control-byte
checked before the provider is entered.

## Local authority mapping

A matching `auth/:mount/users/:name` record remains the bounded administrative
mapping for policies, TTL, use count and optional TOTP. Its stored password
verifier is deliberately ignored for LDAP authentication. A successful external
bind without a current local mapping does not mint a token; deleting the mapping
therefore revokes future login authority even when the external directory still
accepts the password.

This separation lets the external directory own password authentication while the
HeptaBao namespace/mount continues to own authorization and token policy.

## Failure and concurrency semantics

Invalid LDAP credentials return permission denied. Connection, TLS, framing or
provider failures return a bounded service-unavailable result and do not mint a
token. The provider call runs through the same split-phase online-auth machinery
used by Kubernetes/OIDC, so a slow LDAP server does not hold the global Service
writer. Configuration is rechecked after provider observation; a concurrent
remount/reconfiguration prevents publication.

## Explicit remaining scope

This is a real network/TLS LDAP simple-bind profile, but it is not full OpenBao
LDAP parity. The current implementation does **not** provide service-account
search, user/group search filters, nested-group expansion, referrals, StartTLS,
SASL, external group-to-policy discovery, or an independently qualified OpenLDAP/
Active Directory matrix. Those remain open under `HB-SURFACE-AUTH-LDAP`; this
document grants no compatibility or production authority.

Executable acceptance: `qa/openbao-acceptance/ldap_bounded.py`. The fixture
runs a real TLS socket and LDAPv3 BindRequest/BindResponse exchange through the
production outbound path, deliberately uses different local and external
passwords, checks provider-side DN/password observation, restart and revocation,
and keeps `actual_openldap_distribution=false` / `independent_qualification=false`.
