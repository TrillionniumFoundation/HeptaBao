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

## External group synchronization and remaining scope

The current profile now performs one bounded whole-subtree group search on the
same verified LDAPS connection after the authenticating user's successful simple
bind. Configuration supplies one `group_dn`, one exact member attribute and one
group-name attribute. The request is BER encoded rather than assembled as an LDAP
filter string, response bytes and entry count are bounded, and referrals or
unexpected operations fail closed. Observed group names are joined only to
administrator-owned `auth/:mount/groups/:name` policy mappings. Removing a live
directory membership therefore removes that mapped policy from the next login;
existing tokens retain their already-issued authority until their normal
revocation/expiry lifecycle.

This remains narrower than full OpenBao LDAP parity. It does **not** provide a
service-account search credential, arbitrary user/group filter templates,
nested/recursive group expansion, referrals, StartTLS, SASL or an independently
qualified Active Directory matrix. Those remain open under
`HB-SURFACE-AUTH-LDAP`; this document grants no compatibility or production
authority.

Executable acceptance includes `qa/openbao-acceptance/ldap_bounded.py` and
`qa/openbao-acceptance/ldap_openldap_live.py`. The latter launches a real
OpenLDAP `slapd`, proves live group-to-policy projection, removes the directory
membership and proves the next login loses that policy, then restores membership
and verifies the mapping survives HeptaBao restart. Provider outage/recovery and
local-authority deletion are exercised in the same profile. Independent
qualification remains a separate exit.
