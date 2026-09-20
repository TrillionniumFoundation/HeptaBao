# External LDAP authentication profiles

## Native manager-search profile

A fresh `ldap` mount accepts OpenBao-style `binddn`, `bindpass`, `userdn`,
`userattr`, `userfilter`, `groupdn`, `groupattr`, `groupfilter`,
`case_sensitive_names`, `username_as_alias` and token lifetime/policy fields.
It uses one host-enrolled LDAPS connection for manager bind, unique user search,
user bind, manager rebind and optional group search. `userattr` and `groupattr`
default to `cn`; the default user filter compares the configured user attribute
with the username. The default group filter matches `memberUid`, `member` or
`uniqueMember`. A missing group base or empty group filter disables group search.
Configuration rejects unsupported filters before any provider I/O or state write.

`users/:name` optionally contributes `groups` and `policies`; no synthetic local
password is required. `groups/:name` contributes policies. Writes replace mapping
contents, reads and writes fold names unless case sensitivity is enabled, and
DELETE uses the exact stored key. Directory alias and group values preserve their
case; username-as-alias uses the canonical login name without requiring a returned
alias attribute. Manager passwords are omitted from configuration readback.

All three renewal routes repeat directory authentication and use current policy
and token limits. Policy changes reject renewal; changes confined to external
Identity groups update that membership with the lease/wrapper in one transaction.
Renewal retains the issued alias. Provider credentials are encrypted and zeroize
on drop; token-API children and orphans never inherit them. Config, auth mount,
target token, live actor and mapping absence/presence are rechecked after I/O.

This profile requires schema 23. Existing bounded configuration and local
user/MFA authority stay intact. A request mixing the two configuration
vocabularies returns 400; switching an existing profile returns 409. Use a new
mount to select native configuration, including when a legacy local user was
created before configuration.

Filters support AND, OR, NOT, equality and presence, with `{{.Username}}`,
`{{.UserAttr}}` and group-only `{{.UserDN}}`. Template values become BER assertion
values, never filter syntax. Filters are bounded to 4 KiB input, 16 KiB wire,
12 levels and 128 nodes. The entire exchange has one three-second deadline,
64 KiB response frames and a 256 KiB total response budget. Search admits at most
two user entries to establish uniqueness and 128 groups; multiple users fail.
Substring/extended filters, general Go templates, anonymous discovery, paging,
referrals, StartTLS, SASL and a complete Active Directory matrix remain open.
The endpoint address, TLS name and CA still require process enrollment.

`ldap_native_live.py` compares this profile with pinned OpenBao 2.6.2 using actual
OpenLDAP. `ldap_native_upgrade.py` exercises the pinned schema-22 binary and store,
legacy mapping revocation, native optional mappings, credential isolation,
downgrade refusal and recovery. These are scoped tests, not full migration or
production qualification.

## Legacy bounded profile

The legacy profile admits an `ldap` auth mount with durable configuration at
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

This legacy profile remains narrower than full OpenBao LDAP parity. It does **not** provide a
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
