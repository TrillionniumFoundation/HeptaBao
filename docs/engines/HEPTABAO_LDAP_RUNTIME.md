# Bounded LDAP authentication profile

HeptaBao now admits an `ldap` auth mount with durable configuration at
`auth/:mount/config`, directory fixture users at `auth/:mount/users/*`, and
password/TOTP login at `auth/:mount/login/:name`.

The profile validates `ldap://`/`ldaps://` endpoints, rejects control
characters and embedded LDAP filter/query syntax, and requires a
`{{username}}` DN template. Login uses the mount's encrypted durable user
records, so revoking or deleting a fixture user immediately changes subsequent
login authorization and survives restart. User records are never returned by
the config endpoint.

This is a bounded local directory profile. It does not claim external LDAP
TLS bind/search, nested-group expansion, provider timeout precedence, or
cross-provider compatibility. Those behaviors remain external qualification
requirements under `HB-SURFACE-AUTH-LDAP` and `HB-BLK-EXT-*`.

Executable acceptance: `qa/openbao-acceptance/ldap_bounded.py`.
