# Bounded OpenLDAP dynamic-secret profile

HeptaBao exposes a bounded `ldap/` secrets mount for dynamic credentials over
an enrolled LDAPS origin. The profile persists the lease intent before any
directory I/O, performs manager Add/Modify operations outside the Service
writer, and publishes a credential only after marker and password readback.

## Implemented path

`ldap/config` accepts one canonical LDAPS origin, manager DN/password and a
user subtree. `ldap/role/:name` accepts a strict single-entry LDIF add template
with `{{.Username}}` and `{{.Password}}`; `GET ldap/creds/:name` creates a
bounded account. The lease owner is bound to the issuing token, and renewal
checks the owner, expiry and role maximum. Configuration and role changes are
fenced while an intent or lease remains.

The provider path observes the DN before Add. A repeated or response-lost Add
is accepted only when the request marker matches and the generated password
binds. Revoke uses an asserted atomic Modify that replaces the marker and
removes `userPassword`, then reads the marker back and verifies the old password
is rejected. If the DN is absent, a marker-only retained-DN tombstone fences a
delayed Add. This retained-DN behavior is a bounded safety profile and is not
OpenBao's native delete behavior.

Pending issue/revoke state can be reconstructed after process or provider
restart. The lifecycle worker runs the provider effect on the current HA leader,
uses a fair provider cursor, and finalizes only after a fresh linearizable
check. A local snapshot restore is refused while an OpenLDAP mount exists,
because an older snapshot cannot revoke a directory identity created by newer
state.

## Delivery and recovery admission

HTTP credential delivery retains the original private request admission across
provider I/O and rechecks current policy, identity, namespace, request deadline
and Service activation before and after durable completion. A global
seal/unseal cycle cannot revive the old admission. Rejection retains the same
lease identity for cleanup; cleanup never requires a new credential grant.

If a namespace was sealed and the process disappeared before the finalizer
recorded rejection, recovery converts that pending issue to revoke before
another directory Add can be admitted. Already-delivered active leases still
retain their original owner and expiry; sealing a namespace is not a blanket
revocation of them. Global unseal may recover the original still-live pending
issue through the maintenance-only path without restoring its lost HTTP
admission or extending its expiry. See the request capability boundary and
`service_secret_delivery_tests.rs` for executable distinctions.

The real fixture is `qa/openbao-acceptance/openldap_secret_live.py`. It uses the
same private, validated slapd prerequisite resolver as the authentication
fixtures, and sends manager/issued bind passwords through inherited anonymous
pipes. Subprocess and pipe failures must close descriptors without replacing
the original failure or leaving plaintext password files.
`qa/openbao-acceptance/evidence/openldap-secret-live-da33417.json` is a retained
historical receipt, not current-head evidence. The replacement workflow runs
the live profile separately for each candidate; its success does not remove
the whole-surface gaps below.

## Remaining OpenBao 2.6.2 surface

This profile does not claim static roles, rotate-root, service-account checkout,
multi-entry LDIF, AD/RACF schemas, native deletion compatibility, HA/provider
replication qualification, lost-reply fault injection, tombstone garbage
collection, or revocation of already-established LDAP sessions. Those remain
separate blockers before a full OpenBao 2.6.2 replacement claim.
