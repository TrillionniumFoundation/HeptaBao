# SSH OTP and registered local leases: runtime development guide

Owner: the existing `heptabao-server` EngineState writer inside Service.
Sources: `engines/ssh.rs`, `engine_leases.rs`, `service_leases.rs` and AuthState
issuer metadata. This is an actual online credential API, not the standalone
`heptabao-lease` model. It does not configure or authenticate an SSH host by itself.

## Routes and role profile

Enable an `ssh` mount through the existing sudo-gated `sys/mounts/<mount>` API.
`GET/POST/PUT/DELETE <mount>/roles/<name>` owns role configuration; `LIST roles`
returns bounded role names; `POST lookup` maps an IP to roles. The supported
`key_type` is `otp`; CA and other SSH profiles return an explicit unsupported error.

A role defines `default_user`, comma-separated `allowed_users`, `cidr_list`,
`exclude_cidr_list` and `port`. Usernames are bounded ASCII identifiers, not shell
arguments. The default user is allowed; empty allowed-users or `*` admits otherwise
valid users. IPv4 and IPv6 have separate CIDR matching; an IPv4-mapped IPv6 address
does not silently bypass IPv4 policy. Exclusions take precedence. Empty required
CIDR policy, invalid address/prefix, invalid port and unknown fields fail closed.

`POST/PUT <mount>/creds/<role>` requires the actual authenticated principal and
`update` permission. Input supplies an IP and optional username. Output contains
an unpredictable one-time `key`, IP/user/type/port, `lease_id`, `lease_duration`
and `renewable:false`. TTL comes from mount tuning (600 seconds by default, at
most 32 days), clamped to the authenticated issuer and ancestor-token expiry.
An issuer whose final finite use is exhausted cannot mint this longer-lived
credential; this is an explicit bounded service restriction.

`POST/PUT <mount>/verify` authenticates by OTP possession, not a second bearer.
Success returns only IP, username and role name, after durable consumption. The
helper deploying this API must validate these fields against the actual SSH host
and login user; merely accepting a 200 result would be unsafe. No PAM helper,
sshd configuration, local account change or host login is implemented or qualified
by the server API tests.

## Durable state and lifecycle

Each mount owns at most 128 roles and 1,024 registered OTP leases; the global
the aggregate service-state cap (16 MiB local; 768 KiB on the current HA proposal path) may reject earlier. A lease ID is a separately random
suffix under the exact mount/credential-role path. The store keeps an OTP SHA-256
verifier, issuer digest, bound IP/user, issue/expiry times and consumed state—not
the original OTP. An intentionally response-wrapped OTP is retained only inside
the encrypted wrapper until release/expiry. Neither form belongs in audit logs,
ordinary diagnostics, learning records or evidence exports.

The states are issued → consumed → expired/revoked cleanup; consumption and
registration are distinct. Successful verification makes the OTP unusable but
keeps lease metadata until expiry or explicit revocation. Repeated verification
returns 400. Role deletion prevents new issuance; unmount destroys that mount's
credential state and re-enabling it cannot restore old passwords.

The Service performs expiry, issuer/ancestor revocation and current entity
liveness reconciliation under its existing post-ReadIndex mutex. It commits the
observed clock frontier and removals before later rejection. Thus an observed
expiration or revocation cannot be reversed by clock rollback or process restart.
This is on-request reconciliation, not a general external-provider scheduler,
wall-clock oracle or background 24-hour operations service.

## Lease administration and authorization

`POST sys/leases/lookup` returns ID/path/issue/expiry/TTL and nonrenewability.
`LIST sys/leases/lookup/<prefix>` returns hierarchical keys and requires both
`list` and `sudo`. `POST/PUT sys/leases/revoke` accepts a lease ID; the path-ID form
is also accepted. Exact removal is synchronous and idempotent for unknown IDs.
A supplied `sync` must be Boolean. A conflicting body lease ID and path lease ID
is rejected before mutation, preventing a body from redirecting path-scoped ACL.

`POST/PUT sys/leases/revoke-prefix/<prefix>` needs `update` plus `sudo` and only
accepts a registered SSH mount/credential prefix. Matching uses segment boundaries:
`creds/a` does not revoke `creds/a-other`. Empty, general token/auth or unimplemented
provider prefixes return 501 rather than falsely claiming that those effects were
revoked. This profile's nonrenewable OTP leases reject renewal; they do not silently
extend expiry. Other lease administration surfaces remain explicitly unsupported.

## Transaction, faults and recovery

Issuance and verification use an isolated EngineState candidate. The existing
encrypted durable journal/commit and mandatory result audit precede release. A
response-wrap failure rolls back new lease issuance, not to raw OTP delivery.
A caller finite-use decrement already admitted remains consumed. Unknown commit
or result-audit failure fences the service and withholds verification metadata;
reopen/reconciliation cannot turn a committed consumed OTP back into an issued one.
At-most-once verification does not guarantee that the SSH client received a reply.
Do not blindly retry after uncertain verification or infer login success from
issuance, queue acknowledgement or lease creation.

Schema 3 is the combined wrapping/OTP runtime increment. Legacy schema 1/2 reads
are accepted only without newer state, and no-op reads preserve old bytes. New
mutations upgrade atomically; schema-2 binaries reject new state. Mixed-version
rolling HA upgrades and historical-snapshot rollback are not qualified.

## Tests and remaining implementation work

`cargo test --locked -p heptabao-server ssh_` exercises encrypted restart, single
use, concurrent verification, CIDR/namespace isolation, issuer and identity
revocation, audit failure, schema/record corruption, bounds and prefix/path-ID
safety. `ssh_otp_live.py` compares selected real official OpenBao behavior.
`ssh_otp_ha.py` tests actual local processes and includes the earlier wrapping/HA
baseline; counts must not be added as independent coverage. `wrapping_upgrade.py`
checks old-reader rejection and new-reader recovery for both wrappers and OTPs.

The remaining gap includes the SSH CA profile, host/PAM integration, wider SSH
parameter/error compatibility, database/cloud/PKI providers, general renewable
lease callbacks, external side-effect reconciliation, a production lease worker,
and independent multi-host/hardware/platform evidence. This scoped implementation
never sets complete compatibility, production, migration or release authority.

## Current bounded evidence binding

The current compatibility corpus admits the executable `ssh_otp_live.py` profile for
nine selected OTP behaviors: mount and role creation, bounded issuance, exact target
verification, replay rejection, explicit revoke and revoked-use rejection, response
wrapping, and successful unwrapped verification. The profile runs those requests
against a fresh candidate and a pinned OpenBao 2.6.2 oracle through the isolated
harness. It remains a selected OTP comparison: SSH CA signing, sshd/PAM login,
host-account effects, and independent qualification stay outside this admission.
