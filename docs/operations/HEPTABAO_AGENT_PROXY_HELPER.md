# Agent, local proxy, SSH verifier and idle lifecycle

Status: executable bounded product profiles; not full OpenBao replacement, independent
security acceptance, production rollout, PAM installation or external-provider closure.
The current source is the exact Git tree, not counts copied into this document.

## Architecture and owners

`clients/python/heptabao/agent.py` owns one OS-private AppRole token sink and its
local execution checkpoint. It calls the real HTTPS authentication and renewal
routes, never edits server state, never grants ACL, and does not become a secret
authority. The existing Rust `heptabao-agent` crate remains a separate model.
`proxy.py` is an actual Linux Unix-domain HTTP listener, not that standalone Rust
proxy model. `ssh_helper.py` is a one-shot verifier, not a shell/login service.
All server mutations still use the existing authenticated Service transaction,
accepted-before-entry audit, encrypted durable storage and optional Raft commit.

`service_lifecycle.rs` adds one host-owned periodic worker for already registered
local SSH OTP leases and wrapped response payloads. It does not execute external
provider callbacks. The service's single writer mutex and ReadIndex/consensus path
remain authoritative; the worker cannot mint tokens, enlarge TTLs, add leases,
unseal the server or expose a remotely selectable clock. Standbys do not write.

## Idle lifecycle algorithm and failure semantics

`lifecycle_interval_seconds` is a server configuration integer, default 5, with
1–60 enabled and 0 explicitly disabling idle ticks. Per-request expiry/revocation
checks remain mandatory even when idle ticks are disabled. A single weak-reference
worker wakes on a bounded timer, uses `try_lock` (no queue behind a request), and
joins on host teardown. Sealed/recovery-fenced servers do not maintain state.
A leader confirms ReadIndex, copies the authoritative state, advances observed
local lifetime clocks, removes expired/revoked local leases and erases expired
wrapped payloads. A synced lifecycle-request audit precedes publication; the
same commit pipeline publishes once; a lifecycle-response audit records outcome.
A post-commit audit failure fences service recovery. A transient unavailable
ReadIndex does not fabricate expiry success. No live lifecycle state means no
periodic rewrite; clocks cannot regress. Tick latency is not an expiry SLO under
contention, disk failure, quorum loss or clock failure. Clients still face the
online time/issuer check before receiving data.

The maximum source state and registry bounds are inherited (including the 768 KiB
service state ceiling). The current code clones/scans bounded state; it is not an
indexed million-lease scheduler and has no general database/PKI/cloud callback.
No new durable fields were added by the worker: Service schema remains 3.

## Agent configuration and invocation

Install the reviewed Python wheel. Create a dedicated OS user and an existing,
caller-owned 0700 state directory. Use 0600 private configuration and credential
files outside that state directory. The CA must be a bounded regular file owned
by the caller or root and not writable by group/other. The exact CA bytes are
hashed into the binding and loaded into TLS from those same bytes, avoiding a
second mutable pathname read. Role/SecretID values are never command arguments.

Example (paths are placeholders to substitute in an isolated environment):

```json
{
  "address": "https://127.0.0.1:8200",
  "ca_file": "/etc/heptabao/ca.pem",
  "auth_mount": "auth/approle",
  "namespace": "",
  "role_id_file": "/etc/heptabao/role-id",
  "secret_id_file": "/etc/heptabao/secret-id",
  "state_dir": "/var/lib/heptabao-agent",
  "timeout": 5,
  "interval_seconds": 1,
  "renew_increment_seconds": 60,
  "max_token_ttl_seconds": 3600,
  "max_authentications": 32,
  "max_runtime_seconds": 3600
}
```

```sh
heptabao-agent --config /etc/heptabao/agent.json
```

The AppRole must issue non-root renewable **service** tokens with unlimited uses,
finite TTL and the `default` self-lookup/renewal permissions (or equivalent).
The agent verifies these using the actual issued token before publishing it.
Use narrowly scoped product policies; there is no root-token fallback. HCL, JWT
Agent methods, wrapped SecretIDs, wrapped/encrypted sinks and template engines
are not implemented. SecretID files are deliberately retained and re-read before
an explicitly admitted reauthentication, not silently deleted. The operator must
provide a SecretID suitable for that workflow; a consumed single-use SecretID
cannot be recreated by the agent.

Resource bounds: request timeout 0.1–30 seconds, poll interval 0.1–60 seconds,
renewal increment 1–3600 seconds, token TTL ceiling 2–86400 seconds, authentication
attempt budget 1–256, and process runtime 1–86400 seconds. The process does not
promise indefinite operation; a service supervisor owns any restart policy.

## Agent persistent state machine

```text
empty/stopped -> auth_pending -> token file -> ready
ready -> renew_pending -> token file -> ready
ready -> confirmed expiry/renewal denial -> empty -> new admitted authentication
ready -> graceful stop -> stopped (sink removed)
pending/invalid/digest mismatch -> reconciliation required; never automatic login
```

`state.json` is schema 1, with binding digest, phase, generation, authentication
count, wall-clock observation, expiry, TTL, renewal time and token file SHA-256.
It contains no token/SecretID bytes. `token` is a 0600 raw bearer file, intentionally
unencrypted for the selected same-UID process profile. These are **not** general
logs or audit receipts. The agent writes a durable pending checkpoint before every
login/renewal, removes the public sink while renewal is pending, verifies a complete
response plus self-lookup, atomically publishes token bytes, then publishes ready.
A crash between the two publications remains pending, not an adopted orphan token.

A valid 403 renewal denial or locally confirmed expiry can start a new bounded
AppRole admission. Network/HTTP ambiguity, malformed token responses and
publication uncertainty do **not** trigger blind retries. Startup cannot recover
an unknown token from a digest. Keep the private checkpoint, investigate with the
server operator, revoke/expire possibly issued tokens through an authorized
procedure, then establish a reviewed fresh state directory. Do not delete a
pending checkpoint merely to make the daemon restart. No file flag self-attests
that an unknown server-side effect did not happen.

`--once` executes one step and leaves an admitted sink until its recorded TTL.
It does not renew after exit. Normal shutdown invalidates the sink but does **not**
revoke copies already held by consumers; server TTL/revocation remains decisive.
A generation/digest/time-checked `token_snapshot` is required for consumers;
reading the raw token file alone does not establish readiness. Runtime monotonic
expiry prevents wall-clock drift extending a running agent lease. Restart rejects
wall time behind its recorded observation and never extends stored expiry.
This is not tamper-resistant time across complete host/state rollback.

## File integrity boundary

`private_state.py` walks absolute directory components without following symlinks,
binds the final 0700 owner directory descriptor, and takes one single-writer flock.
Private state files must be regular, 0600, caller-owned and have one hard link.
Writes use a random exclusive staging file, file fsync, descriptor-relative atomic
rename, and directory fsync. Reads verify the same metadata generation around the
secret and its digest. Renamed/replaced directory or lock paths fail closed.
No independent writer creates an alternative state store. These protections do
not stop root or the same OS user, and Python immutable strings/library copies
are not guaranteed to be zeroized or absent from dumps/swap.

## Linux local proxy

A separate 0700 socket directory is required. `heptabao-proxy --config ...` listens
only on `api.sock` inside it, mode 0600. Linux `SO_PEERCRED` restricts accepted peers
to the current UID. Same-UID applications are trusted; the socket is not a boundary
against a user who can already read the token sink. A stale socket is not removed
automatically on startup; operator reconciliation must identify the old owner.

```json
{
  "agent_config": "/etc/heptabao/agent.json",
  "socket_dir": "/var/run/heptabao-proxy",
  "routes": [{"method":"GET","path":"secret/data/application","effectful":false}],
  "allow_effects": false,
  "timeout": 5,
  "max_runtime_seconds": 3600,
  "max_requests": 10000
}
```

Every route is an exact method/path pair, at most 64 entries, no prefix wildcard.
Writes require `effectful:true` and `allow_effects:true`; a GET that issues a dynamic
credential is also an effect and must be classified as such by the trusted owner.
Auth/system-management paths are rejected. The origin/namespace/CA come only from
the admitted agent binding. Incoming tokens, namespace overrides, wrapping headers,
proxy headers, chunked framing, duplicate headers, query strings, percent aliases,
pipelining and keep-alive are rejected rather than silently reinterpreted.

One serial worker allows one upstream operation and a listener backlog of 16.
Headers are at most 16 KiB, request body 256 KiB, response 16 MiB, timeout 1–30
seconds, max requests 1–100000 and runtime 1–86400 seconds. Each request reads a
ready unexpired sink generation, then lets the server enforce live policy and
revocation. The parser deadline is checked again before upstream admission; the configured
HTTPS timeout is an I/O timeout, not an end-to-end SLA covering DNS, disk or a
malicious slow-drip trusted server. No secret cache, auto retry, TCP listener, leader redirect or arbitrary
URL forwarding exists. Error responses do not certify that an effect was absent.
Shutdown removes only its own socket inode. This is not full OpenBao Proxy parity.

## One-shot SSH OTP helper

```json
{
  "address":"https://127.0.0.1:8200",
  "ca_file":"/etc/heptabao/ca.pem",
  "namespace":"",
  "mount":"ssh",
  "host_ips":["192.0.2.10"],
  "allowed_roles":["host-login"],
  "allowed_users":["deploy"],
  "timeout":5
}
```

The trusted login integration runs `heptabao-ssh-helper --config /etc/heptabao/ssh.json
--username deploy` and supplies one OTP through stdin, never argv. Input has a
bounded deadline and maximum 256 bytes; diagnostics contain no OTP. A successful
HTTPS verification must match the trusted requested user, an allowed role, and an
operator-configured **local host** IP. `PAM_RHOST` is the client/remote address and
must not be substituted for that local binding. Configuration is never derived
from login-supplied environment strings. No retry follows an unknown or failed
verification, including a mismatch after the OTP may already have been consumed.

Exit 0 means that one response passed those bindings; exit 1 means denial or
uncertainty. The helper does not edit PAM, sshd, NSS, host keys or account policy,
and does not itself create an authenticated SSH session. Deploying it as a PAM
module/helper requires independent privilege, environment, account and failure
review. SSH CA mode is still separate work.

## Executable evidence and completion boundary

Run all three test families and the actual processes:

```sh
python -m unittest discover -s clients/python/tests -p 'test_*.py' -v
cargo +1.98.0 test --locked -p heptabao-server --lib
python qa/openbao-acceptance/agent_proxy_helper_live.py \
  --binary /absolute/heptabao-server --output /private/evidence/operational.json
```

Run `compare_operational_reports.py --candidate ... --oracle ... --output ...`
against fresh clean-source reports from the same candidate and client distribution.
It requires the fixed 50 common observations plus 8 separately labeled candidate
checks, rejects failed/empty/duplicate/non-boolean results, and never admits full
compatibility or independent provenance from caller-supplied report metadata.

The optional `--oracle` mode uses only checksum-pinned official OpenBao 2.6.2
binary/archive supplied to the existing Oracle launcher. The same distributable
Agent/proxy/helper executables are exercised on both services. Candidate-only
idle audit checks are identified separately, never counted as upstream parity.
The fixture kills a real post-login client process before token publication and
checks the ordinary executable refuses to repeat its pending login. Negative
cases include root-header injection, namespace changes, real policy revocation,
wrong host/user/role, bad CA, second writers, clock drift and secret-free diagnostics.
`idle_lifecycle_ha.py` additionally kills the leader after issuing short-lived
OTP/wrapping state, sends no client requests until a surviving node records a
committed autonomous-expiry audit event, and checks expiry cannot revive when
the old leader restarts. It includes the prior core HA cases; do not
add those counts together. These source assertions and repository CI commands
are not pass receipts for a
future candidate. Multi-host HA, mixed-version upgrades, ARM64/macOS execution,
Windows file security, external providers, full Agent/Proxy/SSH compatibility and
independent production acceptance remain open.
