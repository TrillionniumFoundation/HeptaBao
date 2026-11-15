# Fixed-slot AuthBus coordinator candidate

This is a concrete, independent service for the existing
`heptabao-authbus-fixed-slots-v1` client. It is a new implementation, not a
recovered r11 coordinator. No production installation, credential migration or
provider call is implied by its local tests.

`cli.mjs` provides `initialize`, `authorize`, `revoke-authorization`,
`bootstrap`, `enroll`, `recover`, `once`, `serve`, and `shutdown`. `serve` runs
the same finite enrolled-key scan and stops admitting work on termination. It
waits for the original operation before closing its resources. It does not
spawn another process or signal other clients.

The four files in `transport/` are byte-for-byte existing published client
modules. The service concretely uses `StrictBaoClient` for pinned CA/hostname/
leaf HTTPS and durable AppRole login/renew/revoke; it uses `PrivateOutboxStore`
for the real SQLite WAL/FULL state and independent DELETE/FULL OS-released
operation lock. The original producer's `initialSlot`, `initialAck`, canonical
digest and `validatePair` are imported directly. No legacy inbox scanner is
called. The original Python grant/credential/manifest/receipt logic is retained
unchanged as a test oracle under `reference/`; production does not execute it.

## Private deployment configuration

The configuration and event/grant inputs must be owner-only, regular, single
link 0600 files. `stateDir` and its parent deployment area must be a protected
0700 directory with no alias. The factory verifies all nine runtime source
files against `implementationSha256` before opening credentials or journals.
An approved external launcher must also bind the executable/import sources
before execution; a check inside a Node module is not an external code-signing
boundary.

```json
{
  "schema": "heptabao.fixed-slot-coordinator.r1.config",
  "address": "https://127.0.0.1:31080",
  "caFile": "/owned/private/ca.crt",
  "serverCertificateSha256": "exact-current-leaf-DER-SHA256",
  "roleIdFile": "/owned/private/role_id",
  "secretIdFile": "/owned/private/secret_id",
  "stateDir": "/owned/private/coordinator-state",
  "implementationSha256": "source-manifest.public.json implementationSha256",
  "ownerId": "one-fixed-owner-UUID",
  "bootstrapProfileCount": 3,
  "topology": [
    {"host_id":"mac","epoch":"one-new-enrolled-UUID","slots":2,"agents":["main"]}
  ],
  "operationMs": 30000,
  "scanLimit": 32,
  "pollMs": 1000
}
```

The strings above are placeholders for reviewed private inputs, not usable
credentials. Host topology must contain the actual full registered agent set;
it is not inferred from the example. Every source epoch is a distinct UUID.
The mount is fixed to `openclaw-auth`. There is one private state directory for
the one coordinator owner; independent copies must not be run as competing
coordinators. The implementation refuses to adopt an existing remote control
without the original local enrollment journal.

An administrator must explicitly configure and verify KV2 mount retention
`max_versions=2` and `cas_required=true`, and provision independent roles and
policies. The service reads actual mount and per-key metadata before publishing
control. It accepts inherited or explicit two-version key retention. It does
not silently change mount policy or retention. The coordinator role needs
these metadata reads, exact enrolled records and canonical publication paths;
initial enrollment also needs CAS-0 creation of slots/reports. Producer roles
may update only their enrolled outbox/report keys and read their own ack plus
the canonical read scopes. They must not write ack, manifest, profiles or other
hosts. Root/admin tokens are not passed to this service.

## Initialization and operating sequence

Commands take an explicit config path; they never load a default config or an
environment-selected token. With reviewed inputs and an actual qualified service:

```sh
node /approved/bundle/cli.mjs initialize /owned/config.private.json
node /approved/bundle/cli.mjs authorize /owned/config.private.json /owned/grant.private.json
node /approved/bundle/cli.mjs bootstrap /owned/config.private.json /owned/event.private.json
node /approved/bundle/cli.mjs enroll /owned/config.private.json
node /approved/bundle/cli.mjs once /owned/config.private.json
node /approved/bundle/cli.mjs serve /owned/config.private.json
```

Repeat authorization/bootstrap only for the explicitly reviewed distinct initial
profiles. Bootstrap is refused once control exists. Initialization does not
admit an empty manifest for production clients. Enrollment creates exact initial
slot/ack/report documents with CAS 0, verifies retention and publishes immutable
control last. A failed enrollment keeps its original plan; `recover` resumes
only known-not-dispatched stages or reconciles dispatched stages by reads.

Every credential event still needs the original exact operator grant: source,
provider, profile, identity, expected-current digest and next digest. A fresh
timestamp or AppRole login is not rotation authority. Publishing writes an
immutable content-addressed profile, consumes that grant in the manifest CAS,
confirms the canonical receipt, and only then acknowledges the original slot.
Health events receive only the inline `observed_health_no_scheduler_action`
receipt; no per-health immutable server key or scheduler effect is created.
Fixed reports are validated and observed, not promoted to authorization.

The scan is finite: at most 32 enrolled slots and 32 enrolled reports per call,
with persisted cursors. One operation has a 30-second absolute budget and each
unchanged strict request has at most 15 seconds. `serve` accepts an optional
maximum cycle count for qualification. A signal stops new admission but does
not cancel or resend an already dispatched request.

## Journals and recovery

`journal-store/` contains the original two private SQLite databases and any
sidecars. `operations/` contains create-only, fsynced original plans, dispatch
intents, known responses, exact confirmations and completion records. They can
contain credentials and credential-derived digests and must remain private.
Public CLI results contain fixed codes/counts only. No complete credential
event, grant, profile key, original private path or credential digest is logged.

Each request is marked dispatched durably before its one call. A crash or
response loss leaves that original request pending. `recover` reads the exact
next version/postimage or retained history; an unchanged preimage remains
unknown. There is no repeat dispatch, replacement UUID, fresh epoch, automatic
backup rewind or empty-state bypass. A known CAS/ACL rejection remains a
blocked original record for review. This release intentionally has no command
that clears a rejected or unknown journal; a separately reviewed recovery or
migration is needed instead of resetting files.

Ordinary process exit preserves a known active bearer for the next process.
`shutdown` explicitly revokes it once and is refused while a coordinator
operation is unresolved. Full backup/restore must include the entire original
SQLite/sidecar and operation directory. Do not copy only `state.sqlite`, erase
unknown operations or run restored state beside the original. Journal and
canonical immutable credential history are retained; this implementation does
not claim an automatic retention/garbage-collection policy.

## Qualification boundary

Run `python3 build_manifest.py`, then `node --test tests/*.test.mjs` in an
isolated local workspace. Tests use actual SQLite, two original synthetic child
SIGKILLs, the original Python publisher as a transaction oracle, and actual
loopback TLS with a synthetic HTTPS peer. The original producer performs real
slot publication against the same engine. The TLS test uses the concrete
factory/StrictKvAdapter; a wrong leaf pin produces zero HTTP requests, and a
dropped successful ack response is recovered without another write.

The first draft had two fixture closure mistakes: removing a synthetic directory
before later resource-close hooks, and checking a peer socket set after only one
event-loop turn. Their failures are retained. The fixes defer directory cleanup
until all resource hooks finish and await every original peer's actual close
event, with a finite bound. They do not relax service or TLS behavior.

Actual normal HeptaBao server execution, every deployed role/policy, actual
three-client restart/rollback/cutover, provider validity, production maintenance,
permanent backup recovery and full HA qualification remain separate gates.

## Revision 2 confirmation boundary

Revision 1 and its 19 local results remain frozen. Revision 2 requires the current immutable profile, receipt, control and pre-control enrollment head to remain version 1 with the exact original postimage. Only manifest confirmation can consult retained history, and only when its validated current head is exactly one version above the saved original target. Ack confirmation requires the original target as the current ack; the producer's bound slot may remain at the acknowledged version or advance once, with the original pair validator passing in both cases. A larger head, an old preimage, a changed immutable head, or an invalid pair leaves the original operation unresolved and never authorizes another write.

Private confirmation records retain the original target digest, observed current head version, whether retained history was used, and the observed slot version. This is a stricter source revision; it cannot adopt a previous implementation's private state binding.
