# AuthBus R5: native control backend and distinct cold SDK processes

## Qualification boundary

This candidate runs the installed OpenClaw SDK against a newly created native
HeptaBao fixture on the same Linux host. The earlier owner-r5 run passed all
127 checks in its 11 scenarios on Node 22.23.3 / OpenClaw 2026.7.1-2, with
actual SQLite and an owned HTTPS provider. Its control service was a KV2
emulator. That original receipt remains unchanged:

`067961e9851cee9e09deb2beaee5a63a02c38f98e9086eae7344f0a8b15289b9`.

This new candidate does not recategorize that evidence. It has four explicit
native transport scenarios, followed by two independently started SDK
processes over the same real SQLite and authority directories. A passing
parent receipt must establish the actual native backend, native SIGKILL
recovery, each original SDK process exit, and all worker assertions. The
local unit checks qualify only fixture contracts and synthetic filesystem
boundaries. No local test result is a native or installed-SDK pass.

All OAuth credentials and provider responses in this new run are synthetic.
Its AppRole credentials are real, newly generated credentials of the disposable
HeptaBao instance. It imports no J3160 authority or production credential. It
does not prove real external-provider refresh, production SDK installation,
per-host cutover, or all 127 prior scenarios on the native backend.

## Exact runtime closure

The runtime packet contains 21 source files plus one root manifest:

- The 13 byte-frozen owner-r5 runtime modules, including its unchanged old
  caller runner as a provenance anchor. The new runner does not invoke that
  old emulator runner.
- Five existing native helpers: `native_v6_authbus_client_live.py`,
  `owned_process.py`, `cert_auth_live.py`, `fixture_mounts.py`, and
  `qa/single-node/smoke.py`.
- Three new runtime files: `native_v6_authbus_refresh_live.py`,
  `authbus_refresh_sdk_native_worker.mjs`, and
  `authbus_refresh_sdk_native_fixture.mjs`.

Each file is listed with repository-relative path, byte length, SHA-256 and
Git blob ID. The controller checks the complete manifest before its first
fixture process, and rechecks it after cleanup. Each SDK worker independently
checks the 15 JS source pins before import and after guard restoration. The
existing SDK loader retains its exact installed-module hashes and final
installed-SDK verification. Source symlinks and writable input files are
rejected. The overlay changes no existing runtime module or Rust source.

## Native data path and fault definition

The controller creates a private server directory, its own CA/TLS certificate,
and a new HeptaBao process with `--fixture-native-v6-service`. It initializes
and unseals that instance, explicitly creates the `authbus` KV2 mount,
activates native V6 once, and requires `native_kv2_reader_format == 2`.

Two new AppRole policies cover only the four fixture control keys and their
own token lookup/renew/revoke endpoints. Reader and issuer role/secret IDs
are written into the private SDK fixture. The root token, unseal key and
server TLS key stay in the controller's directory and are never provided to
the SDK worker. The worker also refuses reads of that controller directory,
including when the fixture is outside the user's home directory.

A stable loopback TLS proxy preserves the original native response body and
Date header. Its allowed routes are only the exact AppRole login, token-self
operations and four control keys. It never substitutes a token, grant, KV
document, native clock or CAS success. No response redirect is followed. A
new proxy remains running across SDK process changes and native server
reopening, so the trusted source's origin and CA binding remain unchanged.

The sole control fault is an explicit lost acknowledgement:

1. Forward the issuer's original UNKNOWN CAS to the actual native server.
2. Require the actual successful CAS response with exactly the next version.
3. Read that same native key with the controller's independent observer and
   require the complete document and version to match the submitted intent.
4. Only then close the SDK connection without returning the acknowledgement.

The controller never clears UNKNOWN. Its event journal contains bounded
counts, versions and hashes; the journal is not an authorization source.

The separate owned HTTPS provider checks the exact SDK refresh route/body.
Before receiving a request as a permitted refresh, it independently reads the
actual native KV2 record and requires the matching original credential digest,
UNKNOWN attempt, REFRESH_PENDING assignment, boot, scope and fence epoch.
The provider returns synthetic credentials. The `provider-ack-lost` case
closes the response after that native observation and its fsynced event.
Any duplicate or cold provider attempt fails the overall run; it cannot be
hidden as a successful safety check by the fixture provider.

## Scenario inventory

| Scenario | Warm SDK result | Native state required | Provider requests |
| --- | --- | --- | ---: |
| `manager-success` | Actual shared manager returns the actual SQLite successor; old wire/scope bypasses are denied | PUBLISHED with the actual stored digest; fresh higher grant after SDK readback | 1 |
| `intent-ack-lost` | Actual shared manager refuses; original SQLite credential remains | UNKNOWN committed and read back before the response was lost | 0 |
| `provider-ack-lost` | Actual shared manager refuses; original SQLite credential remains | UNKNOWN / REFRESH_PENDING retained | 1 |
| `sqlite-abort` | All 18 actual SQLite INSERT/UPDATE abort triggers prevent publication | UNKNOWN / REFRESH_PENDING retained; no grant for an uncommitted successor | 1 |

Each warm case uses the actual source's reader permission probe, reader token
renewal and issuer token renewal. Each worker closes its actual bearer tokens
and requires revoked-token lookup to fail. All configured secret IDs are
destroyed after the final cold phase and actual reenrollment must fail.

## Cold and restart ordering

The warm SDK process must complete its original owned exit before the first
cold SDK process starts. The controller waits for the old successful refresh
owner to expire using freshly observed native Date's lower bound. This wait
neither renews a lease nor restarts a budget.

Each cold SDK process constructs fresh trusted-source and authority objects
over the prior actual SQLite and local authority files. It must prove a new
boot identity over the same source provenance, and must initially refuse
SDK selection from a cached positive record. A native grant for the previous
boot cannot bootstrap the new process. UNKNOWN cases must reject both a new
coordinator issuance and an actual SDK retry, with the old SQLite contents
unchanged and zero final provider dispatches.

For the successful case, the old credential digest remains fenced by the
actual PUBLISHED record. The new current digest may be authorized only by a
fresh native CAS grant with a strictly higher epoch. The actual SDK then
resolves the exact persisted successor without calling the provider. The
real profile resolver is also given a stale caller store containing the old
credential and must refuse it; no real SQLite mutation is used for this test.

After the first cold SDK exits, the controller SIGKILLs the original native
server handle, completes its original wait, rechecks the binary pin, starts
the same binary/data directory and unseals it. It requires every full control
document and KV2 version to be identical across that reopen. It also checks
all previously revoked bearer tokens remain denied. A second distinct cold
SDK process repeats the cold authority, UNKNOWN and fresh-successor checks
against this recovered native backend. All attempt digests remain unchanged.

SDK cold construction here follows completed SDK process exits. This run does
not claim a SIGKILL of a partially executing SDK process; the SIGKILL/reopen
claim applies to the native HeptaBao server.

## Original budget and custody

The controller supplies an original 180-second absolute monotonic deadline to
the existing `owned_process.Owner`. A shorter inherited deadline is retained.
The helper's older 360-second maximum is unchanged and does not grant this
profile extra time. An initial owned Node probe proves that Node `hrtime` and
the Python parent share the same monotonic clock domain. The unchanged
absolute deadline then travels in every SDK worker configuration. Server
initialization, hashing, OpenSSL, the warm process, cold processes, native
restart, lease-expiry waits, HTTP I/O and cleanup all consume it.

The original ten-second authorization/refresh leases remain unchanged. No
product deadline, native request cap, general KV limit or provider call
timeout is raised. Control requests/responses are capped at 2 MiB and provider
messages at 64 KiB. Absolute-deadline timers also close partial HTTP reads;
progress on a slow socket cannot reset the overall budget. Unstarted or live
fixture listeners and original process handles are retained for cleanup.

Binary hashing is streaming. The known 776,397,280-byte unstripped Linux
binary is supported without copying it into the source packet or loading it
into a single memory buffer. Its hashing and exec-admission cost still counts
toward the same deadline.

## Concrete main-host execution

Use the separately verified existing Linux binary, not the Mac executable.
The known build belongs to commit
`0f1c996136aae94e99c2b709a5797ffea479f6cd`, tree
`8befd5cedfb7ccafee5f707e5985d49eeb78fb60`. Its original full test run was
53/55, with the two remaining assertions retained in the build provenance.
A native AuthBus pass does not erase those failed tests or promote that build
to full OpenBao replacement status.

After exact extraction of the packet to the new source path below:

```bash
python3 -B /home/qian-qi/heptabao-next-gates-20261017/authbus-r5-native-cold-r1-source-20261019/qa/openbao-acceptance/native_v6_authbus_refresh_live.py \
  --binary /home/qian-qi/heptabao-next-gates-20261017/native-full55-0f1c-main-r1/heptabao-server \
  --binary-sha256 a45ebe3e4d7b845ca5392431bdae9ba8348e16d2fe88489c3347049a07a7b8d2 \
  --node /usr/bin/node \
  --openclaw-root /home/qian-qi/heptabao-next-gates-20261017/authbus-admission-sdk-20261018-01/openclaw \
  --source-manifest /home/qian-qi/heptabao-next-gates-20261017/authbus-r5-native-cold-r1-source-20261019/source-manifest.json \
  --work-dir /home/qian-qi/heptabao-next-gates-20261017/authbus-r5-native-cold-r1-actual-20261019-01
```

The work directory must not already exist. There is no automatic retry on an
ambiguous outcome. Retain the controller's `public-receipt.json`, all three
`sdk/reports/*.json` receipts, the original-process receipt and failed private
logs. Credentials/recovery files and raw SQLite stay private and are not
copied into a public evidence overlay. Parent process receipts, file hashes
and exact original exits must accompany any reported actual result.
