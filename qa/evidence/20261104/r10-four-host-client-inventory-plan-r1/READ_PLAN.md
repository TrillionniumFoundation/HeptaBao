# Four-host consumer and backup inventory — R10 read-only plan

This is a finite, source-only plan. It has not run a host inventory collector.
It preserves the user's machine-by-machine migration requirement: Pocket evidence
does not qualify the Mac, ROG, X230, their production service registrations, or
their recovery paths. Product API/HA tests and local consumer tests have distinct
scopes. No deletion, service transition, provider request, J3160 connection, or
production initialization is authorized by this document.

The current normal product is commit 49503322c7f446e5eb41e7744f1fdbd7f1192ecc,
tree 1d4211f91e1b34a2ed087a3bbef2e2884bac88e9. Both physical normal44 gates have
completed and root has independently accepted them. That result does not refresh
the older client/configuration observations below.

## 1. Evidence and remaining per-host work

| Host | Existing observed consumer evidence | What it does not establish | Next finite scope |
| --- | --- | --- | --- |
| Mac | Normal360 main-agent registered Codex 0.144.3, actual initialize/login/account-read; parent60, native95 twice, rollback62 twice, all four phases. Pure installed-SDK preview covers five configured agents. | R10 same-identity consumer qualification, current production gateway cold restart, all active sessions, backup migration. | Exact current config, five recorded agent DB metadata sets, gateway plist, six caches, credential/native file custody; then four legacy relay registrations from the original finite matrix. |
| ROG | Normal360 native-preservation parent60, consumer94 twice, rollback64 twice. Explicit user home reads separate identity4. Later normal33 SDK314 and installed-entry SDK330 use synthetic provider credentials. | Native source1 driving independent4, actual ROG manager qualification, R10 production restart or backup migration. | Exact config, six recorded agent DB metadata sets, native user files, gateway unit and three recorded drop-ins; then two held dormant helper registrations from the matrix. |
| Pocket | R8 first cycle: core66, two consumer128, two full raw/effective/cache rollback95, four native factories/eight RPC. Both agents preserve default local5, managed1/2 are imported, ungranted new identities deferred. | R10 consumer pass, hold release, production gateway activation, or recovery of another host. | R10 source packet is approved; its inert stage and separate three-artifact intake are tracked independently. Inventory covers the two agents, original unit/drop-ins, exact two hold markers and six caches. |
| X230 | Normal360 real88 credential transport is an isolated fixture using the already bound ROG credential. Normal33 owned system-manager547 uses synthetic inputs. R10 finite full31 and comparison69 have passed. | An installed production OpenClaw consumer, whole-host absence of credentials, or authority to delete disabled containers/proxy/recovery assets. | Recover the finite registration matrix, then inspect only its exact registered proxy/dev-oracle/client/backup objects. Standard-home paths being absent is explicitly a limited observation. |

The detailed JSON lists every currently recoverable path. The public Mac/ROG
source observation was made while production was running and reports changed
SQLite sidecar metadata. It is planning evidence, not a stopped, atomic rollback
backup. The planned metadata pass will not open those production databases.

Historical semantics to preserve:

- Mac retains original local fallback 1,2,3, including profile3's rejected
  generation and recovery material. trnm's profile-free local primary row must
  retain the actual inherited effective store. Raw omission of homeScope does
  not override the installed registry's observed agent-scope behavior.
- ROG retains the user-native identity4 and homeScope=user. Its main SDK order
  4,2,1 and main exclusion remain; azi2–azi5 retain2,1, and zbj inherits4,2,1.
  The earlier inference that identity4 was native-only was already corrected.
- Pocket retains publishNew=true, the two original order exclusions, shadow
  scheduler, main/tg default5, independent user-native4, exact raw profile-free
  tg row and all usage. Its two held entries are not removed by changing a
  releaseGeneration field or by passing an isolated fixture.
- Shared managed candidates2,1 were selected by actual pure SDK previews for
  all eleven Mac/ROG agents. This preserves their different effective orders;
  it does not enroll independent4/5 into a common manifest. Current digests and
  active bindings must still be rechecked before any later transition.

## 2. First operation: recover the finite original scope

The original matrix is referenced by the published current-source evidence,
but its whole bytes are not currently recovered in this agent's Git/V8 custody.
The exact files to read, in one host at a time, are:

 /home/qian/heptabao-cutover-cleanup-inventory-20261104-r1/finite-cutover-registration-scope-r2.public.json
 SHA256 f458db4ebda522c3054c48eca917b8d7aaafcef33c13892a846c53441b49aa64

 /home/qian/heptabao-cutover-cleanup-inventory-20261104-r1/four-host-cutover-cleanup-assessment.public.json
 SHA256 aa23dcf2c01b9ea0372a67942510b6e9d8b49a1d3e823b2e62344748fdb92cf0

No exact basename is invented for the four Mac relays, the two ROG held helpers,
X230's disabled objects, or the nine previously reviewed recovery scopes.
Those exact names come from these originals, after whole-digest verification.
Their absence from the current validation Git tree is not absence on the hosts.

A concrete new configuration, command, mounted path or restore reference may
extend this finite set. A hypothetical unregistered manual path does not create
an unbounded whole-filesystem search gate.

## 3. Small, sequential read windows

The proposed metadata collector uses NEW limits: one host at a time, one
45-second monotonic operation and a 60-second remote supervisor cap. Each
subprocess gets at most10 seconds and only the remaining original operation
time. One pass handles at most32 exact registered objects, at most16 declared
backup metadata items, up to2MiB per small metadata document and8MiB total reads,
and at most64KiB public output. These are inventory limits, not changes to any
existing native, HTTP, migration, rollback, or supervisor-stop deadline.

A deadline, denied read, oversized document, missing file, registry discrepancy
or mismatched prior digest is retained as an incomplete observation. It does not
mean no consumer exists. Do not silently retry under a new budget.

For Mac, the first exact registration is
 /Users/qianqi/Library/LaunchAgents/ai.openclaw.gateway.plist
and the read-only query is launchctl print gui/501/ai.openclaw.gateway.

For ROG, the first exact registration is
 /home/qian-qi/.config/systemd/user/openclaw-gateway.service
with these recorded drop-ins:
 10-telegram-dns-verbatim.conf
 20-drain-timeout.conf
 30-telegram-spooled-handler-timeout.conf
under the unit's .d directory. Query only Id, FragmentPath, DropInPaths,
ActiveState, SubState, UnitFileState, MainPID, KillMode, KillSignal and
TimeoutStopUSec. The original six-minute stop allowance is preserved; this
inventory never performs a stop.

For Pocket, the exact units are openclaw-gateway.service and
openclaw-authbus-restart-when-idle.service. Their held-cohort drop-in filenames
and both full hold marker paths are in the JSON. Read the marker and original
source map for provenance; do not turn automatic_release_permitted=false into
permission to delete it, nor broaden its legacy provider conditions into a new
unrelated feature gate.

The exact client configurations are each known home's .openclaw/openclaw.json.
Their four connection keys and existing flags are projected alongside whole
original hashes. The three credential files remain
 .openclaw/credentials/authbus/{ca.crt,role_id,secret_id}.
Only paths, private-owner metadata and digests go into public inventory output.
No role/secret/token value or raw environment is printed.

The five Mac and six ROG database paths come from the whole published observation;
the two Pocket agent paths come from its approved current harness. Initial reads
are lstat/sidecar-existence only. Do not let mode=ro SQLite establish a missing
SHM file. A later exact-row read or snapshot would use a separately reviewed
stable-source/sidecar contract and does not follow automatically from this plan.

All six plugin cache paths are explicit: applied-profiles, publish-baseline,
bad-refresh-quarantine, refresh-backoff, lease-epochs and status under each
host's .openclaw/authbus. Preserve exact absences as well as present bytes.

Only the exact service/container PIDs may be inspected if necessary to bind
registration to a live consumer. Container inspection is limited to exact IDs
recovered from the matrix, with safe mount/command-source/restart/state metadata
projection and no secret environment values. Missing ports, no currently mounted
volume, an inactive process, or a disabled unit is not deletion authorization.
There is no docker exec/start/rm/prune, broad process command-line dump, recursive
HOME/root scan, SDK import, credential refresh, or provider call.

## 4. Backup and recovery closure

Start from the recovered matrix's declared backup and startup paths. Read the
actual command/config/manifest reference before resolving an exact destination.
Project encrypted archive owner/mode/size/version, the manifest's existing
digest, generation/cluster identity, key-custody reference without key content,
and the scope of native-user, SDK, raw auth rows, six caches, old client
connection files, and coordinator owner state.

Do not hash or transfer an arbitrarily large archive in the small metadata
window. If whole archive verification or restore is needed, bind the actual size,
single explicit path, original custody and a separately reviewed owned restore
intent. An old ciphertext hash is not a recovery proof; a KV-only snapshot is
not a complete backup of independent native-user identity or coordinator owner
state. Pending coordinator journal and KV history must be paired under its
actual two-lock recovery contract.

Production cutover remains per host: actual final local TLS/CA/AppRole and
supervisor binding, a stopped fresh private baseline, exact forward configuration
CAS, actual installed first cycle and cold restart, one strict inverse from its
committed checkpoint, and a proven backup/recovery path or explicitly reviewed
retirement. An inverse must not overwrite an independently refreshed generation.
Its unknown CAS is never automatically replayed. Restoring the old J3160
configuration does not certify that the old endpoint became reachable.

None of this invents provider quota recovery or login to an unselected historical
identity as a prerequisite for faithful HeptaBao credential migration.

## Primary source custody

The packet retains whole primary files from these fixed Git objects:

- QA commit682c063994c18e1dafc476f6affa4d25e7ff716f:
  AUTHBUS_MAC_ROG_CUTOVER_PLAN.md, source-observations.public.json,
  cutover-plan-r2.public.json and AUTHBUS_CURRENT_SOURCE_EVIDENCE.md.
- Validation commit1f5e1ee6e44de71d3d007589dc1b981bfb064a45:
  independent normal33 SDK314, installed-entry SDK330 and owned system-manager547
  root reviews. Their synthetic/real/manager scope is explicitly retained.
- Pocket R8 root review and the approved R10 source manifest remain separately
  pinned. R10 source approval is not a runtime result.

This read plan is ready for source review. It does not itself dispatch any of
the proposed host collectors.
