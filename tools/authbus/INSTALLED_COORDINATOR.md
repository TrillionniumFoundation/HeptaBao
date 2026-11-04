# Installed single-owner AuthBus coordinator

This entry binds the existing inbox/manifest coordinator to an explicit
production configuration and exact installation. Preparing its files does
not install a service, change a client, release a hold or enroll an account.

The existing `authbus_coordinator.py` CLI still requires
`production_cutover: false`. The installed entry requires true and reports
`production_configuration: true`. That result identifies the configuration
contract, not proof that production client traffic has switched. An isolated
qualification must retain its separate production-unchanged receipt.

## Existing protocol, explicit enrollment

The remote mount and protocol remain `openclaw-auth` and the original
inbox/manifest contract. This change adds no host-filter field, alternate
mount, provider alias, refresh scheduler or new approval protocol.

Each grant retains the exact existing seven fields:

- `authorizationId`, `profileId`, `sourceHost`, `provider`.
- `identityDigest`, `expectedCurrentDigest`, `nextDigest`.

Digest calculation remains the existing JavaScript-compatible canonical
implementation. Initial enrollment requires a null current digest. A
rotation names the actual current digest and the exact approved successor.
The original publication CAS consumes the grant. A timestamp, a newer
expiry, an inbox event or possession of a credential does not authorize it.

Current fleet scope is previously managed identities 1 and 2. Pocket's
independent local identity 5 and ROG's user-native identity 4 receive no
implicit grant. Original `publishNew` may submit their inbox events; without
an exact grant they remain deferred and do not enter the shared manifest.
No credential value belongs in a public result.

This owner never writes order-policy, scheduler assignments, refresh leases
or default models. Separately reviewed current-client planning uses managed
IDs in order [2, 1], `activeProfile: null`,
`enforceManagedOrder: false`, no enforced scheduler, and Pocket's original
two order exclusions. Actual Mac/ROG previews selected [2, 1]: [1, 2] changed
ROG zbj's inherited order. The ordinals in this document are explanatory;
final private files must contain the exact verified profile IDs/digests.

## Binding and create-only preparation

`prepare-state` creates a new mode-0700 owner directory, the mode-0600
owner/source anchor, and original operation/service locks. Its parent must
already be owned and mode 0700. Existing state is not adopted or repaired.
A partial preparation is retained for explicit review.

`prepare-service-file` creates the exact proposed unit from the true
configuration and final absolute code, state, binding and pin paths. It has
one ExecStart, running only `service serve`, and no administrative hooks.
The generated unit must be reviewed before installation. Paths containing
whitespace, shell syntax or systemd percent expansions are refused.

`prepare-binding` requires exact config and service-file byte hashes and
checks the service bytes against that generated command contract. It binds:

- Exact host name, effective UID, unique owner UUID and finite source-host list.
- HTTPS endpoint and actual peer DER certificate digest.
- Actual entry/core, config, CA, RoleID and SecretID paths and byte hashes.
- Original owner directory and both lock device/inode/UID/mode identities.
- Exact owner/source anchor and exact service file.
- The absolute path of the private activation reference.

The unit loads a separate mode-0600 `binding-pin.env` containing only
`HEPTABAO_BINDING_SHA256=<64 lowercase hex>` and a newline. Its fixed
ExecStart passes that variable as the externally expected binding SHA.
The binding pins the whole unit and the activation-file **path**. Once the
binding SHA is known, preparation creates the activation file with exactly
that value. Every invocation verifies its entire content equals the external
SHA. Thus the hash graph is acyclic; there is no normalized digest slot or
unbound second command in the service file. Both files are create-only.

The activation file is an explicit local trust anchor, not a credential.
Changing it, the binding, source, role material, config, service file or
original lock makes an active instance stop before further operations.
The generated unit protects code/config/home read-only and permits writes
only to its state directory. It explicitly uses `PrivateUsers=yes`: the
per-user manager needs a user namespace to apply its filesystem namespace
restrictions. Actual manager support still requires host qualification,
including the process's user namespace, mount flags and effective readonly
filesystem flags. A declared `ProtectSystem=strict` value alone is insufficient.
If the kernel or AppArmor denies this namespace, retain that failure; do not
remove the restriction or change a host-wide security setting to start it.

### Explicit manager and nonroot identity

The true config must include `service_scope` with exactly `manager`, `user`,
`uid`, `group` and `gid`. The manager is `user` or `system`; all four identity
fields must match the actual operator. System scope refuses UID or GID zero.
The installation binding records this exact scope, and verifies it again at
runtime. A service cannot silently switch to a different account or manager.

System scope emits explicit `User` and `Group` directives. The coordinator and
all one-shot operator/API commands still run as that nonroot user. Only the
manager performs privileged namespace setup. Its actual registered unit is a
root-owned regular file with root GID, mode 0644, and a pinned complete digest,
device and inode, under `/run/systemd/system` or `/etc/systemd/system`. The
service user cannot rewrite it. User scope retains an owner-owned mode-0600
unit and also pins its custody. Same-byte inode replacement is a binding error.

The disposable system qualification uses `authbus_system_unit_runtime.py`
only as an externally pinned inline operation. Its whole input program and
the two exact unit/proposal paths are fixed by the reviewed run plan. Root
never imports code from a service-writable Python file. The helper opens
ancestors and the target parent with directory file descriptors and
`O_NOFOLLOW`; installation uses `O_EXCL`, root:root 0644 and fsync. It never
starts a process or reads an AppRole/credential file. Removal requires the
same exact unit SHA and observed device/inode after the driver proves its
manager has stopped it. It accepts no arbitrary source path or unit name.
It creates only fresh runtime QA units; it is not an unattended installer or
permission to modify a permanent production unit.

The driver retains the original inode identity returned by installation.
Cleanup must compare against that original receipt; it cannot authorize a
same-byte replacement by observing a new inode. A missing/lost installation
receipt remains a separate reconciliation condition. While the helper still
holds its original newly created descriptor, a write/chown/chmod/fsync/readback
failure may remove only that same named inode, before binding/start, and fsync
the parent. Its structured failure receipt records whether this self-cleanup
completed. An outer kill or incomplete cleanup remains unknown even if a later
path observation looks empty. The helper does not re-install or re-delete on
an unknown result.

User-manager and system-manager results are separate qualifications. The
X230 user-manager attempts retained an actual writable code/config mount
even with a distinct private user namespace. A later system-manager pass
must not relabel those failures as successful user-manager hardening.

The system qualification's separate `authbus_owned_proc_runtime_observer.py`
is read-only. Its externally pinned source and fixed run plan restrict it to
the original root-owned unit, exact cgroup, PID/start time, executable and
expanded argv. It holds a proc-directory descriptor and rechecks those
identities before returning. It reads only status/mount metadata and uses
`O_PATH` plus `fstatvfs` for the three exact code/config/state paths. It never
reads the target environment, credentials, file contents or memory. Sudo
policy and observation share the remaining original start deadline (12s)
with the original manager-command ceiling (15s). This observer addresses a
permission boundary in the nonroot observer; it does not alter service
permissions or replace a failed filesystem assertion with declared settings.

The core's optional `lock_factory` lets this entry use an existing-only,
identity-bound original lock, without O_CREAT. Candidate callers retain
their original behavior. A separate original service lock is held throughout
the service lifetime. That excludes another local service using the same
installation; it is not a distributed owner lease.

## Service versus operator commands

| Entry | Scope | KV writes |
| --- | --- | --- |
| prepare-state | New private owner directory, anchor and locks | None |
| prepare-service-file | Exact unstarted service bytes | None |
| prepare-binding | Exact installation and activation reference | None |
| service serve | Original bounded inbox scan and event recovery | Only original grant-authorized CAS operations |
| service recover | Original event journal/history and receipt recovery | Original recovery, never administrative replay |
| operator inspect | Current manifest version/digest and pending indication | None |
| operator initialize | Original empty manifest CAS0 | One recorded CAS |
| operator authorize | Original exact grant append | One recorded CAS |
| operator revoke-authorization | Original exact grant removal | One recorded CAS |
| operator reconcile | Classify pending admin CAS from its original immutable version | None; local completion only |

Inspection/reconciliation can still cause AppRole authentication or renewal
through the original client. A GET wrapper is not proof that no authentication
POST occurred. Unknown login/renewal outcomes retain their original
classification and must not be automatically retried.

Every runtime command requires the external binding path and SHA. Authorize
and revoke require the exact mode-0600 grant file plus its byte SHA. Each
administrative mutation requires a fresh expected manifest version and
canonical digest. Initialization accepts only version 0 / literal `absent`.
A head mismatch stops before dispatch; the original CAS also closes the race
after the read. Revoke rejects a different grant body using the same UUID.

The generated supervisor uses `Restart=on-failure` and
`RestartPreventExitStatus=2 3`. Definite failure and unknown results both
stop it. It cannot invoke initialize/authorize/revoke. A process crash can
restart serve, which enters original event recovery before another scan;
an existing administrative pending journal blocks all service processing.

Known owner-busy, input/pin drift, expired bearer, TLS/ACL denial or read
transport failure is not permission for a tight supervisor retry. Diagnose
and satisfy the exact precondition, confirm original state/credential custody,
and explicitly restart/recover. For administrative unknown, use explicit
operator reconciliation. Never remove a journal to make a service start.
Read-transport errors that were caused by an unknown authentication mutation
remain unknown.

## Durable administrative dispatch

The installed entry wraps the original administrative methods. Under their
original operation lock, it fsyncs an intent containing the exact desired
manifest, expected version/digest, grant-file hash, owner/source anchor and
original installation SHA, then a dispatched phase before sending once.

Only one manifest CAS is allowed. If an original event receipt still needs
completion, perform explicit service recovery first; an operator operation
cannot silently perform that other write before its pinned administrative CAS.

A confirmed response or known CAS/ACL/pin rejection is durably archived
before pending is removed. A crash between those local steps requires a
matching completed record. An unrelated completed file cannot clear an
unknown. Failed archive/fsync after dispatch, or a malformed successful
reply/version, is reported as unknown with exit 3 while dispatched intent
remains. A repeated mutation and a service cycle are both refused.

The same conservative classification applies to the original event journal's
manifest-dispatched/confirmed phases. An unreadable existing pending journal
is unknown. Results distinguish operator reconciliation from original service
recovery; a post-commit service error cannot be labeled a known rejection.
The original prepared phase may already have dispatched an immutable profile
CAS. It is conservatively unknown on failure, while the result separately
states that the event manifest has not been dispatched. Original recovery
retains immutable leftovers and resolves the manifest's not-dispatched state;
it does not invent an absent profile write.

Explicit operator reconciliation reads expectedVersion + 1:

- Exact desired canonical body confirms the requested manifest state.
- A different immutable body occupying that same CAS slot proves this request
  did not occupy it; it is not resent.
- A head not yet at that version, or deleted/pruned history, remains unknown.
- A completed response archive is also checked against the same remote
  history before completion is closed.

Reconciliation performs no KV mutation. It may fsync a local resolution and
remove local pending. A new operation after a known rejection needs a fresh
head, reviewed grant and explicit invocation. Missing history never authorizes
a replay.

## Concrete proposed ROG owner layout

The following are new proposed paths under the existing ROG user. Their
existence or activation is not asserted:

- Code: `/home/qian-qi/.local/lib/heptabao/authbus-coordinator/20261104-r1/`.
- Config/CA/RoleID/SecretID/binding/pin:
  `/home/qian-qi/.config/heptabao/authbus-coordinator/`.
- State: `/home/qian-qi/.local/state/heptabao/authbus-coordinator/`.
- Unit: `/home/qian-qi/.config/systemd/user/heptabao-authbus-coordinator.service`.

A dedicated writer AppRole and exact policy must be assigned to this single
owner. The old canonical writer must be stopped/fenced and excluded before
activation. Local locks cannot exclude a surviving remote writer. Do not
reuse client roles as the publisher or copy the writer role to a second owner.

The true config retains the original schema and fields: owner_id,
source_hosts, state_dir, address, server_certificate_sha256, ca_file,
role_id_file, secret_id_file, request_timeout_seconds=10 and
poll_interval_seconds=15, and adds the explicit `service_scope` described
above. If ROG uses system scope, the actual unit is instead a root-owned
`/etc/systemd/system/heptabao-authbus-coordinator.service`; its process user
and all configuration/state paths remain `qian-qi`. That is a proposed layout
until the host's actual manager qualification and reviewed installation.
The final endpoint/CA/certificate and current source
generation must come from actual qualified server/source evidence. No guessed
address, candidate token, fixture profile5 or placeholder is a production default.

## Executable initial installation sequence

All preparation is create-only. Commands below name the entry operations;
substitute only the exact reviewed paths, hashes and actual captured values.
No command may be looped on unknown.

1. Qualify the final normal HeptaBao target/TLS, KV2 history retention, source
   AppRoles and dedicated writer policy. Bind actual server/build and
   old-writer exclusion evidence. Client addresses are unchanged.
2. Stage reviewed immutable code and private true config/CA/role material into
   the new layout. Keep the unit unstarted. Record source bytes and identity.
3. Run `prepare-state --state-dir <exact state> --owner-id <actual UUID>
   --source-host mac --source-host rog --source-host pocket4`. Preserve its
   original owner/directory/lock receipt.
4. Run `prepare-service-file --config <exact config> --config-sha256 <SHA>
   --binding <new installation.private.json>
   --activation-pin-file <new binding-pin.env> --output <private proposal>`.
   Read/review the complete generated unit and returned SHA.
   In system scope, install those exact reviewed bytes once as the actual
   root:root 0644 unit, with create-only target, original inode receipt and
   parent fsync. The nonroot operator does not write the system unit itself.
   Keep it unstarted; the binding and activation files do not yet exist.
   The disposable QA helper is limited to its two fixed runtime paths and
   is not a general permanent-production installer.
5. Run `prepare-binding --config <config> --config-sha256 <SHA>
   --service-file <actual registered unit> --service-file-sha256 <SHA>
   --output <new installation.private.json>
   --activation-pin-file <new binding-pin.env>`. Review the returned binding
   SHA and activation file; every later call uses that exact pair.
6. Run `operator inspect --binding <binding> --binding-sha256 <SHA>`.
   For a truly absent manifest only, run exactly one
   `operator initialize --expected-manifest-version 0
   --expected-manifest-sha256 absent` with the same binding arguments.
   An existing manifest requires reviewed migration; never wipe it.
7. Derive each approved initial grant from the exact immutable source event.
   Inspect the current manifest and run one `operator authorize` with
   `--authorization <private grant> --authorization-sha256 <byte SHA>
   --expected-manifest-version <N> --expected-manifest-sha256 <canonical SHA>`.
   Do not automatically authorize all discovered inbox credentials.
8. After actual isolated entry/service qualification, perform the reviewed
   manager reload/readback and start of the exact already installed unit.
   Check immutable profile, grant consumption, manifest
   generation and original coordinator receipt. Capture the paired backup
   before each client's reviewed config CAS/restart/rollback transition.
9. Later enrollment, rotation and revocation use the same explicit operator
   contract. Unknown is reconciled by history, not retried.

## Paired owner and KV restore

A current manifest alone is insufficient. Preserve the matching recovery set:

- Exact code/config/binding/activation reference and current writer provenance.
- Original owner/source anchor and both lock files.
- All pending/completed event journals and the original inbox scan cursor.
- All pending/completed operator journals, including original dispatch
  installation SHA, intended CAS body and grant-file hash.
- The full required remote KV state/history: manifest generations/grants,
  immutable profiles, original inbox events and coordinator receipts.
- Actual HeptaBao snapshot/import/build and owner-state backup receipts.

Capture requires quiescence of both the service and administrative writer.
Hold the original service lock and original operation lock throughout owner
file capture and remote KV snapshot creation, until both copies and their
receipts have been fsynced. A matching manifest before/after is insufficient:
scan cursors and observed receipts can change without a manifest change. The
actual server snapshot must use its consistent snapshot contract. If source
inbox producers are not paused at the same barrier, document the snapshot's
inbox RPO and retained source delivery evidence; do not claim zero-loss paired
capture. No backup tool should silently create replacement lock files.

Stop/fence the old owner. Restore the complete captured owner bytes under a
new private directory and restore the corresponding remote snapshot/history.
Do not regenerate an owner UUID or discard pending records. Prepare/review
a new installation binding for the real path/inodes/host/credential generation;
the old binding must fail against replacements. Pending administrative recovery
accepts the unchanged owner/source anchor across that explicit rebinding while
retaining its original installation SHA as provenance. It still checks the
original CAS history.

Run explicit operator reconciliation if pending, then original service
recovery. A missing historical generation or inconsistent remote restore stays
unknown. Only after both journals/history and the actual finite client scope
are verified may the owner run continuously. A host migration is not automatic
publisher HA; old-writer exclusion is independent evidence.

## Qualification scope

The installed contract suite uses real private files, fsync and locks, actual
core methods and a synthetic KV boundary. It proves binding/command/CAS/unknown
contracts; it is not production service, provider, real TLS or full backup
restore evidence. The initial state-copy test rebinds actual local owner files
against existing synthetic KV history, rather than claiming a live paired restore.

The real qualification must use the final pinned entry, normal server and the
original live SDK producer/follower under their original budgets: initialize,
explicit grants, ungranted identity deferral, plugin consumption, owner crash/
cold recovery, token renewal/revocation, unknown-CAS/history reconciliation,
and complete owner plus real KV restore. Every failed attempt remains separate.
Each host still needs its finite reviewed config/restart/rollback qualification.
No old asset is deleted by this entry or this preparation.

### X230 normal33 system-manager result

The executed fresh `live-system-r5` completed **547/547** checks with full
owned-process and runtime-unit cleanup. The byte-exact public result is
`qa/openbao-acceptance/evidence/authbus-installed-coordinator-20261104/system-r5-result.public.json`,
SHA256 `fef3c0905dc90c2a30975cb5f0b3714e60624b69d532ad2fffc4c87de8720f0b`.
It binds normal server commit `33cafa4c6e29f0bde1553e041550d21b4c725d9c`,
binary SHA256 `7dc5bc5157d62fd92e8cb10f1270f9ea776a929fde77a87eeb284509e82f1bba`,
entry SHA256 `16204429b78d370e58aa1332aa17ae1a295eae94e59bceb08c9144d7e991891b`
and core SHA256 `eaf83832144e7ecf1f369ec91007b0d8b4dc55f59342f3ce27ca64a4aea6f76d`.

This execution used `native_v6_file` and the formal
`sys/storage/native-v6/activate` route, with no fixture command-line option.
Five actual service-process observations verified UID/GID 1000, exact
argv/executable/cgroup, stable PID/start identity, NoNewPrivs and a distinct
user namespace. Both code and config were read-only in mountinfo **and**
`fstatvfs`; the bound owner state was writable. The two root-owned mode-0644
unit files were removed only with their original installation inode receipts.

Under both original locks, with the service and fixture producers quiescent,
the test captured all nine owner-state files and a real KV snapshot. It
restored that snapshot after an observed later mutation, SIGKILL/waited and
cold-unsealed the normal server, then recovered the original
`manifest_dispatched` journal in a new bound unit. Recovery preserved the
original manifest generation and did not replay its CAS. Snapshot SHA256 is
`4c844fca98d72804f50128a7019c4df478cc9b81b98fe765a1ea39d3fe0f5164`.

The actual manager also retained stopped exit-2 and exit-3 outcomes beyond
RestartSec, with no automatic restart. The exit-3 case followed an actual
successful manifest CAS and an injected local reply-validation error;
explicit read-only history reconciliation confirmed it before revocation
and rearming. This deliberately exercised an unknown boundary; it is not a
claim that no unknown state was encountered.

Earlier attempts remain separate evidence:

| Attempt | Actual boundary | Cleanup |
| --- | --- | --- |
| user r1 | Reset of a fresh inactive unit was rejected before service start | Original failure retained; independent exact cleanup receipt |
| user r2 | Actual filesystem-readonly gate failed | Complete |
| user r3 | Distinct user namespace, but code/config remained writable in both observations | Complete |
| system r4 | Nonroot `/proc` observation hit PermissionError; no filesystem conclusion | Complete |
| system r5 | Actual root-owned system unit, nonroot worker and paired restore passed | Complete |

The result uses synthetic OAuth data and makes no provider calls. It
explicitly does **not** test an installed SDK producer/follower, current
provider-account availability, ROG's manager, production traffic or user-unit
hardening. Those have separate evidence and gates. No production configuration,
hold, credential store or legacy asset changed.
