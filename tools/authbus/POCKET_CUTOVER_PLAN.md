# Pocket4: reviewed transition and exact reverse operation

This is a preparation document. No production configuration, unit, hold,
credential store or old asset is changed by it. The finite subject is the
registered Pocket4 gateway, its installed AuthBus consumer and its registered
idle-restart helper. The two current default agents are `main` and
`tg8687951891`; both currently select local identity 5. User-scoped Codex
identity 4 remains a separate local consumer.

## Fixed current inputs

The source configuration is `/home/alex/.openclaw/openclaw.json`, SHA256
`3611380b8c77282e785e00e20d9eba8bc8cf0164b3b3f00e2ea5d1f52a441c98`.
The current four AuthBus connection fields are under
`plugins.entries.openclaw-authbus.config`:

| Key | Current | Proposed new generation |
| --- | --- | --- |
| address | `https://100.66.117.33:8200` | `https://192.168.0.9:8200` |
| caFile | `/home/alex/.openclaw/credentials/authbus/ca.crt` | `/home/alex/.openclaw/credentials/authbus-heptabao/20261104-r1/ca.crt` |
| roleIdFile | `/home/alex/.openclaw/credentials/authbus/role_id` | `/home/alex/.openclaw/credentials/authbus-heptabao/20261104-r1/role_id` |
| secretIdFile | `/home/alex/.openclaw/credentials/authbus/secret_id` | `/home/alex/.openclaw/credentials/authbus-heptabao/20261104-r1/secret_id` |

The proposed endpoint is a concrete deployment target, not an existing qualified
listener. It requires the final qualified HeptaBao normal binary, its actual
192.168.0.9 leaf certificate and the reviewed fleet CA. Pocket generates its
own leaf private key/CSR locally; the private CA authority remains at the Mac
authority. No fixture certificate, fixture replication key or fixture port
46230/46231 is a production input. The client CA/AppRole files are staged
create-only in the new private generation; the old files remain available for
an exact reverse operation.

All other configuration fields retain their original values. In particular:

- `leader=false`, `publishNew=true`, `manageOrder=true`, `hostId=pocket4`.
- `orderExcludeAgentIds=[main,tg8687951891]`, 15000 ms polling,
  900000 ms refresh margin, and one maximum refresh per cycle.
- Existing shadow scheduler/default lease behavior, model/runtime selection,
  Codex agent home scope, every local identity, profile order, usage and
  last-good state. `releaseGeneration=202` is informational and is not a
  release authorization.

The shared manifest enrolls only the previously managed, verified identities
1 and 2 with exact grants and credential-generation digests. Its non-enforced
order policy uses `[2,1]`, `activeProfile=null`, and no enforced scheduler.
Pocket's two exclusions remain in force. Identity 5 is not granted admission
to the shared manifest. Original `publishNew` may submit its event to Pocket's
authorized inbox; the coordinator must defer it without a matching grant.
No baseline is fabricated to suppress that original behavior.

## Exact installed and held entries

The gateway unit is
`/home/alex/.config/systemd/user/openclaw-gateway.service`, SHA256
`6fda457a5c62fe4a8d9665602bf288b377eddf17af9d2426f4efbea10a2be457`.
Its observed state is enabled, inactive/dead, PID 0 and empty cgroup. The
registered helper is `openclaw-authbus-restart-when-idle.service`, static and
inactive. Its script is
`/home/alex/.local/bin/openclaw-authbus-restart-when-idle`, SHA256
`a078be050dbb132b3a2a5c3c3d7d29096e32f4aea42612579b5f92c2f1c26be7`.
It waits for three idle observations and then restarts the gateway; it has no
separate Bao endpoint. The current gateway environment file is
`/home/alex/.openclaw/gateway.systemd.env`, SHA256
`63056507acfe0e81992f6d87cb76ece97792c4dd29e609bcb6c65d9992be53ad`.
No environment values belong in public receipts.

Both hold markers live below
`/home/alex/heptabao-authbus-persistent-guard-hb3-r1`:

| Held entry | Original marker basename | Marker SHA256 |
| --- | --- | --- |
| Gateway | `hold-0dcbd843db6bbaf3fb0fdab97ae4775029d63660a7365b8da5b498385917c5e5.json` | `0fccbd0c976d259d01b359c3fd7e82552d182a656eb0af44faac89a863ceef9d` |
| Idle-restart helper | `hold-89902581f0d98cb21706f6dfdb9e879d2d6dffc7b8f4f3f4a9c654645f9624a1.json` | `370fc76cad249542b4b73763909fb546624071a4febd437501aa3a3b543cabc4` |

Their drop-ins use negative `ConditionPathExists` checks. The original plan
is `plan.private.json`, SHA256
`d21ff06e72e0769e16d3dc1a78b8ebfe409c255c09577269bde9f40b3270c4dd`;
the original lock is the existing file `lock` in that guard root. Its existing
inode must be opened without `O_CREAT`, with the original identity checks.
The source package is
`/home/alex/heptabao-hb3-linux-inhibition-stage-20261023-r1`, with fixed source
map SHA256 `749d63b4590fe5a2ea51444f6cff6fc453ffd7a8948b98c7203c1282c8bd381c`.

The original plan says `automaticReleasePermitted=false`; its installer has
observe/install/reconcile operations and no release operation. A new explicit
transition must therefore record the release decision and exact prerequisites.
It must not change that old flag, reset `ConditionPathExists`, manufacture a
ready marker, or treat the filename alone as permission to start the gateway.
The previous original-lock reconciliation passed without modifying the hold;
its receipt SHA is `2544dd36aeeb9e3627f460dc8a9ee884cc79f6b8ce2a33ca14c8d3138cb9cadf`.

## Admission before any production write

1. Bind the final normal server/build, both required HA directions, final
   listener certificate, CA and replication peers. Establish actual TLS,
   AppRole permissions and current managed credential-generation evidence.
   The initial target manifest/grants and the unique coordinator owner must
   be qualified together with owner-state/KV paired recovery.
2. Prepare the four-field configuration candidate from the exact current file.
   Require both the original whole-file SHA and a structural comparison proving
   that those four fields are the complete difference. Prepare private new
   credentials and the inverse operation without overwriting existing files.
3. Run a faithful isolated first-cycle rehearsal using this original installed
   plugin, both agents' complete current effective/local stores and original
   six cache files/absences. Use shared manifest 1/2 and original flags, not the
   earlier isolated manifest-5 fixture. Prove main and tg still select identity
   5, local identity 4 remains intact, and any inbox event for 4/5 stays deferred.
   Preserve exact native factory selection, normal server cold restart, logical
   and raw two-table CAS rollback and the original time budgets. No provider
   model request or new OAuth refresh is needed for this rehearsal.
4. Capture the current finite Pocket generation: exact config and new/old
   connection files, both agents' auth rows and state, effective inheritance,
   known six cache files/absences, independent native auth/config, both original
   holds/drop-ins, original lock identities, and installed code pins. Use the
   existing reviewed encrypted off-host transport/restore contract with this
   new generation; do not label the November 3 capture a current backup.
5. Re-run the original bounded hold reconciliation and current source barrier.
   Verify the gateway/helper are still inactive with empty cgroups and all
   expected file/database generations match. Any changed source needs a new
   explicit comparison; it is not overwritten by the old snapshot.

The completed two-scope native assessment
`current-native-two-scope-assessment-r1.public.json`, SHA256
`9f7a9ee41ea0bcfd1246380c438161989163086810ce190a8ce7f1b99461315b`,
already proves actual identity-5 native consumption, normal-entry cold recovery
and strict rollback for its full/missing-5 fixture scopes. It is not by itself
the four-field production first-cycle or a release of the original holds.

## Single-host transition and reversal

Create a new private transition journal before dispatch. Every action records
its expected input identity/hash, one dispatch, observed result and durable
receipt. Unknown service/config outcomes are reconciled from the exact files,
PID/starttime/cgroup and manager state; they are not blindly repeated.

The gateway's explicit release should preserve the original marker's inode:
after the original lock/barrier and all admission checks succeed, rename that
single marker to a new transition-owned archival name on the same filesystem,
then fsync both directories. Retain its bytes, owner, mode, device and inode.
Keep the drop-in and original plan unchanged. The helper marker remains held
through the gateway's first restart and reverse-operation qualification. This
is a proposed operator release action requiring the reviewed transition
journal, not automatic release by the coordinator or plugin.

Apply the exact four-field config CAS while the gateway is stopped and preserve
the old file generation. Start only the existing registered gateway once.
Read back actual manager source/drop-ins, PID/starttime, readiness, the first
AuthBus cycle and both real default selectors. Confirm current local identity
5, the independent identity-4 source and the intended managed 1/2 generation.
An explicit second restart must reproduce the same selection and state from
the new target. Do not replace an actual post-start authentication generation
with a stale baseline merely to make a rollback compare equal.

The inverse operation first restores the original gateway hold by renaming the
same archived inode back under the original lock and fsyncing both directories.
It then stops and waits for this owned gateway invocation, confirms its empty
cgroup, and restores the old config/state only through exact expected-current
CAS. Restore complete auth/state and cache shapes, including tg's original
primary metadata row with no local profiles; do not call its tables empty.
The pre-transition service state is inactive and held. Reversal restores that
state; it does not start an unavailable J3160 service. The separate native
identity-4 source must retain its original generation throughout.

After this reversible transition has actually passed, a new explicit final
activation may leave the gateway on HeptaBao. The helper's hold is handled as a
separate registered entry after its restart dependency and original ownership
are reconciled. There is no bulk release of all hold markers.

## Backup and deletion gate

The observed finite startup/backup registration scope found no separate active
Bao/AuthBus backup timer on Pocket. Historical encrypted captures remain
historical evidence, not proof that a new generation can be restored. Register
the actual new client/state recovery entry and the coordinator owner/KV paired
backup with their concrete paths, hashes, retention and restore receipts.

Only after all four machines' finite client/startup/backup entries are closed
may the old OpenBao/J3160 connection material and superseded HeptaBao service,
binary and regenerable assets be considered for cleanup. Retain compact
failure/pass provenance and the reviewed rollback/restore evidence. Existing
old assets, hold files and historical captures are not deleted by this plan.
