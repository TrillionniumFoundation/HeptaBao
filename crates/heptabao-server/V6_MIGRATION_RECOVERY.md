# Native V6 migration and recovery boundary

The opt-in `fixture-native-v6-service` writer now has a bounded publication
path for a populated V5 source. It remains a root-namespace, single-node
candidate with the existing file/barrier custody. This document does not
establish physical-host HA acceptance or authorize a client cutover.

## Migrating a populated V5 store

`POST sys/internal/native-v6/activate` is owned by the real Service request:
root Principal, original token clock and deadline, live barrier, and the exact
selected V5 source. The migration planner preserves the complete source KV2
history, metadata, soft deletion and destruction state. It also rekeys the
V6 object-address domain instead of reusing an earlier abandoned plan.

`service_native_v6_writer.rs::commit_native_root_plan` stages and reads back
immutable ciphertext through the actual file backend before registering
its private 72-byte journal locators. Object payloads remain outside the
application journal. When all locators and the final root fit in the existing
96-mutation bound, the writer retains its single atomic Apply behavior.

For larger candidates it registers locators in bounded batches. Every batch
keeps the exact original application root, absent active cursor and absent
retained V5 source as conditional preconditions. It retains the original
Actor/ACL/deadline gate at each physical append. The old V5 root remains
selected throughout this stage.

The generation-bound original object source session is dropped before any
locator batch. After registration, the writer opens a new source session at
the actual durable generation and authenticates the candidate's complete
typed graph from persisted objects. It then atomically publishes the V6 root,
active cursor and retained V5 source in one three-slot Apply. The cursor uses
the actual publication generation, while preserving the original source
generation. A final durable read verifies the committed root, cursor, source
and complete graph before installation in Service.

## Interrupted staging and a recoverable V5 snapshot

If a locator batch commits but activation stops before the root Apply, cold
opening continues to select the original V5 root. An unknown append result
fences the live Service until it is reopened. A fresh migration must prepare a
fresh plan; an expired Actor or a generation-bound source session is not reused.

Generic V5 `HBB2` backup intentionally rejects registered external locators.
Omitting ciphertext while retaining its locator would produce an incomplete
backup. A **new, authorized root snapshot download** can repair this specific
interrupted migration state before exporting an ordinary V5 archive.
`service_native_v6_staging_repair.rs` requires all of the following:

- The configured candidate still has an actual `RecordsV5` root whose exact
  durable bytes, epoch and identity match the admitted request.
- The current complete V5 graph authenticates against the selected Service
  state. Its object resources occupy a different domain from V6 resources.
- The active V6 cursor, retained active-source root, experimental side root
  and side publication cursor are **all absent**. Any present pointer, including
  an unfamiliar or malformed one, prevents repair.
- The original snapshot Principal is root, the namespace is root, and its
  original clock, deadline, unseal nonce, physical seal and source identity
  remain valid at the append boundary. HA and alternate storage profiles
  remain excluded.

Only private locators in the current cluster's exact known format are selected.
Each deletion batch contains at most 91 entries: five exact root/absence
conditions plus each locator's exact prior value fit the 96-condition bound.
The helper deletes **only journal locator metadata**. It never removes or
rewrites a physical `.hbo` ciphertext file, changes the V5 root, or changes
V5 history and owners. Partial known progress can be retried by a new snapshot
request. An unknown durable outcome requires reopening before another attempt.

The resulting V5 archive restores through the existing authenticated V5
materializer and seal path. It does not require the abandoned physical V6
files. A newly prepared activation can then migrate the restored V5 store.
Unconfigured profiles, unknown locator formats and stores with any retained
V6 side/active pointer retain the existing fail-closed backup behavior.

## Active V6 backup and restore

The existing native `HBV6PK01` transport includes the authenticated core state
and every registered external ciphertext object, including registered objects
that are no longer selected by the current root. Export authenticates the
full current typed graph and actual ciphertext under the original snapshot
authority. Restore authenticates the incoming archive and materializes its
typed graph against the actual target seal before publication.

Copying root JSON, a journal or `.hbo` files alone is not a completed restore.
The Service must accept the authenticated archive and its graph, then reopen
successfully with the configured candidate profile and real unseal path.
Physical files left by aborted staging are deliberately retained; this
metadata repair is not general object garbage collection or old-service cleanup.

## Focused regression evidence

`service_native_v6_migration_tests.rs` exercises two actual Service workflows:

1. A populated V5 store with 112 distinct KV2 entries and retained four-version
   history, including a deleted version, a destroyed version, CAS-required
   metadata and custom metadata. The prepared plan must contain more than
   96 actual objects. Activation must use multiple journal generations, retain
   the exact history, cold reopen the same native root and enforce later CAS.
2. A real first locator Apply loses its acknowledgement **after** file append
   and fsync. Cold recovery must retain V5; generic export must refuse the
   external locator. A new root-authorized snapshot repairs metadata while
   preserving every physical ciphertext hash and the V5 identity. The archive
   restores to a separate same-seal V5 target with no `.hbo` files, then supports
   a fresh activation and native cold reopen with the original history.

These tests must be executed with the feature enabled. Their presence alone
does not constitute a passing result or real-host acceptance.

## Experimental shared-key HA object adapter

The separate `experimental-native-v6-ha` feature introduces a ciphertext
adapter; it does not remove the Service's native-HA admission guard.
`ha_v6_native_codec.rs` uses the existing, actual `ClusterStateCodec`
replication key. A node's local Shamir barrier key remains local. The single
native cluster binding is SHA-256 over
`heptabao.native-v6.replication.cluster.v1\0`, the configured cluster ID's
four-byte big-endian UTF-8 length and its exact bytes. Enrollment, intents
and the codec use that same digest. The actual replay epoch is preserved,
including zero; no synthetic epoch increment converts one identity to another.

Object encryption uses independent random AES-256-GCM nonces. Its AAD binds
the frame version, configured cluster, native cluster digest, replay epoch,
the concrete owner role or KV2 namespace/mount/incarnation, and the complete
typed `ObjectRef`. Encryption never substitutes for the root-derived typed
object MAC. The actual V6 materializer verifies that MAC and the full
owner/KV1/KV2 graph on both preparation and recovery.

A full native payload block is 256 KiB plus 25 bytes of record framing.
After encryption it is split into two bounded transport leaves. Every
external leaf stays within the existing 25-byte to 256-KiB runtime bound.
An authenticated encrypted directory maps the root's domain ordinal and
complete typed reference to its ordered ciphertext leaves. Directory pages
and their index are also external encrypted objects. Their AAD additionally
binds the selected typed root digest, actual enrollment digest and page ordinal.
The small root frame binds the complete canonical intent and the one directory
index reference; its maximum is `MAX_ROOT_BYTES + 69`. The directory and large
payloads never enter the Raft application object journal or snapshot.

`service_native_v6_ha_objects.rs` records the objects read by
`materialize_for_service`, using the private plan's new objects and the actual
generation/barrier-bound `NativeSource` for retained history. Only a successful
complete typed read can produce its opaque `PreparedNativeV6HaObjects`.
All object writes use the checked no-replace file and directory fsync path,
and the prepared result retains the original request deadline. Converting it
to a root proposal consumes the preparation. An earlier authenticated
ciphertext mapping can be reused only after current-key decryption and exact
plaintext/reference equality under the same concrete domain and replay epoch.

Cold opening accepts an opaque `NativeV6PublishedRoot` and committed
enrollment. It reopens only that root's actual persisted external manifest,
then requires exact set equality between its references and all directory
pages, index and referenced data leaves. Missing, extra, changed or wrongly
bound objects fail closed. The Service materializer must subsequently use
every typed directory entry, including all paged historical payloads. The
returned owners/views remain detached. A checked visitor can supply their
freshly authenticated bounded plaintext to the target node's local-barrier
stager; it does not itself register locators or install an active root.

`native_blob_source::stage_verified_received` accepts only the visitor's
temporary opaque `VerifiedNativeV6Object`. Its private construction retains
the original Actor/deadline check; the receiving node's additional custody
gate cannot replace it. It checks the actual target cluster, replay epoch,
source session, generation and owner instance, seals with that target's local
barrier, and returns a 72-byte locator only after the real durable owner's
checked filesystem publication and authenticated plaintext readback. An
unregistered file left by an interrupted attempt can be reused after cold
reopen only if the actual file decrypts to the same complete typed object.
No root, cursor or locator journal entry is written by this primitive.

The adapter's regression target is actual Service creation of 17 distinct
2-MiB payload versions, real three-voter Raft root publication, a snapshot
smaller than 1 MiB, removal of the test's source Service storage, and cold
recovery from separately copied ciphertext directories using newly opened
codecs and consensus handles. Additional cases reject wrong keys/clusters,
missing ciphertext, incomplete typed plans, a revoked Actor gate, a changed
manifest and an expired original budget under a longer ambient request scope.
The same 34-MiB regression seeds a separate target with the complete original
V5 closure under an independent local barrier, then stages all cold-recovered
objects without changing that V5 root or generation. It drops and reopens the
target owner, retries without registered locators, and requires unchanged
ciphertext hashes. It also rejects the old owner session, a foreign store ID,
revocation inside the target's callback, and expiration before local staging.
This uses an in-process RPC router and synthetic enrolled pins, and is not
evidence of physical mTLS acceptance or native Service HA response delivery.
The test names are in `service_native_v6_ha_objects_tests.rs`; execution results
must be recorded separately before treating these regression targets as passed.

## Remaining integration limits

The OpenBao KV2 full-history bundle endpoint still imports through the legacy
KV2 owner path and its existing aggregate bound. Importing a full history
directly into an already active native KV2 graph needs a dedicated writer;
the current route fails closed for that destination. Migration of an existing
V5 store and direct native import are distinct paths.

The Raft runtime separately persists real V6 root CAS, membership/pin enrollment,
original intent provenance and external closure recovery under
`experimental-v6-raft-objects`. See `../heptabao-raft-runtime/V6_ROOT_PUBLICATION.md`.
The Service still excludes native V6 with HA. Its required bridge must bind
authenticated peer majority durability, typed candidate custody, original
Actor/clock, actual root CAS, fresh ReadIndex reconciliation, mandatory audit
and private response delivery. A local staging observation is not that proof.

Neither the migration tests nor runtime Raft tests establish Mac/ROG/Pocket4
network partition, production credential migration, client restart/rollback,
backup-path migration, or permission to remove legacy OpenBao assets.
