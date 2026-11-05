# V6 Raft root publication and external recovery

This feature adds actual durable Raft commands and a current V6 root to the
state machine. It remains under `experimental-v6-raft-objects`, default off.
The server's existing V6/HA exclusion is unchanged. No result here is an HTTP
or application credential acknowledgement.

## Persisted records

`EnrollNativeV6` commits a static mapping from the current Raft voter IDs to
distinct TLS leaf SHA-256 pins, the cluster digest and the application epoch.
The command is bound to the full actual membership LogId. It can only be
created through the trusted configuration-owner path; it does not establish
the provenance of arbitrary pins supplied by a network client. Once enrolled,
conflicting enrollment is rejected. This slice does not implement membership
or certificate rotation after native activation.

`PublishNativeV6` carries the already staged intent, its **original full applied
LogId**, the committed enrollment digest and one bounded opaque root envelope.
The envelope is limited to 64 KiB plus 256 bytes of encryption framing. The
state-machine apply path verifies the intent object and its original provenance,
checks the current exact non-joint membership against enrollment, and compares
the prior root digest, prior native generation and prior publication index.
It installs the root with the **actual** LogId assigned to this publication.
Conflicting proposals do not change the current root. Legacy and V5 writes are
fenced after native publication; retained V5 data is not returned as the current
application root.

The initial source must be a real published V5 root. The runtime records the
actual successful V5 Publish LogId. When upgrading an older V5 store lacking
that provenance, an explicit unchanged-root Publish must succeed before native
migration starts. No earlier log identity is guessed from `last_applied`.
Native generations form an independent consensus CAS sequence: migration is
0 -> 1 and each later native publication adds exactly one. They are not a
node-local store generation, snapshot generation or a V5 application's hidden
encrypted revision number.

The retained V5 source digest/LogId, current V6 root/LogId, original intent
LogId and committed pin enrollment survive ordinary state-journal replay and
snapshot compaction. V6 enrollment/publication requires snapshot and durable
bundle format 4. Default builds explicitly reject format 4 and non-null native
fields even if an input claims format 3. Ordinary V5 format 3 remains readable.

## External ciphertext and recoverable closure

`LocalV6BlobStage::persist_local_closure` reopens and verifies every selected
local ciphertext and publishes an immutable canonical `.manifest` using the
existing descriptor-anchored no-replace/file-fsync/directory-fsync primitive.
The caller's same gate surrounds every object, bounded manifest I/O and
publication barrier. Identical existing manifests are physically read back;
conflicting files are not overwritten.

The manifest contains `HBVCM001`, a big-endian u64 count, then strictly sorted
40-byte entries (32-byte ciphertext object ID and u64 exact length). It has a
131,072-object bound and a 5,242,896-byte maximum. The domain-separated closure
SHA-256 is the existing V6 closure digest, not a new incompatible hash. Neither
the manifest nor the external ciphertext enters a Raft command or JSON snapshot.
Only the root envelope and fixed intent/enrollment metadata are replicated.

`reopen_root_closure` accepts a `NativeV6PublishedRoot` returned by the actual
state machine; the public type has no constructor or Deserialize implementation.
It selects the exact committed manifest address and validates canonical order,
count, aggregate bytes and digest, then reopens and hashes every referenced
blob. It does not scan directories, adopt unreferenced objects, write to the
store or treat a valid-looking arbitrary manifest as a committed root. Missing
or changed data denies local activation without changing consensus state.

To move a replica, copy the committed manifest and exact referenced opaque blob
files to an isolated private target, preserve the native Raft state using its
existing recovery path, then call `reopen_root_closure` on the root read from
that restored state. File copying by itself is not a completed restore. The
service must also decrypt the root and validate its typed graph, namespace,
barrier/provider bindings and recovery floors before becoming available.

## Required service proof boundary

The runtime's publish method follows the same trusted application-writer model
as the existing V5 publisher. It does **not** turn a
`V6ReplicaCustodyObservation` into a majority-fsync certificate. Before the
server invokes it, its existing owner must retain these facts under one original
request deadline:

1. A fresh quorum observation selecting the exact committed enrollment,
   membership LogId, cluster/epoch, predecessor and original intent LogId.
2. An authenticated Actor/ACL and live barrier owner for the typed new root.
3. Complete local and receiving-peer closure manifests, each durably published
   after the exact ciphertext objects. Each peer receipt must bind its enrolled
   numeric voter ID and pinned leaf to the cluster, epoch, operation, intent,
   closure digest/count/bytes and enrollment digest. A majority must cover the
   same membership; separate loose node-name configuration is insufficient.
4. A final exact membership/owner check and the real root CAS. The CAS rejects
   membership or predecessor changes that occur during transfers.
5. After commit, a fresh quorum reconciliation of the actual publication LogId
   and root, local closure/typed graph checks and the existing mandatory audit
   and response-delivery checks. Timeout means an unknown result, not no effect.

The minimum practical service interface is an affine, non-serializable
publication context created by that owner and authenticated peer transport,
holding the original deadline, enrollment, intent and root digest plus the set
of peer fsync acknowledgements. It should be consumed by the service publisher.
The log stores the established root decision, not caller-provided pretend
signatures. A crash-fault Raft deployment with trusted static operator enrollment
does not need a new BFT signature framework. It does need authenticated peer
identity and durable receipt handling. Leader changes require reopening or
fetching the committed closure before serving; a missing local blob cannot be
excused by possession of the Raft snapshot.

## Tests and interpretation

The new integration test uses three actual durable OpenRaft nodes and the real
bounded RPC codec with an **in-process synthetic router**. It stages 34 MiB of
external ciphertext on each replica, publishes two actual native roots,
rejects a conflicting CAS and stale receipt, compacts snapshots, kills the
original leader, elects a survivor and reopens all nodes. It checks that the
snapshot stays below 128 KiB and that missing ciphertext or a changed manifest
denies closure recovery while the committed root remains unchanged. A live
membership change also makes the old enrollment unusable for reconciliation.

These tests are executable evidence only after the changed source actually
passes. They do not qualify three-host TLS, production encryption, HTTP request
budgets, AuthBus, leases or the OpenBao client cutover.
