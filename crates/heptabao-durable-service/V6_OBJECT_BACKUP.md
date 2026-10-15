# V6 object-backed backup transport — candidate, 2026-10-14

This module is a storage transport building block, not an enabled HTTP endpoint,
a native graph validator, an Actor capability, a seal migration protocol, or HA
admission. The existing server refusal of V6 snapshot routes is unchanged.

## Problem and scope

The legacy HBB2 container carries the authenticated durable snapshot, replay
journal checkpoint and request ledger. A paged V6 snapshot can instead contain
72-byte immutable-object locators whose ciphertext lives in descriptor-bound
`.hbo` files. Exporting only HBB2 in that state is incomplete even when its own
checksums and AEAD are valid.

The public legacy exporter and legacy prepare-restore paths now refuse a
reserved system V6 object-slot state. Ordinary KV values containing a similar
marker are not reinterpreted. The new explicit `HBV6PK01` transport includes the
existing encrypted HBB2 core and **every registered external slot in that
committed core**. It does not scan directories or adopt unreferenced files.
Registered slots can include retained historical resources; this is not a
claim that the durable layer understands which objects the active typed graph
currently reaches. That application-specific closure check remains mandatory.

## Wire format

The provisional format is fixed little-endian framing:

- Eight-byte `HBV6PK01`, core byte length (u64), object count (u32), zero reserved
  field (u32), and total external ciphertext byte length (u64).
- Exactly one ordinary, encrypted HBB2 core.
- For each registered V6 slot in sorted resource-name order, its exact
  ciphertext length (u32) followed by those bytes. Resource names, slots and
  typed associated-data inputs come from the authenticated encrypted core;
  they are not separately accepted from an unauthenticated file manifest.
- A length-prefixed sealed SHA-256 transcript over the header, core and object
  records under a dedicated barrier context. Exact EOF is required.

Individual ciphertext retains the existing 512 KiB bound. Core snapshot,
journal and ledger bounds are unchanged. The new external-object aggregate is
separately bounded to 1 GiB and 65,536 registered objects. These are transport
limits, not a declaration of Service capacity or a lifted application limit.
Large external payloads are streamed with at most one bounded incoming object
(and a bounded reauthentication buffer) at a time. The encrypted core is still
materialized with the existing bounded whole-component representation; this is
not a zero-copy or constant-total-memory claim.

## Export ownership

`prepare_v6_backup` captures the actual source session and exact generation,
root, replay epoch and backend owner. Its plan is not Clone or serializable.
`export_v6_backup_to` consumes that plan, retains the caller's original gate,
pins each actual source file and authenticates its ciphertext before emitting
it. The caller-supplied typed-object validator must verify grammar and keyed
object references against its authenticated native root. An old source plan
cannot be reused after publication or backend close/reopen.

Every streaming I/O loop rechecks the same supplied gate; repeated EINTR is
bounded. Output is not a successful artifact until the caller has received
success, completed its mandatory audit and published/fsynced its private spool.
A valid-looking partial or late file is not a request completion receipt.

## Import and publication

`prepare_v6_restore_from_reader` owns the input reader. It authenticates the
core, all external object bytes, the sealed transcript and EOF before staging
anything in the target. The typed verifier receives the borrowed incoming
`PreparedRestore`, resource and freshly authenticated plaintext. The caller
must also validate the complete incoming graph, schemas, namespaces, seal
identity, provider/recovery floors and authorization before commit.

The prepared object does not expose an owned standalone HBB2 restore; its state
is borrow-only. Installation rechecks the exact target restore frontier, the
rollback policy and target transaction capability before object writes. Every
selected input ciphertext is hash-rechecked after preparation. Existing files
are never overwritten: their actual current ciphertext must authenticate to
the same plaintext. A known staging failure may leave only unreferenced
immutable objects, never a successful canonical restore. An unknown staging
outcome fences the owner until a real reopen.

After all external files are staged and reauthenticated, the implementation
consumes the existing `restore_prepared` transaction, retaining its authenticated
filesystem intent, recovery ordering, generation/epoch binding and ambiguity
handling. No replacement transaction protocol is invented here. Successful
restore invalidates the other pending plans. The API does not own an Actor,
Clock or audit system; the Service layer must supply those and its final
completion checks. It is not yet wired to V6 HTTP snapshot or Raft paths.

## Validation and limits of evidence

New tests use actual `FileBackend` directories, writer fences, object pins,
file-streamed archives, target staging and cold reopen. TestBarrier is the
existing deliberately nonproduction test provider; these tests are not an
independent validation of production cryptography or the complete Service
native graph. The 132 MiB case verifies all 528 synthetic 256 KiB objects after
restoring the archive to another store and closing/reopening its owner.

Negative cases cover malformed slots, duplicate physical addresses, missing
registered files, wrong contexts/providers, bad core/object/footer bytes,
truncation, trailing bytes, oversized framing, object reordering, expired gates,
stale source/target instances, post-prepare input substitution, conflicting
existing files, unsupported restore profiles, explicit rollback and a real
immutable stage whose acknowledgement is deliberately lost.

Still required before release: integrate and test the actual native Service
root/graph callback and snapshot seal binding; retain HTTP original-request
and mandatory-audit custody across export/import; qualify source and target
failure recovery; run the complete server regression on this changed source;
then run V6 multi-host HA and the client cutover/rollback matrix. Passing the
unchanged parent `9acbb148` server suite does not qualify this later source.

## Bounded thirty-two-object durability experiment

The isolated batch-thirty-two candidate tests one strong device flush per thirty-two
independently fsynced immutable files (maximum 512 KiB ciphertext each).
The original gate is still checked before/after I/O and links, no staged pin
escapes before the final barrier, and the application root is not published
until all objects and the restore transaction complete. Maximum live staging
buffers are 32 MiB (thirty-two ciphertext + their plaintext) plus bounded core.
This is a candidate optimization, NOT a reason to widen a request deadline.
