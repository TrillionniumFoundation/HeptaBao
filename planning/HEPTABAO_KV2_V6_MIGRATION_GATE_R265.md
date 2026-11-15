# HeptaBao KV2 versioned record migration — R265/R266 gate

Status: **RESEARCH_ONLY / NOT_ADMITTED**. This is a concrete migration contract for an
isolated candidate. No V6 production writer, root publication or HA read path is
enabled by the indexed-record trial. Do **not** confuse the trial with a KV2
capacity fix or permission to raise `MAX_APPLICATION_STATE_BYTES`.

## Exact known failure

On r261 (`aabaf8df3a1960d2d01cff89af033de79c15f1a4`) a synthetic
180 KiB KV2 payload written to a fresh V5 service was accepted 90 times,
then denied with HTTP 507 on entry 91. The last observed logical state was
16,637,282 bytes. An actual SIGKILL/reopen preserved the 90 writes and the
denied key stayed absent. Receipt:
`r263-kv2-owner-boundary/public-receipt.json`.

V5 `RecordStateRoot` authenticates five owner JSON blobs and one separate
`Kv1Root`. KV2 resides in the serialized `engines` owner. V5 constrains
**all five owner blobs together** to 16 MiB. Merely allowing more chunks
would create a V5 manifest that old V5 readers reject and can strand an
HA replica. A V6 physical state must therefore have a new format identity,
distinct writer permission and explicit rolling-upgrade fencing.

## Proposed V6 trusted data-plane

1. A separate authenticated KV2 graph indexed by typed key
   `(namespace, mount, incarnation, path)`; each encoded record owns its
   metadata and complete version history (CAS, soft delete, destroy,
   custom metadata, TTL/nanoseconds and lossless JSON precision). Tombstones
   and retirement generations are authoritative data, not cache hints.
2. Keyed object addresses are domain-separated from KV1, namespace custody,
   owner chunks and prior V5 roots. Reopening verifies **every** referenced
   object and key scope; never fall back to other owner data after a missing,
   mismatched or corrupt record. Pin the old committed graph across updates.
3. Stage all new objects without authority, then atomically publish an
   authenticated V6 root **after** storage durability, mandatory audit ordering
   and the same original operation identity have been satisfied. On I/O or
   audit failures before publication, no KV2 mutation is visible.
4. The V6 root references the independent KV1 and KV2 graphs and the
   five protected owner domains, and commits cluster ID, schema floor,
   replay/retirement epoch and format. Old V5 roots remain accepted in
   read-only migration mode only with verified provenance.
5. The promotion V5 -> V6 is monotonic and one-way during the cluster
   transition. All active voters and eligible leaders must prove V6 reader
   support **before** V6 writes can commit. A stale or downgraded writer
   must refuse, never synthesize an old V5 root or erase V6 record data.
6. Snapshot/install/catch-up/compaction must preserve every reachable KV2
   object until all pinned readers, followers and retained snapshots are
   safe to advance. Absent/duplicate/colliding object identity fails closed.
7. Quota is separate and explicit: maximum individual encoded record,
   maximum graph bytes, maximum staged objects / preflight I/O budget and
   runtime memory ceiling. Operator `/sys/internal/capacity` must distinguish
   **V5 opaque owner headroom** from independent KV1/typed KV2 graph headroom;
   neither is a reservation to admit a write.
8. Preserve exact OpenBao 2.7.1 request semantics, including version and
   CAS failures, soft deletion, metadata, listing, namespace isolation,
   webhook/lease side effects and recovery. Use direct, pinned official
   oracle comparisons, not data-length tests alone.

## Negative tests required before promotion

- V5 reader rejects all V6 roots; dual V6 reader accepts canonical legacy
  V5 only under an explicit migration authority and schema floor.
- Wrong namespace, remount incarnation, key path, replay epoch, duplicate
  object ID, noncanonical encoding, unknown format, invalid version floor,
  tampered ciphertext, missing chunk and stale snapshot all fail closed.
- 32+ MiB aggregate KV2 over hundreds of independent objects, under the
  physical graph budget, survives real restart, snapshot, leader SIGKILL,
  catch-up and quorum loss without a ghost write, loss of CAS semantics,
  resurrection of revoked credentials or improper owner reuse.
- Inject actual disk-full, interrupted fsync and root publication failures,
  including the ambiguous case where a Raft write has committed but local
  persistence did not. That case must demand reconciliation and forbid
  blind retries.
- Mixed-version three-host rolling admission and rollback rehearsal,
  with original data and clean snapshots, exercising old/new readers.
- Bind exact source SHA/tree, native binaries for Mac+Linux, diagnostic
  fixtures, full QA and comprehensive OpenBao 2.7.1 differential; release
  authority remains false until all eleven main gates close.

## R265/R266 implementation scope

R265 trial exercises the **actual authenticated persistent B-tree API** with
an aggregate over 16 MiB, immutable old snapshots, reopened roots and
cross-namespace/mount/incarnation non-adoption controls. It is deliberately a
`#[cfg(test)]` model with representative entry JSON. It does **not**
detach the production KV2 engine or publish V6.

R266 is a separate truthful operator capacity observation on V5:
`opaque_owner_aggregate_bytes` and
`opaque_owner_remaining_bytes`; remaining bytes are explicitly
**not** write-admission authority. The canonical V5 limit is unchanged.
