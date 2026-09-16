# Current capacity, maintenance and growth boundary

This contract is subordinate to `HEPTABAO-PLAN-2026-09-07-V2.1`. It describes the currently implemented bounded storage behavior. It does not grant production authority or claim complete OpenBao replacement.

## Current authoritative state format

The server no longer stores the entire application state as one 768 KiB durable value. The current source binds `MAX_STATE_BYTES` to `state_store::MAX_SERIALIZED_STATE_BYTES`, which is explicitly bounded at **16 MiB**. A state generation is split into **512 KiB** chunks and framed by the versioned discriminator `heptabao-state-chunks-v1`.

`system/state` is either a legacy serialized `State` value or a small versioned manifest. Chunked writers alternate between two bounded slots. Every chunk for the next state plus the new manifest is submitted through one durable-service atomic batch, so one logical server-state publication consumes one replay identity and one durable generation rather than one identity per chunk. A reader admits only a complete manifest whose state schema, chunk count, byte length and SHA-256 binding all validate.

This is still an aggregate application-state architecture: a point mutation may require serializing the complete logical `State`, HA proposals still carry complete application-state bytes, and the 16 MiB limit is a hard admission bound rather than a scalability claim. Moving from 768 KiB to 16 MiB removes the immediate single-record ceiling but does not turn the service into a record-oriented storage engine.

## Legacy migration

On unseal, the service distinguishes a manifest from the historical raw `State` record. A valid legacy record is decoded and validated first, then rewritten into the current chunk/manifest layout through the same atomic batch primitive. The old state remains the authoritative readable value until the migration batch publishes its new generation. An indeterminate durable outcome returns a recovery reference and fails closed; capacity exhaustion and malformed state also fail closed. Manifest/schema disagreement, missing chunks and digest mismatch are never accepted as legacy fallback.

Fresh initialization writes the current manifest/chunk format directly. Local state commits and HA catch-up also use the same state-batch publication path, avoiding a second persistence protocol.

## Durable atomic batch boundary

`DurableService::apply_batch` and `apply_batch_with_compaction` bind an ordered mutation set to one principal/namespace/request identity and one authorization digest. The binding includes each resource, operation kind and value digest. A successful batch advances one generation and records one replay identity; replaying the identical request returns the retained duplicate outcome, while changing the mutation set under the same identity is a binding conflict.

The durable crash protocol remains intent -> candidate snapshot -> commit marker -> replay ledger publication. Because the full mutation set is applied to one candidate snapshot before publication, recovery observes the batch as one committed or unresolved logical operation rather than partially committed resources.

## Capacity observation

`GET /v1/sys/internal/storage/capacity` follows the audited service path, requires a root principal in the root namespace, and exposes metadata only. The response includes the explicit state bound, durable generation, logical payload/journal usage, retained request count and remaining replay slots. It does not expose tenant names, keys, operation IDs, tokens, password material or secret plaintext.

The local replay ledger is bounded at **32,000** detailed operation identities per replay epoch in the server profile. Ordinary preflight refuses a known-full epoch before proposing a new HA state effect. Journal compaction retains active replay records. Explicit replay retirement is a separate authenticated epoch transition and is allowed to proceed even when the detailed ledger is full; it is not implicit FIFO eviction.

## Checkpoint and recovery behavior

Automatic journal checkpointing is permitted only after a proven pre-entry journal-capacity rejection and retries the same bound request once. Unknown outcomes, filesystem failures and replay-capacity exhaustion are never automatically retried. A failed maintenance publication can fence the durable owner, and the server mirrors that recovery requirement rather than serving cached state as healthy.

Ordinary compaction never retires identities, so `replay_id_eviction` remains false. `DurableService::retire_replay_epoch` first checkpoints the active ledger, then publishes an authenticated next-epoch ledger carrying the retired generation frontier, then rewrites the journal checkpoint. Stale explicit epoch writes are rejected. The server now persists `State.replay_epoch`; in HA the marker is Raft-committed before each node retires locally and publishes the corresponding state batch. A retirement/state mismatch fences the node and is normalized only through restart recovery or committed HA catch-up.

## Remaining replay-lifetime qualification

Source tests cover restart, deliberately full active ledgers, stale-epoch rejection, follower-style catch-up and a failure after retirement but before state publication. Complete replacement still requires exact-candidate execution of more than 32,000 successful logical mutations, real multi-process leader/follower retirement across partition/heal and snapshot catch-up, and proof that external-effect tombstones or other replay-sensitive ownership are not incorrectly discarded.

## Wider scalability boundary

Even after replay retirement, full scalable storage still requires record ownership rather than repeated whole-state serialization, deterministic multi-record/Raft transaction ownership, authenticated streaming snapshots, migration/rollback fencing, and declared performance envelopes under real data sizes and failure campaigns. Native manifest/chunk support is not OpenBao snapshot-byte compatibility and does not itself establish production replacement authority.
