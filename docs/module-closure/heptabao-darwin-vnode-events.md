# heptabao-darwin-vnode-events module closure dossier

## Design and state ownership

One `VnodeMutationQueue` owns the kernel queue and every registered duplicate
file descriptor. Queue and sequence IDs are checked process-local counters.
The caller retains its original file. There is no durable state or recovered
watch authority after restart.

## Module boundaries and trust assumptions

Only macOS compiles the implementation. The safe API exposes bounded vnode
observations and opaque queue-scoped tokens. The pinned libc syscalls are the
explicit unsafe boundary; existing consumers retain their unsafe-code ban.
Kernel receipts and events are checked against held registrations. A numeric
token is never dereferenced, and sequence values from different queues may
coincide without granting cross-queue removal rights.

## Failure semantics and ordering

Install the owned duplicate before registration. Release it only after the
matching removal receipt. Ambiguous registration/removal or malformed events
close the queue before clearing duplicates. A foreign queue ID is refused
without changing local registrations. A poisoned queue cannot be revived.
The filesystem guard owns complete draining, the failure latch and fresh
physical validation; empty polls cannot establish universal immutability.

## Acceptance evidence

**Named executable anchor:** `vnode_real_events_and_receipted_removal_preserve_caller_file` in `crates/heptabao-darwin-vnode-events/src/lib.rs`.

The anchor observes actual file mutations and successful removal while the
caller's file remains usable. The same source contains actual ambiguous-removal
poison and cross-queue-token rejection tests. Exact-candidate macOS runtime
receipts are required separately; Linux cfg exclusion does not qualify these
tests. Run the owning filesystem guard and native service profiles as well.

## Known gaps and evolution

These are ephemeral, potentially coalesced notifications, not universal
generations or authorization proofs. New kernel filters and API surfaces need
new review and executable evidence. This dossier grants no compatibility,
production, migration or release authority.
