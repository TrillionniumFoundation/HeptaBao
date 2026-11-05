# `heptabao-darwin-vnode-events` developer guide

## Purpose and non-goals

This macOS-only crate owns the narrow `kqueue`/`EVFILT_VNODE` boundary used by
`heptabao-filesystem-guard`. It reports bounded mutation observations for held
files. These observations do not constitute a universal file generation, an
authorization decision, or complete filesystem qualification. Non-macOS builds
exclude the implementation; zero tests on Linux are not a macOS pass.

## Public API and ownership

`VnodeMutationQueue::new` owns the kernel queue. `register(&File)` clones and
retains the file descriptor before registration and returns an opaque `WatchId`.
`remove(WatchId)` requires a successful kernel removal receipt before releasing
that duplicate. `poll()` performs one nonblocking poll of at most 64 events.
`WatchId::value()` exposes only the sequence number, not an fd or queue identity.
The complete `WatchId` is scoped to its originating queue; a sequence alone is
not transferable between queues. No descriptor or pointer escapes the safe API.

## State and data model

The owner retains an optional `OwnedFd`, a map of watch IDs to owned `File`s,
a checked process-local queue ID and a checked sequence counter. The only
dependency is the pinned `libc` package. There is no stored credential, durable
state, wire protocol or cross-process registration recovery.

## Invariants and authorization

The fixed event mask covers write, extend, attribute, link, delete, rename and
revoke notifications. Registration/removal receipts must match the submitted
descriptor, filter and opaque numeric token, carry the expected error-receipt
flag and report zero error. Polled events must match an owned registration and
the admitted flags/mask. The filesystem guard remains responsible for its
complete-drain policy, mutation latch and all independent physical checks.

## Failure, retry and reconciliation

Ambiguous registration, same-queue removal failure or invalid observation
poisons the owner: it closes the queue before releasing registered duplicates.
Later register/poll operations fail. A foreign queue's ID is rejected without
altering this queue. Errors are not evidence of immutability; consumers must
reject their operation and acquire a fresh owner for a later request.

## Concurrency and ordering

Mutation methods require exclusive access to the queue. The file owner enters
the map before the registering syscall. Acknowledged removal precedes file
release. Field declaration order and the explicit poison path close the queue
before watched descriptors can be recycled. The crate does not implement an
event loop, concurrent mutation arbitration or request authority caching.

## Security and privacy

This crate explicitly permits the reviewed unsafe OS boundary and denies unsafe
operations without explicit blocks. Each syscall documents pointer and descriptor
lifetimes. Kernel `udata` carries a numeric token that is never dereferenced.
The existing filesystem guard keeps its unsafe-code prohibition. Debug output is
fixed and exposes no raw fd, file pathname, key or event payload. `fcntl` sets
close-on-exec separately; it is not described as atomic queue creation.

## Persistence and compatibility

All watches are ephemeral and must be reacquired after restart. Kernel events
can be coalesced; an empty bounded poll describes that observation only. The
consumer in `crates/heptabao-filesystem-guard/src/mutation_macos.rs` drains up to
64 polls and rejects an uncompleted drain. This module does not replace source,
directory, actor, seal, deadline or durable-writer validation.

## Observability

The API returns `io::Result` and opaque watch IDs. A refusal reports a fixed
ownership/observation error. Callers may record failure status while retaining
secret-safe error handling; successful registration alone is not a runtime pass.

## Operations

Build and run this crate on the actual macOS target with
`cargo +1.98.0 test --locked -p heptabao-darwin-vnode-events --all-targets`.
Also run the filesystem guard tests and current native server mutation/restore
profiles on the intended filesystem. Do not replace a failed kernel check with
pathname polling or treat this guide as an execution receipt.

## Tests and executable evidence

The three tests in `crates/heptabao-darwin-vnode-events/src/lib.rs` are
`vnode_real_events_and_receipted_removal_preserve_caller_file`,
`vnode_ambiguous_removal_poison_closes_queue_before_owned_duplicates` and
`vnode_watch_token_from_another_queue_cannot_remove_same_sequence`. They exercise
real events, acknowledged removal, caller-file survival, poison ordering and
cross-queue identity rejection. Their presence is not a claim that this source
has passed independently on every filesystem or OS release.

## Evolution and open boundaries

New filters, flags, callbacks, arbitrary pointers or public raw descriptors
require a fresh safety and ownership review. Filesystem-specific notification
coverage and a complete product migration remain separate admission gates.
See the [module closure dossier](../module-closure/heptabao-darwin-vnode-events.md).
Shared engineering rules are in `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.
