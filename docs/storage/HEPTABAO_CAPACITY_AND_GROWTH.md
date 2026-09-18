# Storage capacity and growth navigation

This file is intentionally a navigation shim, not a second capacity specification.

The current authoritative capacity, replay-retirement, state-format and scalability
contract is:

- `docs/operations/HEPTABAO_CAPACITY_AND_GROWTH.md`

That document is source-bound to the current V3 content-defined state store and
must be updated with the implementation. Historical V1/V2 fixed-chunk and
alternating-slot descriptions are retained only in source history and format
compatibility tests; they are not current development instructions.

## Current invariant summary

- local application state uses `heptabao-state-chunks-v3` content-addressed,
  content-defined chunks;
- the serialized logical application-state admission bound is 16 MiB;
- ordinary compaction does not retire replay identities;
- authenticated replay retirement advances the durable epoch/frontier and keeps
  retired requests stale;
- HA orders replay-epoch transitions through Raft before local publication;
- PostgreSQL terminal revoke removes the local lease row only after provider
  retirement/readback, while the global monotonic provider fence survives;
- chunk reuse reduces physical rewrites but does not make the application state
  record-oriented.

Do not add independent limits, format descriptions, completion claims or test
status here. Add implementation details and evidence requirements to the
operations capacity contract above, then bind them to executable source/tests.
