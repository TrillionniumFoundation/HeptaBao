# R810 — Compile V6 shard graph read validation, preserve V5

Base source: `d70e0345dd4b3c1ca3931dc27cec2fbd0bbc9865`.

## Scope and isolation

The existing V6 private per-version sharded graph reader/checker moves from
`#[cfg(test)]` disk-trial code into the ordinary private Rust compilation
unit `kv2_v6_shard_validator.rs`. The QA trial imports the same exact checker
instead of maintaining a divergent duplicate. Only the record scope derivation
and the full graph *read-only validation* are compiled in normal builds.
Object staging, signed-root publication, migration, Service dispatch, Raft
writer integration and rollback authorization remain solely outside this module.

## Exact counterexample and fix

In the original QA shard derivation, validating the derived physical key
was insufficient: a malformed original logical mount such as the empty
mount, missing trailing separator, or a reserved mount could still yield a
syntactically valid derived physical key. A one-test red regression must
naturally fail on that state rather than succeed with zero matched cases.

The derivation now validates the complete *original logical scope* with
the existing V6 typed-key checker before hashing or staging an independent
physical shard identifier, and bounds the QA schema's versions to 1–32.
The graph verifier continues to enforce exact reserved-domain closure,
canonical metadata, every signed referenced shard, and rejection of orphans
before staging and after signed-root reopen.

## Admission boundary and remaining P0 blockers

This does not grant any actual V6 storage, legacy V5-to-V6 transition,
credential custody, mixed-version voting, or application route. It cannot
raise the 16 MiB V5 opaque-owner ceiling. A production V6 cutover requires a
version-granular writer with format identity and rollback fence, atomic roots
after fsync and audit, retention and retirement, physical power-loss and
disk-full tests, HA snapshots/readindex, exact OpenBao 2.7.1 oracle coverage,
migration of genuine assets and real clients, and all eleven release gates.

Any failed Rust test, host-differential, HA ReadIndex or source digest remains
a blocker; there is no hidden fallback, retry of ambiguous mutations, or
automatic old-OpenBao decommission.
