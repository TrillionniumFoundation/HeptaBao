# R740 — Authenticated version-granular KV2 V6 trial

## Authority boundary

Isolated synthetic Rust QA only, within the test-only V6 disk module.
It does NOT participate in production Service, EngineState, Raft writer,
KV2 mount or OpenClaw runtime. The V5 opaque owner limit is still 16MiB
and the independent authenticated graph limit remains 64MiB.

R720 proved a single 2560KiB KV2 Cell survived immutable staging,
signed-root publication and reopen with a 4MiB per-cell limit. The same
Cell could not retain two different 2560KiB values; the payload exceeds
4MiB. The original R740 red test failed with RecordError::TooLarge.

## Separate version records and signed-root closure

The experimental R740 layout uses a small per-logical-path index Cell
with canonical version pointers and independent full-payload Cells,
one per version. A test-only reserved mount suffix, deterministic path
digest and typed namespace/mount/incarnation protect index and shard
address binding. The same signed TrialDisk root authenticates index,
version shards and all immutable object pages.

Version 1 is published. Version 2 is durably staged but the root is
not yet published; the only visible value remains version 1. Then
generation 2 is committed and both 2560KiB retained values are
recovered byte-for-byte.

Cross-index validation executes BEFORE immutable object staging
and again AFTER authenticated root reopen. It rejects a forged
version pointer, missing referenced shard, unreferenced orphan
shard, and rewriting an already acknowledged version. All rejected
candidate publications must preserve the prior signed root.

## Evidence

Base commit a662755646d781358e883bd567900896ade404d7.
Worktree r740-kv2-version-shards on ROG.
Red log r740-red.log: exit 101, one matched TooLarge failure.
First green r740-green.log: exit 0, one pass.
Adversarial green r740-adversarial.log: exit 0, one pass.
Scoped V6 r740-kv2-scope.log: exit 0, 32/32 pass.
Full suite r740-full.log / r740-full.exit: exit 0, 2661 passed,
0 failed, 8 ignored. The log remains available for SHA256 audit.
The source and logs must remain available for independent SHA256 audit.

## Remaining hard gates

This is not a production V6 record format. It does not implement
full KV2 retention, sparse version retirement/destruction, precision
timestamps, CAS semantics, old-reader compatibility, complete
migration, HA replicated V6 delta/snapshot, disk-full/power-loss
failure injection, or OpenBao 2.7.1 release parity. A production
implementation needs a reserved format discriminator and migration
authority that cannot expose partial current state.

Do not switch real OpenClaw client credentials or remove old
OpenBao until the final migration and restart/rollback proofs pass.
