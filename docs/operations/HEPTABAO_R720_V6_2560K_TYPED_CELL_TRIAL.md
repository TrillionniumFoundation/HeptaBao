# R720 — KV2 V6 single 2560KiB value, isolated trial only

**Scope:** a source test of the independent V6 authenticated typed-record
graph. This does not enable a production V6 writer, change the OpenClaw
AuthBus configuration, grant new permissions or migrate OpenBao data.

## Reproduced mismatch

OpenBao 2.7.1 and R700/R710 HeptaBao HTTP ingress accept a 2560KiB
KV2 JSON write through narrowly scoped 3MiB transport (ordinary APIs
remain capped at 2MiB). The V6 typed record encoder still had a
256KiB MAX_CELL. A new isolated disk-backed source test using precisely
one typed 2560KiB payload failed with RecordError::TooLarge before root
publication. The red test real exit was 101.

## Scoped source change

Only the test-only V6 cell envelope is bounded at **4MiB**, allowing a
2560KiB value plus the typed scope/version/history metadata. The
authenticated Kv1Index already owns immutable 256KiB object blocks,
16MiB maximum value size, and 64MiB total graph capacity.
The V5 aggregate opaque-owner limit remains **16MiB**. HTTP budgets
and Service ACLs are unchanged.

The Rust test creates a private TrialDisk, builds the authenticated
object graph from a typed KV2 record, publishes its signed root,
reopens persisted bytes, and compares the full payload and version.

## Remaining production blocker

The per-path V6 Cell embeds the entire retained versions map. Two
different 2560KiB retained versions exceed the current 4MiB bound.
Production still requires a version-granular record layout, atomic
old-to-new migration, replay/epoch fencing, HA replication, retirement
protocol, crash recovery, and rollback.

## Evidence

Source base HEAD: 9459df315147806c116ae3f617bccb8fa074dc8a
ROG isolated worktree: r720-kv2-single-large
Red: r720-red.log (exit 101, TooLarge).
Targeted green: r720-green.log (exit 0, 1/1).
All V6 scoped: r720-kv2-all.log (exit 0, 31/31).
Full serverlib: r720-full.log and r720-full.exit (exit 0,
2660 passed, 0 failed, 8 ignored). All outputs remain on ROG.

No test here permits production cutover or deletion of old OpenBao.
