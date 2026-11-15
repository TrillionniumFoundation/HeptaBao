# R780 — Canonical V6 shard-field closure (isolated QA)

## Admission and scope

This source change tightens the **test-only** authenticated KV2 V6 shard
format. It does not create a production V6 writer/reader, change the V5
16MiB opaque owner limit, migrate credentials, or grant service access.

Parent R770: 59fc3bb9a2997956f1fd163a99fb7a267ccce6c1.

## Genuine red finding

An earlier group of security regression tests changed a serialized typed
Cell through a generic serde_json::Value. That can reorder the fixed outer
Cell fields and cause decode to reject the noncanonical byte order before
the shard-closure rules have been exercised. A passing rejection under
that construction is insufficient evidence for a closed shard grammar.

R780 constructs malicious cells using the actual typed Cell structure,
serializes them with the canonical codec and explicitly proves that
decode() accepts them. Before the fix, adding an unexpected field to
versions["1"].data was accepted by validate_sharded_trial_index().
The targeted actual test failed (exit 101, one matched failure).

## Format fix

Within the private R740 shard_schema v1, a logical index must carry
only shard_schema, current_version and versions. Each version pointer
must carry only data and destroyed=false; pointer data must contain
exactly one shard_path matching the derived authenticated scope.

A physical version shard must carry only current_version and versions.
Its single retained version must carry data and destroyed=false; the data
object must contain precisely one payload string. Extra aliases,
authorization flags or alternative identifiers fail the closure check.

Canonical test construction is now used in the existing R740/R760
pointer-mismatch and pointer-extra regressions. The change is deliberately
schema-specific: future retirement and metadata formats must receive a
new discriminator and migration protocol, not silent v1 field extensions.

## Executed ROG evidence

Original canonical red: r780-canonical-data-red.log (exit 101, one
matched failure). Modified canonical green: r780-canonical-data-green.log
(exit 0, one matched pass). All shard disk tests:
r780-shard-scoped.log (exit 0, 29 passed). Complete serverlib:
r780-shard-full.log (exit 0, 2667 passed, 0 failed, 8 ignored).
All logs are retained under /home/qian-qi/heptabao-271-r104/.

## Remaining production gates

V6 remains cfg(test), the index permits at most 32 contiguous versions,
and physical retirement/destruction lacks an authenticated authority.
Integration still requires exact legacy KV2 migration, stable production
state schema discrimination, HA replicated V6 delta/snapshot and replay
fencing, disk-full/power-loss failure recovery, credible rollback, full
OpenBao 2.7.1 parity and four real OpenClaw client secret reads.

Old OpenBao stays in place until production no-dependency evidence passes.
