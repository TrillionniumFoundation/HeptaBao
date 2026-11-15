# R790 — Compiled KV2 V6 codec, no publication authority

## Scope

R790 is a pre-admission code organization change on top of the isolated
R780 canonical shard-field closure fix. Its purpose is to make the
prospective typed KV2 V6 scope/Cell/encoding/decoding logic compile in
ordinary, non-test HeptaBao builds, without turning on any production
reader, writer, migration, HA publication or fallback path.

The existing test-only V6 disk graph continues to exercise exactly the
same codec through an import. It must not keep its own divergent
validation implementation.

## Code boundaries

- New private module: crates/heptabao-server/src/kv2_v6_record_codec.rs
- Normal lib.rs contains an unconditional private module declaration.
- The experimental kv2_v6_record_trial.rs remains compiled only under
  cfg(test), with disk fixtures, stage operations and QA-only records.
- The production engines::kv::Kv2 and V5 opaque-owner publication route
  remain entirely unchanged.
- Compiling the prospective codec introduces no API route, configuration
  switch, security credential, migration authority or disk schema.

The module is deliberately named a codec: a production V6 writer would
need separate authority for the exact schema, version-granular indexes,
physical retirement, atomic V5/V6 handover, replay epoch validation,
HA snapshot/delta consistency and crash/power-loss recovery.

## Verification

Run from the isolated ROG worktree r790-v6-compiled-codec:

1. cargo +1.98.0 build --locked --offline -p heptabao-server --lib
2. cargo +1.98.0 test --locked --offline -p heptabao-server --lib
   kv2_v6_ -- --test-threads=4
3. cargo +1.98.0 test --locked --offline -p heptabao-server --lib
   -- --test-threads=4

Retain r790-production-lib, r790-v6 and r790-full exit and log files
on ROG. Only tests with an actual nonzero matched denominator and
natural exit code zero may be counted as passed.

## Release gate

This patch cannot authorize OpenClaw production cutover or old OpenBao
deletion. J3160 data was not recovered. Real production credentials
must be independently reissued and four clients must pass actual
reads, renewals, revocation, restart and rollback after a complete
verified storage/HA migration. R790 does not replace any of those gates.
