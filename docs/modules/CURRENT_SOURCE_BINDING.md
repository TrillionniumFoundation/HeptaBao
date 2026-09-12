# Current module source binding

The active plan remains `HEPTABAO-PLAN-2026-09-07-V2.1`. Current source facts for
all workspace packages are bound by
`planning/HEPTABAO_CURRENT_SOURCE_INVENTORY_V2.json`, checked through
`python scripts/current_source_inventory.py --check` and the ordinary V2
repository validator. A package's guide, manifest, full Rust source paths/bytes,
lexical declarations, discovered tests and path dependencies participate in this
binding. The expanded workspace and the guide set must match exactly.

## Historical and current evidence

`planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml`, the frozen V1.4.7 renderer,
and blocks marked `GENERATED V1.4.7` are historical snapshots. They are NOT the
current source API inventory, even where an inherited block calls itself
"authoritative" or "exact candidate". Do not run the old renderer in write mode
to make its historical results describe a new source. The V2 inventory rejects
changes to the preserved historical inventory bytes.

Current, complete lexical details are reproducible with:

```text
python scripts/current_source_inventory.py --details
```

The detailed output includes file paths and digests, declaration names and
source lines, discovered test names/attribute lines, and dependency scopes.
Each package's compact committed entry binds these complete details by digest.
`pub const fn` is classified as a function and parameterized `tokio::test`
attributes are recognized. Lexical discovery is not Rust type/visibility
analysis, branch coverage, test execution, or semantic API compatibility.

## Change procedure

Update the implementing source, its module-specific narrative and tests in one
candidate. Recompute only the V2 snapshot with
`python scripts/current_source_inventory.py --write`. Review the source/guide
changes and generated digest delta together, then run the read-only check and
complete repository/security/Rust gates. A generated digest alone does not
prove the narrative's correctness or an executable test pass.

The snapshot binds source inputs by content rather than embedding its own Git
commit ID, which would be self-referential. CI must separately record the actual
commit, tree, snapshot digest, binary digest, commands, exit statuses and test
results. Exact-head and prospective-main-merge receipts are separate. Any
candidate movement invalidates the old current-head qualification claim.

## Present product boundary

`Service::new_with_ha` and `HaProcess` now compose a real per-process voter,
mutually authenticated transport and the authoritative encrypted application
state path. This is implemented source, not completed HA qualification. The
server owns operation admission; the consensus runtime does not authenticate
public clients. Snapshots exported by the bounded server use its own encrypted
backup format, not OpenBao's Raft snapshot format. Standby forwarding is a
credential-bearing internal boundary and must never expose tokens or bodies in
Debug output. Production peer enrollment, certificate/key rotation, destructive
fault campaigns and independent admission remain separate requirements.
