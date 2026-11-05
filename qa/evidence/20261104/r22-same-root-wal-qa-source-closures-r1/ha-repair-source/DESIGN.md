# Same-content root at a later HA publication: source proposal R1

## Outcome and scope

This proposal fixes a source-level selection gap exposed by the df026 stopped-node diagnostic. The original cold and warm paths select their exact-current fast path by root content identity alone, although their next mandatory check also requires the local HA cursor to name the exact current Raft publication. A valid older cursor can remain covered by the current read while A -> B -> A returns to the same root bytes at a later generation.

The proposal keeps `NativeHaCursor::matches_current` strict. A covered but non-current same-content selection goes through the existing full replica installer. It does not rewrite cursor bytes directly, infer permission from covered_by, renew the original request deadline, or accept a content digest as publication authority.

Parent: `6d02ceca629163e1c07480fa1f21520434407143`, tree `09aa45b9439741780961c2af76680c27e0773d08`. This parent includes the earlier test, Clippy, and formatting corrections. The actual LAN failure and normal binaries remain identified as df026; no qualification is transferred to this uncompiled proposal.

## What was observed

The complete read-only projector packet is `c246a6c981853b70873462564e6d32fbfebdb164`. Its stdout is `c100cfff1cf7a89c7796d79856dbe5790b57d425`, 55,402 bytes, SHA256 `e780e0681a8f8b5ca8b1ca84a1fabc4e014e74042cfe70c55e88c6b12e84448d`. Authority is `1feae0c7b721fad920e13f917fd3c1376410add6`: exit 0, complete and durable, no timeout. All six descriptors were closed; the ten-field file identity, whole input SHA and held/named directories remained stable. No product request, child, write, or network request was made.

Line 183 is an unseal 503 marker with state, recovery_required, barrier, record_root and activation all false. Line 184 is an ordinary failure-timing record with 10,275,494 microseconds elapsed and 3,717,085,098 nanoseconds remaining at exit. It records:

| Phase | Outcome | Elapsed |
| --- | --- | --- |
| committed_changed_root_recover | advanced | 10,240,410 us |
| committed_root | completed | 10,265,917 us |
| local_selection | completed | 221 us |
| local_root_binding | completed | 0 us |
| local_root_identity | completed | 9 us |
| current_cursor | failed | 5 us |
| load | failed | 10,266,207 us |

There are no replica_source, replica_install, installed_local_selection, materialize_full, physical_repair, or materialize_after_repair buckets in that record. Its bucket bound was not reached. Thus this record does not describe a failure inside the later full local materialization. It also does not prove that every previous phase consumed negligible time.

The marker has no request identifier. Adjacency and the fixture's final unseal ordering are not a cryptographic request correlation. The original mutation ledger records node2 unseal 503 at sequence 49, but the diagnostic is kept as a scoped source-and-log inference, not a fabricated route/request ID.

## Why the cursor check is the relevant code gap

The exact df026 read source is `b09e57362d53ce207b255d713d7aa7c126215691`. Parent 6d02's source is `8c67a106e6a9628ad77214e09656cf73b050dcbe`; the prior final-gate Clippy/formatting change is retained.

1. `LocalSelection::read` in install.rs 664-685 decodes the native root, retained V5 source, active cursor, and the same owned HA bytes. It validates the active cursor, canonical HA decoding, covered_by, root/migration pairing, local epoch and local publication generation. A missing or malformed HA cursor fails there.
2. The selected native root and HA bytes are owned values. With no replica-install/reselection branch, the later current_cursor closure reads the same selected bytes and the same immutable committed-read value.
3. `matches_current` first preserves covered_by, then additionally compares Raft generation, exact publication LogId, exact intent LogId, and root digest. Under the stated source path, the later refusal is an exact-publication mismatch, not a newly missing or newly malformed selected HA byte string. No private cursor values or exact generation numbers were read by the projector.
4. The ordinary same-epoch covered_by rules permit a strictly older generation, but reject a mismatched equal-generation publication. Content equality therefore cannot be substituted for exact publication equality.
5. The old cold condition at read.rs 302-308 and warm condition at install.rs 1328 checked only content identity before entering a path that demands the stricter cursor equality. Both have the same omission.

This establishes a concrete source-level defect and a regression construction. It does not prove which earlier application operation produced A -> B -> A in the failed fixture, or expose its private cursor fields. Those are not required to preserve the current authority checks in the repair.

## Minimal production changes

### Cold path

The existing changed-root install condition additionally selects the original installer when the canonical selected HA cursor is not exact-current. LocalSelection has already authenticated and covered that cursor. Malformed decoding still returns its original error. The installer, original cold owner, original committed witness, original deadline, publication uncertainty handling, subsequent re-selection, and final strict CurrentCursor block are unchanged.

### Warm path

The exact-current local fast path additionally requires canonical HA cursor exact-current equality. A covered older publication falls through to the existing full installer under the same actor, owner, witness and original deadline. The strict check inside the fast path remains byte-for-byte; it is not replaced by covered_by.

### Read-only continuation boundary

The existing same-root continuation is explicitly read-only. Previously its admission checked only current_state_identity and captured the original environment/generation. Once the same-content stale-cursor branch can install, that admission would be too broad.

The new private `native_v6_same_root_continuation_is_current` requires both current content identity and canonical persistent HA cursor matches_current before that original continuation is captured. An older publication returns false, so an installation attempt cannot inherit the read-only retry path. Missing/invalid bytes still fail closed. The original environment/generation checks, witness-refused requirement, original deadlines, one final read-only attempt and failure fencing are unchanged.

This helper is not a read permission or a replacement for LocalSelection. The actual installation still follows LocalSelection's owner, epoch and four-resource pairing checks.

## Why the existing full installer is sufficient

The unchanged install.rs body 1617-2028 opens the actual committed source, validates its complete typed ciphertext graph, stages every actual local object under the original gate, and rejects corrupt or changed existing bytes. It retains the original four selected resources as CAS predicates: state, active cursor, retained source root, and HA cursor.

Before publication it fully materializes the candidate local graph and compares it with the received state. It then prepares the next local generation, creates the ordinary active and HA cursors, and publishes state/active/HA in the original conditional batch. It checks current ownership, local generation/epoch, exact resource readbacks, retained source, active cursor validation and strict HA matches_current. It fully authenticates the local graph again afterward. Root-publication uncertainty remains governed by the original root_committed/durable.recovery_required branches.

`NativeActiveCursor::advance` in reader.rs 130-163 requires a strictly higher local publication generation and the original cluster, epoch and reader-floor conditions. It does not require different root content. The installer therefore supports same-content publication advancement without a new cursor-only write primitive or any omission of graph validation.

The original full installer is reused unchanged; the additional work must fit the original request budget. No claim is made yet that the failed fixture's 34 MiB workload will complete within its remaining time.

## A real A -> B -> A regression

The new module contributes exactly one independently counted test:
`service::native_v6_ha_install::tests::same_root_republication_tests::native_ha_same_root_republication_advances_warm_and_cold_cursors`.

Consecutive A -> A is deliberately not used. NativeV6CommitIntent::validate in blob `3568d548cb69d0cfb6ff4d52216cc87c9b35a917`, line 51, forbids proposed_root_digest == prior_root_digest. The regression uses a genuine intermediate B:

1. Prepare source A with the existing 112-key fixture and version history, including deleted version 2 and destroyed version 1. The existing fixture establishes an actual three-node Raft cluster.
2. Seed two independent real local barriers from A and install its first actual publication.
3. Seed a separate isolated source B from A, make a real synthetic KV write in B, and publish B with the exact current prior digest/generation/index.
4. Project unchanged source A again and publish it against B. Assert that the third actual root equals A's content, has a later generation/log, and retains the same migration source.
5. For each target, call the production LocalSelection::read against an actual fresh ReadIndex. Assert canonical cursor covered_by succeeds while strict matches_current fails, content identity equals the current publication, and the exact new read-only-continuation admission returns false.
6. Advance one target through the normal warm installer and cold-open the other through production load_cold_native_ha. Each call remains in the unchanged 15-second request scope and additionally checks measured elapsed time is below that budget.
7. Assert the root bytes remain A, local generation advances, active and HA bytes change together, the active/HA publication generations match, and strict HA matches_current succeeds. Verify all four retained history/lifecycle states through the existing actual read proof.
8. Close and cold-reopen both independently owned targets again. Assert the paired resources and durable generation are unchanged; exact-current cold reads must not republish.

The test uses the pre-existing explicit ciphertext-copy fixture followed by actual Raft publication/ReadIndex and the production local installer. It does not claim to replace pinned-mTLS transport, HTTP unseal audit, or the independent physical LAN regression.

## Validation and qualification boundary

The three modified old files have strict forward and reverse unified-diff reconstruction, and the original test file is byte-identical after removal of the single new module declaration. The complete NativeHaCursor implementation, LocalSelection, LocalHaEnvironment, full replica installer, cold gate/final tail, original warm current body, install failure/recovery tail and continuation body are unchanged. Parent membership and all 358 parent Merkle trees were independently checked.

The initial source-check harness used a nonexistent text anchor and failed before completing its comparisons; that failure is retained. Correcting only the harness anchor produced the source checks in this packet; candidate bytes did not change.

There has been no rustfmt, Rust compile, test execution, host deployment, new process, or product request for this proposal. No ref or commit is created by this packet. Original normal 44+7+9=60 tests and LAN 98+12 names/assertions remain unchanged. This new regression must be listed and run separately under its own new qualification after root review; the anticipated name is not an actual Rust test listing.

The physical df026 outcome remains 91/98 with seven missing and postcold 0/12. The earlier X230 relay remains UNKNOWN and its failed create-only fence remains failed. This proposal neither retries those operations nor changes their evidence.
