# B preparation: committed witness proposal R1

Status: source-only proposal. No product code, existing QA source, prepared object, old fixture, host state, or Git ref is modified. There is no executable replacement, dispatch or runtime permission in this packet.

## Observed failure and the exact unfulfilled condition

The single B run `1a1a9094b62-fc05-30ab` / run ID `e70cd7fda3c928604cd82e8c1a157502` ended with `direction_new_committed_frontier_not_observed`. Its original checks are 83 passed and 15 missing, exactly partitioning the original 98. The extra post-recovery cold scope observed 0 of 12 checks. The 45 mutation boundaries have explicit known outcomes; this does not claim that every readonly GET completed. The final health observation explicitly has `response_observed=false`.

Before stop, ROG2 reported `is_self=false` and committed/applied index 61. Its once-read stopped journal has last and committed LogId `(term=2,node_id=3,index=61)` and a committed vote for `(2,3)`. All available readings among 190 bounded observations show Pocket3 as leader, and both Mac and leader committed/applied positions remain 61. Thus the remaining Mac1/Pocket3 quorum preserved its leader without appending a new entry. The source waited for a newer entry that it did not arrange to create. These facts support the preparation refusal; they are not a completed missing-cipher recovery, a post-recovery durability failure, or a unique explanation of every previous election.

The executed runner also has a second, not-reached predicate: after stopping Mac, its new committed **term** must exceed both the stopped ROG last-log term and stopped ROG vote term. An ordinary write in the continuing Pocket3 term would not satisfy that predicate. Adding a write without reviewing that relation is therefore insufficient.

Original evidence:
- Full core and original SDK reads: tree `02c5afd1ca16d7df65680089dde0ba69d029b788`.
- Full 45 intent/outcome pairs and six original SDK file-read responses: tree `1e96e9c25850e07182850b6861fd576a505dcb86`.
- Root known-failure/cleanup review: blob `668fec1db7af05d813df2fe7bf32060e9fc99ae2`.
- Earlier successful R3 98/98 remains independently qualified and unchanged.

## Version and comparison contract

Canonical product `49503322c7f446e5eb41e7744f1fdbd7f1192ecc` pins OpenRaft `0.10.0-alpha.34` in Cargo.lock, checksum `06fe14d529f8fc098fbb4b9655d5db9b7ee0594e6a9d4e220aa931618de17b1f`. The upstream release tag resolves to commit `dfee06ca9a8193f061149ce784caa6bcbe92a0c4`, actual Git tree `df6167c8f3075dd570ef6a6c7962af0ddddff42a`. The complete recursive tree was checked against all 235 tree objects and 1,239 blob entries. The selected source files are whole-byte SHA-256 / Git-blob checked; their exact URLs and pins are in source-membership.public.json.

This is a static source binding through the canonical lockfile and upstream release. It does not claim a new byte-level verification of the physical hosts' Cargo registry source cache or downloaded .crate archive. No such host read was performed.

The relevant contracts are explicit in the source:

1. Canonical state_machine.rs:136–142 selects `leader_id_adv::LeaderId<Self::Term,Self::NodeId>`.
2. Upstream raft/mod.rs:201–240 supplies the omitted Term and NodeId defaults as u64.
3. Upstream leader_id_adv.rs declares fields in order `term,node_id` and derives total Ord. Its committed leader ID is the same type.
4. Upstream log_id/mod.rs declares fields in order `leader_id,index` and derives Ord. Therefore the concrete comparison is lexicographic `(term,node_id,index)`, with checked u64 components.
5. engine_impl.rs:393–419 rejects an ordinary vote if the candidate's complete last LogId is behind. The log check precedes updating the vote. Lines449–462 apply the same complete-log rule to pre-vote without changing persistent vote/term.
6. Canonical process/node.rs:1345–1370 enables pre-vote and uses default leader restore. Upstream config.rs:647–652 resolves leader restore to true. engine_impl.rs:171–200 immediately restores a node whose persisted committed vote names itself when that option is enabled.
7. Canonical process/network.rs:422–433 and 503–512 implements both actual Vote and PreVote RPC paths, including dispatch to `raft.pre_vote`; this is not reliance on the upstream default Unreachable stub.

The protocol reason for preparing a newer Mac log is consequently a **strictly newer complete LogId with retained committed history**, not a separately mandatory larger term. A same-leader append from `(2,3,61)` to `(2,3,62)` is strictly newer by the exact comparison. A larger numeric index under an older leader ID is not sufficient.

This source argument predicts how a valid request is compared. It does not guarantee that a later timed election succeeds. The actual empty-leader=Mac1 predicate remains mandatory.

## Proposed minimal fresh-fixture protocol

All steps occur only in a separately frozen new controller, new roots, new run ID and new operation key. The failed B roots are never restarted or repaired.

1. Retain the original three initial cold unseals and source selection of Pocket3. Read and retain the original pre-stop ROG local frontier. Perform the original once-owned stop of ROG2.
2. Start one preparation deadline immediately after that stop: `min(now + 60s, original_controller_until)`. Read stopped ROG once with the existing numeric helper, its original 15-second local bound and SSH bound clamped to this same parent.
3. Within that same deadline, observe a unique actual healthy, unsealed, application-ready leader among Mac1/Pocket3 using the existing health/is_self fields. Discovery uses readonly GETs capped by the remaining deadline; it never changes membership, vote, term, election configuration or the leader. If none is observed, fail preparation. Do not invoke a helper which creates a new independent 60-second budget.
4. Perform exactly one CAS=0 KV2 creation at a separately generated run-scoped path, for example `native-ha-<new-run-id>/direction-prepare-witness`. Use a small synthetic value bounded below 1 KiB, the existing root token, the unchanged `NativeRun.request` and `FixtureRecoveryLedger`, and `min(15s, remaining)` through the existing optional parent_deadline path. Record the dispatch-attempt flag before calling. Require status200/version1. No retry, retargeting, new path, or compensating request follows an unknown outcome.
5. Read the exact value through Mac's ordinary small read path, under the same deadline, and compare the expected digest/version1. Then issue exactly one metadata DELETE for that same witness using the same original request ledger and bound, requiring204. Confirm absence through the ordinary small-read path on Mac and the actual leader. This deletion is a second explicit mutation with its own original intent/outcome; it is not hidden cleanup or a replay. A failure or unknown stops the fixture. Only process cleanup follows; an incomplete witness remains confined to the new owned fixture.
6. Keep the witness outside `self.history`, `self.retired` and `self.acknowledged`. Retain a separate witness report with request sequence references, path/value digests, create/read/delete outcomes and deadline completion. Obtain a post-delete actual-leader committed/applied frontier. The original stable quorum-frontier observation must show Mac committed=applied at or beyond that post-delete frontier and strictly beyond the stopped ROG last index.
7. Preserve the original stop order and count: ROG2, then Mac1, then Pocket3. Preserve the stopped Mac once-read and its directory/file identity, CRC/EOF, bounded parsing and publication checks. Continue only if the full persisted predicate below passes.
8. Leave quarantine, empty pair startup, real sealed election, later Pocket3 rejoin, actual pair3→1 gate, unseal, all original history/readindex checks, extra12 cold scope, final original deletion sequence and all owned cleanup unchanged. If the actual empty leader is not Mac1, stop before target unseal as before.

The create/read/delete protocol supplies real committed changes even when stopping ROG2 removes a follower. It avoids relying on a noop request: existing native noop-config and delete-missing tests explicitly prove such requests do not advance the native frontier. The witness is an actual new write and actual removal. It does not invoke an administrative election or insert forged Raft data.

The proposed report must replace the misleading label `new_readonly_preparation_seconds` with an explicit preparation label and disclose **two synthetic mutation attempts maximum**, with one new body/path pair each. A new failure before either dispatch leaves the corresponding attempt unissued. The original ledger's public projection remains hashes only.

## Complete persisted relation proposed for review

Let `L(x)=(x.leader_id.term,x.leader_id.node_id,x.index)` and `V(v)=(v.leader_id.term,v.leader_id.node_id)`, after the existing closed-schema, non-bool u64 checks. These are the exact advanced-leader comparators, not index-only comparisons.

Retain all original constraints which bind the actual leader, passive local frontier, readback and application index, and strengthen the structural relations:

- old committed and old last are present; `L(old_committed) <= L(old_last)`.
- Old committed index is at least the actual ROG applied index captured before its owned stop.
- Both old and new persisted votes are committed.
- New persisted vote leader ID equals new committed LogId leader ID.
- New committed leader ID equals the actual leader identity observed in the preparation quorum and is node1 or node3.
- New committed index equals Mac's last observed applied index, is strictly larger than old last index, and is at least the post-delete witness frontier.
- **`L(new_committed) > L(old_last)`.**
- **`V(new_vote) >= V(old_vote)`.** This permits the same already committed leader to append a later entry while rejecting any regression behind a stopped persisted vote.
- **`L(new_last) >= L(new_committed)`**, retaining the original independent index inequality as well.
- The once-created, once-deleted witness is known complete, Mac's actual content/absence checks passed, and all shared deadline publication checks passed.

This is an explicit proposed replacement for the term-only comparison. It is not an implicit deletion of the existing safety gate. The original index-growth guard remains. The evidence remains a preparation proof and never substitutes for the actual final leader observation.

A narrower alternative is available if desired: preserve the old higher-term branch byte-for-byte and admit a second branch only when old last, old committed, old vote, new committed and new vote all name exactly the same leader ID, with all witness/full-LogId/index constraints above. That narrower form solves the observed Pocket3-stable case while refusing more valid but unneeded cases. No implementation choice has yet been authorized.

## Original history, cleanup, and export scope

The existing `history_reads` addresses only `self.path`, versions1–19; versions1/2 are deleted/destroyed and17 large versions remain readable. `metadata` compares that same path's exact version set. `small_reads` addresses only `self.acknowledged`. Original `finish_application` constructs `[self.path,*self.acknowledged]` and deletes in that exact order.

The separate witness must not enter any of those collections. Its known removal occurs inside preparation before quarantine. The original final deletion list/order and original98 check names/conditions thus remain exact. The original98 contains no snapshot-export/restore validation; its report explicitly lists that as uncovered. This proposal does not transfer official snapshot or PhaseB qualification.

The two intended native mutations change the run's actual log and may leave unreachable ciphertext. This is not described as byte-identical storage. Quarantine/recovery/reference capture must continue using this fresh run's actual inventories and actual restored reachable-leaf set. No prior leaf count such as338 is asserted, and no orphan is required to become reachable. The extra12 cold check still binds only the same successful recovery scan's actual captured leaves.

## Bounds, evidence, and necessary validation before any fresh live request

- Product remains canonical495033 with the already qualified normal binaries; no product build is required for this proposal.
- Original98 and extra12 denominators stay separate; preparation assertions/events are not added to either denominator.
- Original2400 total/HTTP15/admission8/sealed election60/foreground lifecycle limits stay unchanged. Preparation60 and postcold300 share the original absolute controller cap; no budget is renewed after dispatch.
- Existing24 prior fences remain. Add the failed B summary, exit, authority and exact dispatch as four explicit old-failure fences in the future controller.
- All mutation intents, outcomes and any unknown remain durable. No additional write/delete is attempted after unknown; no restart of the failed fixture.
- A future small source delta is limited to the B runner's witness helper/caller and explicit numeric comparator, accurate report fields, plus the launcher fresh-path/pin/fence changes. Existing numeric/cipher readers and deadline QA copies should remain byte-identical unless a concrete review blocker requires otherwise.
- Before runtime review: exact base/diff, original98/check-order and finish-application identity checks, parser/schema/source pins, and pure cases for equal/older/newer complete LogIds, same-term node ordering, higher index under an older term, vote regression, uncommitted vote, absent/full-u64 shape, unknown create/delete and expired-parent no-dispatch.
- Actual success still requires full final summary plus terminal exit0, all owned cleanup, all prior fences, original98 and distinct extra12. The current failure is never reclassified by later evidence.

## Pending decision

Root source review is requested for the explicit two-mutation witness and full-comparison predicate. The packet contains existing-source evidence and this proposal only. There is no replacement runner, no prepare/live dispatch and no request to run a host.
