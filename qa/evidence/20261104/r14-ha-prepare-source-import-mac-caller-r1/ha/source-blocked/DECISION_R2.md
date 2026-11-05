# B R2: one committed witness, then a narrowly bounded same-leader proof

Status: source-only candidate. No inert, prepare, live, compiler, SSH, or product operation is submitted by this packet. Product remains canonical `49503322c7f446e5eb41e7744f1fdbd7f1192ecc`, tree `1d4211f91e1b34a2ed087a3bbef2e2884bac88e9`.

## Preserved failure and decision

The sole B R1 operation `1a1a9094b62-fc05-30ab` ended with `direction_new_committed_frontier_not_observed`: 83 original checks passed, 15 original checks were not reached, and none of the 12 added cold checks ran. Its stopped ROG log and committed vote named leader `(term=2,node=3)` at index 61. During 190 bounded preparation observations the available leader was node 3 and the observed committed/applied indices remained 61. Stopping a follower alone did not demonstrate a new committed entry. This is a known preparation failure, not a post-recovery cold result.

The complete failed core/SDK tree is `02c5afd1ca16d7df65680089dde0ba69d029b788`; the 90 mutation metadata and original SDK tree is `1e96e9c25850e07182850b6861fd576a505dcb86`. Root independently verified them in blob `220bc755ce81649b58b7cdb4d961d6ea485348e0` (1,592 B, SHA256 `e5a95a1320c1add4ebbb3e7dbc5ccb982295d217ce824105d08fd5b9918ed412`). Its 45 mutation intents/outcomes were known, but the last readonly node-3 GET had no observed response; mutation-ledger unknown=0 is not an all-HTTP completion claim. Original failed roots, files, and operations remain unchanged. Four exact failed-B files are added to the previous 24 fences.

The earlier proposal/source packet `fd34be3d1b05d186b0966e0e9562171ae2ace9d9` remains intact. Its generalized comparator option is not implemented. This candidate adopts only the narrower same-leader alternative selected by root. Root's independently verified upstream semantic review is blob `3d6a2b3c8969fabf14d4ca722e71e4cddd48a09d` (2,667 B, SHA256 `7a6768f639f5f8fdf1a5185cb740cccdc53b41d30f61b686440b9671eb85b3ad`).

## Exact new preparation sequence

The original cold synchronization and the first stop of ROG node 2 remain unchanged. After that stop, a single absolute preparation deadline is `min(now + 60 seconds, original controller deadline)`. The original controller still has 2,400 seconds and the proposed supervisor has 3,000 seconds. There is no new reset on reads, writes, stops, polling, or publication.

| Step | Actual operation and required evidence |
|---|---|
| 1 | Read the already-stopped ROG numeric files once with the pinned reader. Bind `oldLast`, `oldCommitted`, and committed `oldVote`; validate full order and closed unsigned-64-bit fields. |
| 2 | Observe one actual unsealed, application-ready leader among running Mac 1 and Pocket 3. Confirm `sys/leader.is_self` and its passive committed/applied indices. This does not choose or force a leader. A new GET transport exception stops this witness helper. |
| 3 | Once only, POST CAS0 to `secret/data/native-ha-<this fixture run_id>/direction-prepare-witness`, with one synthetic small value and a body below 1 KiB. Require original durable intent/outcome, known HTTP 200, integer version 1. |
| 4 | Use the existing exact small-read path on Mac 1, with the same deadline, to verify the generated data digest and version 1. Do not add this key to `history` or `acknowledged`. |
| 5 | Once only, DELETE `secret/metadata/` for that exact witness key. Require original durable intent/outcome and known HTTP 204. There is no error/finally cleanup mutation and no automatic replay. |
| 6 | Require Mac data absence and Mac metadata absence; also require data absence on the actual leader if it differs from Mac. Capture leader and Mac passive frontiers. The leader's committed/applied index must exceed both the stopped ROG's last index and its own pre-write committed index; Mac must be applied through that frontier. |
| 7 | Retain the original 2.2-second stable quorum observation in the same 60-second deadline. Its actual leader must remain the witness target and its index must retain the post-delete frontier. |
| 8 | Preserve the original stop order 2, then 1, then 3, with exactly the original three stops. The latter two now receive the same preparation parent deadline through the already-reviewed optional-deadline QA adapters. |
| 9 | Read stopped Mac numeric files once. Require the full stopped-Mac order, committed vote, passive-frontier equality, witness completion, and original budget. Then use one of the two validation branches below. |
| 10 | Continue the original quarantine, empty pair startup, natural sealed election, donor-3 rejoin, actual empty-leader-1 guard, unseals, history, same-scan recovered-reference capture and ReadIndex observations. No new branch bypasses the actual pair guard. |

ROG remains stopped from step 1 through step 9. It does not produce the newer term or index. The extra log entries are created by the real running 1+3 quorum through the one CAS0 and one metadata delete. The comparison at step 9 is between the newly stopped Mac's actual log and the earlier stopped ROG's actual old log. This is not an inferred clock order or a fabricated leader result.

Both mutations use the existing `NativeRun.request` and `FixtureRecoveryLedger.begin/outcome`. They have at most 15 seconds each, further clipped by the one parent deadline; native admission remains 8 seconds. The helper records the sequence numbers, requires exactly two new known intent/outcome pairs, and checks the global ledger still has no unknown. Unknown write/delete, an unexpected known status, an incorrect Mac read, retained metadata, a changed leader, or expiry prevents further new mutation and stops the fixture. A second helper invocation is refused before any read or write.

## Two separate numeric branches

The existing `_direction_verify_prepared_frontier` function is retained in its entirety, byte-for-byte, including its strict higher-term condition, proof, deadline, and publication logic. A new wrapper performs common full-order and witness checks. If the original higher-term relation holds, the wrapper calls that unchanged function; an exception does not fall back to the new branch.

The new same-leader branch accepts only when all five leader IDs are exactly equal:

`leader(oldLast) == leader(oldCommitted) == leader(old committedVote) == leader(newCommitted) == leader(new committedVote)`.

It additionally requires both votes actually committed, the actual leader to be 1 or 3, strictly greater numeric index, the original applied-index equality, and the same post-delete witness frontier. No same-term/different-node alternative is accepted. A boolean, negative, out-of-u64, unknown-field, missing, or noncommitted numeric structure is rejected.

Common order is the pinned OpenRaft order `(term, node_id, index)`: `oldCommitted <= oldLast < newCommitted <= newLast`. Committed votes cannot regress; the new committed vote must name the new committed leader, and no last-log leader may be ahead of that committed vote. The stopped ROG committed index also cannot regress behind either of its pre-stop committed/applied observations. The new Mac committed index must equal the original passive Mac-applied observation and retain the witness's post-delete index. These common guards strengthen validation; they do not replace or weaken the original higher-term function.

The original legacy `new_total_prepare_elapsed_seconds` formula is preserved with the higher-term function. If the 2,400-second controller clips the 60-second preparation interval, that field counts consumption against the 60-second ceiling and is not a new independent wall-duration measurement. Absolute-deadline checks remain authoritative in either branch.

## Exact upstream basis and limits

The complete upstream tree, commit membership and selected sources were verified in the earlier source packet and root review above. Primary sources are pinned to OpenRaft commit `dfee06ca9a8193f061149ce784caa6bcbe92a0c4`, actual tree `df6167c8f3075dd570ef6a6c7962af0ddddff42a`, tag `v0.10.0-alpha.34`. Canonical Cargo.lock selects that package version and checksum `06fe14d529f8fc098fbb4b9655d5db9b7ee0594e6a9d4e220aa931618de17b1f`.

- [Advanced LeaderId](https://github.com/databendlabs/openraft/blob/dfee06ca9a8193f061149ce784caa6bcbe92a0c4/openraft/src/vote/leader_id/leader_id_adv.rs) derives order over term then node ID; committed LeaderId is the same type.
- [LogId](https://github.com/databendlabs/openraft/blob/dfee06ca9a8193f061149ce784caa6bcbe92a0c4/openraft/src/log_id/mod.rs) derives order over the full leader ID then index.
- [Engine startup, vote and pre-vote](https://github.com/databendlabs/openraft/blob/dfee06ca9a8193f061149ce784caa6bcbe92a0c4/openraft/src/engine/engine_impl.rs) compare the candidate's full last LogId against the local last LogId; pre-vote does not write a new persistent term or vote. Startup can restore a committed self-vote when configured.
- [Type declaration defaults](https://github.com/databendlabs/openraft/blob/dfee06ca9a8193f061149ce784caa6bcbe92a0c4/openraft/src/raft/mod.rs) and [canonical type declaration](https://github.com/TrillionniumFoundation/HeptaBao/blob/49503322c7f446e5eb41e7744f1fdbd7f1192ecc/crates/heptabao-raft-runtime/src/state_machine.rs) bind u64 term/node and the advanced LeaderId implementation.
- [Canonical runtime node configuration](https://github.com/TrillionniumFoundation/HeptaBao/blob/49503322c7f446e5eb41e7744f1fdbd7f1192ecc/crates/heptabao-raft-runtime/src/process/node.rs) enables pre-vote and retains the upstream restore default; [actual network RPC](https://github.com/TrillionniumFoundation/HeptaBao/blob/49503322c7f446e5eb41e7744f1fdbd7f1192ecc/crates/heptabao-raft-runtime/src/process/network.rs) carries real vote and pre-vote requests.

For the strict same-leader case, both empty stores retain committed votes naming the same old leader. In particular, if that leader is Pocket 3, neither restarted empty node has a committed self-vote to restore. A ROG candidate presenting its older full last LogId cannot obtain Mac's vote/pre-vote under the up-to-date rule. Mac's larger full LogId is eligible under that rule. This supports the controlled preparation; it does not guarantee network timing, successful election or Mac leadership. The unchanged actual `source=3 / empty leader=1` guard remains the only direction qualification. There is no forced leader, persistent-vote editing, term editing, restart loop, or retry-until-lucky.

These source bindings do not independently verify the physical hosts' registry cache or `.crate` archive bytes. The selected source semantics are not promoted to actual-run evidence.

## Original workload and storage scope

The witness path is fixed within this new run's namespace and cannot alias the history key or any acknowledged key. The code captures the original `path/history/retired/acknowledged` maps before dispatch and checks their exact canonical bytes after the Mac read and after deletion. The original methods for 19 lifecycle versions, 17 active large versions, all original finish deletions and cleanup are unchanged. The original 98 check names and the separate 12 post-cold names/order are unchanged. The witness is preparation evidence, not a new check counted into either denominator.

Two extra real mutations intentionally change the Raft log and may leave unreachable immutable ciphertext. This candidate does not claim byte-identical storage. The witness metadata is deleted before quarantine. The recovered ciphertext reference remains the actual captured set from the original recovered scan of this same fresh fixture; the cold reader binds that set, exact leaf identities and hashes. No leaf count such as historical 338 is hard-coded or borrowed.

The two numeric/cipher helpers contain fixed root literals, so they receive only the new R2 node-root bindings and R2 basenames. Their function bytes, parsing, no-follow/named descriptor checks, size/CRC/EOF bounds, modes and 15-second limit remain unchanged. The four optional-deadline QA files and build probe are whole-byte unchanged. The launcher receives fresh roots, the resulting pins, the witness contract assertions and the four failed-B fences. The inert carrier changes only its fixed control path and nine source pins.

## Validation and remaining gates

The offline final component run executed 130 checks with exact AST-selected candidate methods and original request/ledger methods, using only in-memory clock, HTTP and ledger-storage adapters. It covered known success, unknown write and delete, no replay/cleanup-after-error, incorrect Mac data, retained metadata, pre-expiry no dispatch, known late response classification, full-order/vote/type negatives, strict same-leader acceptance, unchanged higher-term acceptance and full original-function byte identity. It also verified helper literal-only changes, all nine payload pins, carrier binding-only AST delta, all 24 old fences plus four exact failures, unchanged product/build/QA inputs, and unsubmitted dispatch bounds. There were zero network calls, host calls, product processes or child processes. These are source/components, not actual CAS, HA, cold restart or runtime qualification.

`DISPATCH.proposed.json` binds the concrete carrier, payload and new control paths; every stage remains unauthorized, and live's prepared SHA is null. Required next gates are root's whole-source review, separately authorized inert and prepare, actual terminal/readbacks, and a new exclusive runtime window. Any actual failure/unknown must be retained under the new identity without replay. The R1 failed operation and earlier R3 successful direction qualification remain separate.
