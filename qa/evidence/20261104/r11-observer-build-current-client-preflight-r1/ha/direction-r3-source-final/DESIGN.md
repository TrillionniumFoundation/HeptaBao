# Direction98 R3: real two-voter frontier before the original missing-cipher election

Status: source-only draft, not executed. Product source remains canonical 49503322c7f446e5eb41e7744f1fdbd7f1192ecc / tree 1d4211f91e1b34a2ed087a3bbef2e2884bac88e9. The completed R10 full128 qualification and previous direction98 uncovered result remain separate.

## Observed basis and limits

Direction98 R2 completed 87 original checks and stopped before the target unseal because the actual empty leader was ROG2 rather than Mac1. Its original 45 mutating intents all have known outcomes, and original cleanup was completed. This is an uncovered direction, not a measured cold-recovery failure.

The approved R4 diagnostic read only the already-stopped Mac1 and ROG2 stores. Both ended with committed Vote(term2,node2), committed and last LogId(term2,node2,index61), and 62 contiguous retained entries. Current-epoch CRC and exact EOF checks passed. These are terminal-state facts; they do not reconstruct exact earlier startup state or prove the unique historical election cause. No state-machine file was read. R4 also did not independently rebind the final raft/log directory names to their parent descriptors; that limited scope remains on the R4 evidence.

Exact OpenRaft v0.10.0-alpha.34 Git sources at dfee06ca9a8193f061149ce784caa6bcbe92a0c4 show that leader restoration defaults true, committed self-votes may restore leadership, and pre-vote does not advance persistent term/vote by itself. HeptaBao selects advanced LeaderId ordering and enables pre-vote. This explains why a short Mac listener-start lead alone is not a sufficient election control. These Git sources are not independently verified local registry-cache bytes.

## Narrow behavioral change

The original three complete real cold-unseals remain first. Pocket3 is still selected solely as the intact ciphertext source. Before quarantine, the original three stop calls are reordered from1/2/3 to2/1/3 with a guarded observation between them:

1. Read the ordinary passive sys/leader response on ROG2 and retain only role, committed index, and applied index.
2. Execute the original stop(ROG2), without changing its lifecycle implementation or stop budget.
3. Start one NEW60-second absolute preparation deadline. Once, read ROG2 stopped numeric metadata with the fixed read-only helper. Its original per-read ceiling remains15 seconds; the original-wrapper style SSH timeout is at most45 seconds and is clamped to the remaining preparation time.
4. Under that same deadline, observe only Mac1 and Pocket3 using ordinary real GET health/sys/leader calls. Each call receives min(2 seconds, remaining), and the loop/sleep/publication all recheck the same deadline. Health200 must carry the real ready-leader flags; more than one actual leader is refused. Require one actual leader stable for2.2 seconds and Mac committed==applied, caught up through that leader's committed index, beyond stopped ROG2's last index. No mutation, forced election, metadata edit, or retry of a process is introduced. At most512 polling rounds are retained; exhaustion refuses.
5. Execute the original stop(Mac1) and stop(Pocket3), with deadline checks after each original call. Keep the original missing_cipher_targets_stopped check in place. Once, read stopped Mac1 numeric metadata, still within the same60-second deadline and with the same15-second per-read ceiling.
6. Before quarantine, require Mac's persisted committed index to equal the actual passive Mac applied index observed in step4 and exceed stopped ROG's last index. Require the new committed term to exceed both ROG's stopped last-log term and stopped vote term. Both votes must be committed, Mac's vote must identify the same leader as its committed LogId, and that leader must be the actual observed node1 or3. No late preparation completion is accepted.

If a new committed frontier does not form, or any metadata/deadline condition is unavailable, this one fixture stops. The proposal does not promise every natural pre-state will satisfy this stricter preparation. There is no loop that restarts a fixture until a preferred role appears.

After this preparation, the original quarantine, start1/2, sealed-pair60-second election observation, source3 rejoin, actual source3/empty-leader1 guard, target unseal, exact history, real leaf restoration, remaining-node unseals, and final checks remain byte-for-byte. The final actual leader guard is still mandatory; numeric metadata never substitutes for it. It still stops before target unseal on a wrong actual role.

## Reader and process boundaries

The helper is bound to only the new node1/node2 R3 paths and the actual generated run ID. It requires the private owner marker, root and raft0700, marker0600, per-node observed descendant modes, owner UID, ordinary files, nlink1, O_NOFOLLOW, bounded sizes, stable descriptors, exact EOF, CRC and closed serde shapes. It never calls Rust open_existing or repairs a journal. It returns only numeric metadata, file hashes and identities, not entry payloads.

This helper adds the missing directory check: each held directory records its parent FD and basename, and final fstat must match a no-follow stat relative to that same parent. Root is checked too. The existing file relative-name and FD checks remain.

The runner calls unchanged base.ssh, whose own argv contains BatchMode and ConnectTimeout10. During the unchanged native.execute_fixture context, strict_shared_transport wraps base.checked_run and injects StrictHostKeyChecking=yes for SSH. This describes the existing wrapper, not an option unconditionally present in base.ssh itself; no SSH configuration or route is changed. The shell execs the pinned interpreter into the helper, which starts no children and writes no files. Every numeric dispatch is recorded before launch; each node can be dispatched only once. A failed or uncertain SSH return aborts the fixture with remote_completion_unknown preserved. Successful completion requires the SSH exit plus a bound, complete helper response within both remote and caller deadlines. No caller error is an excuse to replay the read or business operation. Original service cleanup remains separate from the explicit numeric-dispatch completion records.

## Preserved contract and new bounds

- Original required set98; all ten original missing-cipher check names and order remain.
- Original five QA files, product commit/tree and ten artifact/build pins remain.
- Original normal features, real fsync/ReadIndex, no diagnostic product features remain.
- Original HTTP upper15 seconds, admission8 seconds, inner whole-QA2400 seconds, sealed election60 seconds and stability2.2 seconds remain.
- NEW preparation budget60 seconds starts only after original stop2 completes and includes both numeric calls, the live quorum observation, original stop1/3 and proof publication.
- Numeric reads remain at most15 seconds each and are clamped to preparation remaining; their SSH wrapper is at most45 seconds and likewise clamped.
- No added mutating HTTP request; only ordinary GET metadata/health observations.
- Three original stop calls in this block remain exactly three on the success path.
- New fresh R3 controller/work/node paths and four R2 failure fences extend the prior16 fences to20.
- The new reader's source is SHA-pinned in runner, launcher, prepare, and final source checks.

## Review/validation status

This package is source-only. No R3 fixture, preparation, helper, parser test, or syntax process has executed. The provided textual preservation check restores the one replacement stop block and exactly reproduces the previous R2 missing_cipher_leader method; it is not a runtime test. Root independently parsed the draft1 three new sources as AST without importing/executing them. The final single-sample completion-clock change and explanatory SSH comment have not executed. Actual syntax/contract preparation and controlled runtime need the root's reviewed window.

Prior evidence remains immutable:
- Direction R2 core tree a6f41fcc1ae5a251c8198e4539568da937fb1668.
- R4 scoped numeric tree cc9db8c7d3962fce1e108212bff71611e1fbe700.
- R4 source/reference tree 6d54fc9dfc854459a8e23546b6bea45303a74eb2.
