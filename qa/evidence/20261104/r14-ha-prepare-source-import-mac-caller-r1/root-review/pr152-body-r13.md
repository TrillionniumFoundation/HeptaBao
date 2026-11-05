## Why this draft exists

HeptaBao still has release and migration gaps that prevent claiming complete OpenBao 2.7.1 replacement. This PR tracks the implementation and CI work together with explicit runtime evidence. It remains a draft: complete compatibility, production cutover, current client/backup migration and removal of old installations are not qualified.

## Current source change

The current head is `e5de554f5dfe99f0de30012122fe3e248fb60532`. The latest implementation change boxes only the private optional `LocalRedirect` payload in `Response`, preserving the public by-value extraction behavior, serialization refusal, custody checks and deadlines. Two layout regressions cover `Response` and `HaRecoveryIndexAdmissionFailure`. The follow-up commit applies the exact Rust 1.98 formatting change without changing expression tokens, workflow commands, lint thresholds or time budgets.

The previous `6d3040a` run completed both workspace test lanes but failed strict Clippy with 1,619 `result_large_err` diagnostics per lane. The subsequent `fab39e28` run stopped at formatting. Both failures and their original logs remain preserved. The current run `41937740513` passed formatting in both lanes and was still in complete workspace tests at **2026-11-05 01:06 UTC**. Current strict Clippy, measured new layout sizes and complete CI success are not yet established.

## Current evidence checkpoint

[R13 report](https://github.com/TrillionniumFoundation/HeptaBao/blob/fa489bfbda996dba77744c7387301711e41fcf9e/docs/validation/HEPTABAO_36076_MAC_X230_LAN_CHECKPOINT.md) · [machine-readable current state](https://github.com/TrillionniumFoundation/HeptaBao/blob/fa489bfbda996dba77744c7387301711e41fcf9e/qa/evidence/20261104/r13-mac-sqlite7-utilities-source-transfer-r1/root-review/current-state.public.json) · [all new evidence files](https://github.com/TrillionniumFoundation/HeptaBao/blob/fa489bfbda996dba77744c7387301711e41fcf9e/qa/evidence/20261104/r13-mac-sqlite7-utilities-source-transfer-r1/root-review/packet-manifest.public.json) · [checkpoint commit](https://github.com/TrillionniumFoundation/HeptaBao/commit/fa489bfbda996dba77744c7387301711e41fcf9e)

| Area | Verified result | Remaining qualification |
|---|---|---|
| Formal KV2 | Existing X230 31/31 on `49503322`, 34 MiB active payload and 19 lifecycle versions remain valid in their recorded scope | Current production migration and current encrypted off-host backup; actual fresh Phase B CLI save/restore and cold recovery |
| Normal observer build | `3cb87391`: normal default-feature build, original 44 tests and separately bounded 7 tests passed | These results do not qualify the PR head or the fresh snapshot CLI |
| Source and artifacts | Complete 23,335,023-byte canonical bundle exported with strict full fsck; three public release artifacts transferred to desktop with source/stream/same-fd readback hashes equal | Canonical source transfer/import, local Phase B stage, prepare and live are not complete |
| Three-host HA | Prior original 128/128 and separate Pocket3 → empty Mac1 original 98/98 retained | New B1 stopped at direction preparation: 83 original checks passed, 15 missing, zero of the 12 new post-recovery cold checks reached |
| Mac AuthBus prerequisites | R2 owned SQLite 7/7 and six actual system-utility file pins verified | Five-agent current credential capture, complete consumer cycle, actual launchd restart and inverse recovery |
| Current client inventory | X230 finite read-only inventory passed. ROG observed all 46 fixed entries and completed all queries | ROG correctly exited 1 because the old config pin differs from independently reobserved current config; finite inventory is not whole-host migration |
| Production and cleanup | Existing evidence and recovery assets preserved | Per-host credential read/write, restart, rollback, cutover and all client/backup paths must qualify before deletion |

### Material details

- **Mac R2** job `1a1a918c6cf-fc05-3143` exited 0 in 0.231131 seconds under the original 45-second controller budget. The actual held-inode guard and immutable SQLite write refusal ran, followed by final source/runtime checks. Production inputs were not opened. The earlier R1 5-pass/1-fail/1-unrun result remains unchanged.
- **Canonical export** job `1a1a928b8b0-fc05-321b` exited 0. All 27 Git children were reaped; 25 exited 0 and two expected no-partial-config queries exited 1. The bundle has zero prerequisites and SHA-256 `25020ee42fe92f95c9408cb937dc507430f18b84fdaef7ec438a0a233de1438b`.
- **Artifact transport** job `1a1a92c7f34-fc05-3248` exited 0 in 2.384357 seconds under the original 300-second controller budget. Only the normal server and two public reports were transferred. Trust files, source controls and original 90-second endpoint budgets were unchanged; owned processes were reaped.
- **HA B1** job `1a1a9094b62-fc05-30ab` is a retained known preparation failure. Stopping an already-follower ROG did not create a new committed frontier. All 45 mutation pairs were observed, but the final read-only health GET had no observed response. The scoped mutation unknown=0 claim is not generalized to all HTTP. All owned servers and five Mac foreground sessions were stopped and reaped.
- **HA next preparation** retains the original higher-term branch and only adds a narrow same-leader complete-LogId/index-growth proof using one owned CAS0 witness and one metadata delete. Exact pinned OpenRaft semantics have been reviewed; source reasoning does not qualify an actual election, ReadIndex or recovered cold restart. No forced leader, unknown mutation replay or budget increase is admitted.
- **ROG current state** independently confirms the new 21,229-byte config hash `6e3659907327039243c60a10b2925edb51e83e4c73f0925c60279ae6a8169819`, six agents, AuthBus disabled/generation 203, and gateway inactive/dead with MainPID 0. Existing hold drop-ins remain unchanged. The old config and gateway were not restored.
- No J3160, provider/model, refresh or quota request occurred in these validation chains. No production initialization, unseal, load, traffic cutover or old-service/binary deletion has been performed.

## Evidence and version boundaries

R13 adds **16 immutable packets / 423 packet files / 4,062,776 bytes**, plus root reviews. Every complete packet blob and all 73 packet Merkle trees were verified; original unsafe JSON integer tokens were preserved. Across the repository, 442 new leaves were added, 6,986 old leaves stayed identical, and only the report and index were updated. All 74 prior index fields other than the as-of field were preserved.

The qualified LAN/KV2/Pocket AuthBus product remains `49503322`; the separate observer build is `3cb87391`; this PR head is `e5de554f`. Qualification is not transferred between those commits. The historical 59-surface ledger targets 2.6.2, and the existing 69-per-side corpus covers 13 bounded families; neither establishes a complete 2.7.1 denominator. Native profile guards remain intact.

[Previous PR body, retained verbatim](https://github.com/TrillionniumFoundation/HeptaBao/blob/fa489bfbda996dba77744c7387301711e41fcf9e/qa/evidence/20261104/r13-mac-sqlite7-utilities-source-transfer-r1/root-review/pr152-body-before-r12.md) contains earlier history. The R13 report retains the full R12 and earlier report text. The original snapshot B01 unknown result remains preserved and has not been replayed.
