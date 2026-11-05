## Why this draft exists

HeptaBao still has release and migration gaps that prevent complete OpenBao 2.7.1 replacement. This draft tracks the implementation and CI work with explicit runtime evidence. Complete compatibility, current client and backup migration, production cutover and removal of old installations remain unqualified.

## Current source change

The current head is `6304a898192bfdf7eabec3c4ea40f7166e59a137`. It retains the private `LocalRedirect` boxing and the two layout regressions from `e5de554f`, and corrects the 18 test-only Clippy diagnostics observed on both CI lanes. Eight test modules change; the production portion of the namespace module and all other 3,903 repository blobs are unchanged. The changes preserve exact I/O error kinds, actual revocation status 204, unwind cleanup, HTTP inputs and all original resource budgets. No lint suppression or workflow relaxation was added.

Run `41937740513` completed both full locked workspace suites successfully, then failed strict Clippy with the same 18 test diagnostics per lane. Later gates were skipped and the final qualification matrix failed. The prior 1,619-per-lane large-error result and the intervening formatting failure remain preserved. The new eight-file correction was formatted by the previously pinned Rust 1.98 tool on ROG in 0.268 s; all eight formatter children were reaped and all outputs were independently read back. The new head still requires fresh CI; formatter success is not compilation, runtime or complete replacement qualification.

The immutable R14 checkpoint below records an earlier runtime state. Subsequent Phase B stage and readonly prepare passed, but the new isolated `3cb87391` live run stopped at B01: the CLI returned exit 2, the server audit recorded a single 503, and no archive was created. Its original server-boundary UNKNOWN classification is retained; B02–B05 and cold restore did not run. Mac's finite public-code observation identified exactly two 0775 parents and a distinct read-cap/file-identity comparison defect; their narrow source correction has not yet qualified the five-agent runtime.

## Current evidence checkpoint

[R14 report](https://github.com/TrillionniumFoundation/HeptaBao/blob/3a6b62142a9c632006c99364b2a987a30dca46e9/docs/validation/HEPTABAO_36076_MAC_X230_LAN_CHECKPOINT.md) · [machine-readable current state](https://github.com/TrillionniumFoundation/HeptaBao/blob/3a6b62142a9c632006c99364b2a987a30dca46e9/qa/evidence/20261104/r14-ha-prepare-source-import-mac-caller-r1/root-review/current-state.public.json)

R14 is an immutable checkpoint as of **2026-11-05 01:56:28 UTC**. It mounts 26 reviewed evidence packets, 596 packet files / 11,302,670 bytes and 33 root records. Every packet blob and all 113 packet Merkle directories were verified; the full new repository tree has 8,059 blob leaves and 996 verified trees. All 7,428 pre-existing non-document leaves and all 75 prior index fields except the top-level timestamp remain unchanged.

| Gate | Actual evidence | Remaining blocker |
|---|---|---|
| KV2 and migration | Existing X230 31/31 on `49503322`; separate normal `3cb87391` build passed original 44 plus separate 7. Canonical bundle and artifacts reached desktop. A new independent local Git import verified 3,755 commits and all 3,911 tracked blobs, fsynced the tree and closed all 21 Git groups and eight held descriptors. | Fresh Phase B stage/prepare/official-CLI save/restore and current off-host backup remain unqualified. The old B01 UNKNOWN result is preserved. Independent archival of all 21 command-log triplets was pending at R14. |
| Physical Mac/ROG/Pocket4 HA | B2 actually passed 91 of the original 98. It recovered Pocket4 ciphertext into an actually elected empty Mac leader and verified 17 large versions plus 338 referenced leaves / 35,742,423 bytes. | Subsequent node2 cold unseal returned known 503 in 9,423.826 ms. Seven original checks and all separate 12 post-recovery-cold checks remain missing. All 16 started server identities and six Mac foreground sessions were stopped and reaped within the original deadlines. |
| AuthBus without J3160 | Corrected complete Mac 18-source packet and real inert append passed. Fifteen new files were read back exactly; six prior sources and all 54 identity values were unchanged. | The unique actual five-agent runtime exited 1 at a public SDK parent-custody guard after 0.250873 s, before private credential capture, SQLite, consumer or service startup. The exact failing parent still needs finite read-only diagnosis. All owned descriptors and the sole diskutil process closed; outcomeUnknown=false. |
| Per-host cutover | Existing finite Mac/X230/ROG observations and exact current-input guards remain recorded. | Real current-credential read/write, restart, rollback, service-wrapper and backup-path qualification is incomplete on all hosts as a set. No production cutover. |
| Cleanup | Historical results, failed attempts, originals and current source/build identities are preserved. | Client and backup migration prerequisites are unmet. No old OpenBao or HeptaBao service/binary deletion. |

## Scope and evidence rules

`49503322` is the scoped Mac/Linux runtime frontier, `3cb87391` is the separately built observer frontier, and `6304a898` is the current PR head. Qualification is not transferred among them. Prior independent 128-check and 98/98 HA runs are retained and are not summed into the failed B2 run.

B2's two once-only witness mutations returned 200 and 204 and were followed by exact Mac read and data/metadata-absence checks. The committed frontier advanced from `(2,2,61)` to `(3,3,66)` through the original higher-term branch. The new same-leader branch was not covered in this run. The original 2,400 s controller, 300 s extra phase, 60 s role preparation, 15 s HTTP and 8 s admission budgets were unchanged. No forced election or unseal replay occurred. The final 49 intent/outcome pairs were being independently archived after R14; a 503 status alone does not establish its internal cause.

Mac's actual failure is `InputRefused` at `readonly_input_parent_custody_or_exact_held_anchor`. The raw outer `errorCode` was null; source-stack analysis identifies the predicate but cannot identify the rejected directory from this log. Nineteen public source records and fifteen aliases completed. No private frozen input or production database was opened, and no owned launchd phase began. Public OpenSSL help advertised repeated `-addext`, but that is not a TLS-generation qualification. QA launchd would also not by itself qualify production KeepAlive behavior.

The historical 59-surface ledger targets OpenBao 2.6.2. The 69-check official 2.7.1 corpus is bounded to 13 families. Neither establishes a complete 2.7.1 route × operation × configuration × lifecycle denominator. Source-only registry maps and action lists do not close the missing runtime surface.

No J3160 or provider/model/refresh/quota request, production initialization, unseal, load, cutover, guard weakening, unknown-outcome replay or legacy deletion was introduced.

## Next concrete work

Complete and review the fresh Phase B actual stage, binding, prepare and CLI archive/restore lifecycle; diagnose the known node2 recovery-unseal 503 from exact source and retained public evidence; identify and repair the Mac public SDK directory binding without relaxing custody; then run the remaining real credential/restart/inverse, current backup and per-host cutover gates. Full replacement and deletion stay false until their actual evidence is complete.