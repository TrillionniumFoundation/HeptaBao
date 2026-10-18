# HeptaBao replacement continuation — 2026-10-18

Production replacement remains **HOLD**. No production clients have been switched and no old OpenBao services or binaries have been removed in this continuation. Passing component suites do not establish full OpenBao 2.7.1 compatibility.

## Exact candidate and completed evidence

R8o server source is commit `e0f95a38850a4a3b0220112eff27e2e32efb7742`, tree `13b9b3cebfe27272134a7addf1905a412f0e47df`. Both native build receipts verify all 2,706 files against this saved Git tree before and after the build. The new Durable local epoch primitive below is a separate, later candidate and is not in these server binaries.

| Evidence | Actual result | Scope |
| --- | --- | --- |
| Mac R8o 14 groups | 111/111 | Immutable ciphertext reuse, strict KV2 projection, native capacity, migration/recovery internals |
| Mac native build | PASS | arm64; binary SHA256 29fe1dfa3c20eb770d3747fa8e75d8709fa0ccd40d9409646ac908c70938b870 |
| Linux native build | PASS | x86_64 GNU; binary SHA256 1e20753a54ea1f44508aac3f26bb1500462dca5637097479161266eeba912960 |
| Recovery harness | 19/19 | Private original init custody; once-only mutation intent and ambiguous-outcome retention |
| Mac service archive R1 | 7+1 PASS | Real service HA export and exact-current-root binary repair; patch retained |
| Mac service archive R2 | 6/7, FAIL | Additional live Durable owner checks compile; damaged-gzip negative test fails at line 196. This is not an approved candidate. |
| Linux atomic epoch publication | 4+11+8 PASS | Actual local root/cursor/epoch publication and FileIntent recovery. Does not implement historical HA restore alone. |
| AuthBus clock R3 | contracts and actual SDK PASS | Same-process clock/deadline fencing; cold same-epoch recovery remains unqualified |
| AuthBus final dispatch R1 | 12 contracts; 30 actual SDK checks PASS | Actual shared LLM path, SQLite, loopback HTTP, DNS/redirect expiry and failed revoke. Synthetic credentials; not every product caller. |

Receipts are in [resumed-20261018](../qa/openbao-acceptance/evidence/resumed-20261018/). Preserve each receipt's own source/patch hashes and scope flags; do not sum these counts into a compatibility score.

## Physical HA attempts

1. R8o attempt 01, Mac–ROG–Pocket4, failed at node 3 listener admission before native capacity or failover. Pocket4 UFW allowed the established HeptaBao lab ports 46230/46231 from 192.168.0.4/.7/.10; the new 47450/47451 ports were not admitted. All newly owned processes were stopped. Failed receipt retained.
2. Attempt 02 reused only the established permitted ports and fresh roots. All six directed peer mTLS handshakes, three API leaf pins, three initial unseals and real native activation passed. The subsequent exact read on Mac follower failed after forwarding to Pocket4 leader. The fixed error digest is SHA256 of `HA peer transport failed`; it does not identify the underlying I/O stage. This remains a product blocker. Both request budgets remain 15 seconds HTTP / 8 seconds native admission; no mutation retries.
3. X230 Ethernet 192.168.0.13 is up with carrier and direct reverse LAN routes. UFW currently has no HeptaBao API/Raft admission. The earlier X230 listener timeout cannot establish an ISA failure: its log shows that the HA TLS listener started. X230 physical qualification is still pending.

## AuthBus boundaries and next implementation

The separately retained owned-source R2 publication evidence used one actual OpenAI OAuth credential version from its true main/desktop SQLite owner, without contacting J3160. It did not perform OAuth refresh or establish refresh ownership.

R3 fixes in-process wall/monotonic rollback and charges awaited SDK transactions to the original deadline. A separate cold-instance reproduction shows that reaccepting the same epoch/grant through a caller-supplied verification callback can reopen an old deadline. R4 must require a new trusted epoch and bind bootstrap identity, assignment and refresh ownership to an actual TLS/AppRole/KV2 CAS document.

Final-dispatch R1 reaches the real shared LLM completion/fetch route. Expiry during DNS and redirect awaits, failed SQLite revocation, wrong wire credentials, missing capability and older epochs produce zero unauthorized receiver requests. Production bootstrap, derived runtime credentials, non-LLM callers and OAuth refresh ownership remain open.

## Remaining replacement gates

- Finish native historical HA restore through actual committed begin/stage/CAS, durable lineage and crash/restart evidence. Current-root repair and local epoch publication are insufficient.
- Verify lossless OpenBao 2.7.1 KV2 migration beyond the old raw-record/transaction limits, including retained, deleted and destroyed versions.
- Resolve mixed-host native forwarding, then run the unchanged full capacity/leader-kill/reelection/ReadIndex/persistence/restart/missing-cipher suites on Mac–ROG–Pocket4 and Mac–ROG–X230.
- Finish independent trusted AuthBus issuance, production caller coverage, actual renewal/revocation, then per-host real credential read/write, restart and rollback before traffic cutover.
- Refresh the OpenBao oracle: the old 59-surface/472-case corpus is scoped to 2.6.2; several strict profiles are pinned to 2.7.0. The 2.7.1 Control Groups repeated-approved-wrap behavior and HA rate-limit quota service behavior remain concrete compatibility gaps.
- Reconcile every client and backup path before removing old services, binaries or regenerable intermediates.

This checkpoint preserves working code, successful evidence and failed evidence. It is not a production migration or a full-replacement declaration.
