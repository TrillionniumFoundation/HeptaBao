# R10 native snapshot pending ownership — new source analysis R1

Identity: heptabao.native-snapshot-pending-ownership.r10.r1. This is a new source-only analysis of canonical 49503322c7f446e5eb41e7744f1fdbd7f1192ecc / 1d4211f91e1b34a2ed087a3bbef2e2884bac88e9. It does not restore, inherit or approve the unavailable earlier relay drafts. No product code was edited and no runtime counterexample was executed.

## Conclusion

The safe integration point is the existing affine snapshot Pending/finish path, with an explicit bounded request-settlement owner added before any outside-lock peer effect. NativeRequestBinding is only a negative-outcome binding. It is not the Actor, an archive-delivery capability, a completed peer receipt, or authority to allocate another deadline. Retaining or copying that binding alone cannot make a streaming relay safe.

The current HTTP final-lock failure is a real source-level ownership boundary: it returns 503 and drops the admitted Pending instead of calling Service completion. Current outside-lock work only exports or stages/parses the archive; the actual historical Begin/root CAS remains inside the later writer-held finish. Therefore this analysis does not assert that this existing branch already loses a committed restore. A future relay which lets the remote leader commit before origin finalization crosses a materially different boundary and must retain a durable uncertain-outcome reference.

## Verified current ownership and effects

| Boundary | Exact current source | Consequence |
|---|---|---|
| Standby decision | [service_snapshot_transfer.rs 374–457](https://github.com/TrillionniumFoundation/HeptaBao/blob/49503322c7f446e5eb41e7744f1fdbd7f1192ecc/crates/heptabao-server/src/service_snapshot_transfer.rs#L374-L457) | The current redirect is selected before authentication, finite-use debit, archive staging and JSON forwarding. Mandatory local request/307 response audits run. A redirect destination is routing data, not Actor admission. |
| True admission and source capture | [stage_snapshot_transfer 487–719](https://github.com/TrillionniumFoundation/HeptaBao/blob/49503322c7f446e5eb41e7744f1fdbd7f1192ecc/crates/heptabao-server/src/service_snapshot_transfer.rs#L487-L719), [historical preparation 201–222](https://github.com/TrillionniumFoundation/HeptaBao/blob/49503322c7f446e5eb41e7744f1fdbd7f1192ecc/crates/heptabao-server/src/service_snapshot_v6_ha_restore.rs#L201-L222) | The plan holds the original Principal, namespace/path, clock/deadline, seal, base/root selection, HA Arc and spool lease. Historical source capture is explicitly after real finite-use debit; it must not revive old token uses. Preparation captures a source, not a historical root commit. |
| Negative custody moves | [plan 95–135 and take 715–719](https://github.com/TrillionniumFoundation/HeptaBao/blob/49503322c7f446e5eb41e7744f1fdbd7f1192ecc/crates/heptabao-server/src/service_snapshot_transfer.rs#L95-L135), [binding 22–35 / 126–175](https://github.com/TrillionniumFoundation/HeptaBao/blob/49503322c7f446e5eb41e7744f1fdbd7f1192ecc/crates/heptabao-server/src/service_native_v6_writer.rs#L22-L175) | The native failure binding moves out of ambient Service into the plan. Its code comments deliberately exclude publication/delivery/time authority. Cancellation must not leave an unrelated binding on idle Service. |
| Affine outer request | [service.rs 1304–1311 and 3635–3643](https://github.com/TrillionniumFoundation/HeptaBao/blob/49503322c7f446e5eb41e7744f1fdbd7f1192ecc/crates/heptabao-server/src/service.rs#L3635-L3643) | Pending also owns the original fingerprint, token clock, wall-clock observation and ingress, not merely the transfer plan. Serializing a few plan fields is not equivalent to carrying this owner. |
| Outside-lock I/O | [transfer execute 197–288](https://github.com/TrillionniumFoundation/HeptaBao/blob/49503322c7f446e5eb41e7744f1fdbd7f1192ecc/crates/heptabao-server/src/service_snapshot_transfer.rs#L197-L288) | Download consumes its prepared source once. Upload reads bounded chunks into the owned spool and parses the archive. These branches do not perform the actual historical Begin/root CAS. |
| Final writer unavailable | [HTTP execute 338–397](https://github.com/TrillionniumFoundation/HeptaBao/blob/49503322c7f446e5eb41e7744f1fdbd7f1192ecc/crates/heptabao-server/src/http_snapshot.rs#L338-L397) | After external transfer, failure to reacquire the writer within the original deadline returns 503 directly. Pending is dropped and the Service finish/audit path is not called on that branch. No 200/file capability is released there. This is a source finding, not a reproduced runtime failure. |
| Original custody returns | [finalize 828–879](https://github.com/TrillionniumFoundation/HeptaBao/blob/49503322c7f446e5eb41e7744f1fdbd7f1192ecc/crates/heptabao-server/src/service_snapshot_transfer.rs#L828-L879) | Completion refuses unrelated ambient binding, restores the exact plan binding, re-enters the original deadline and checks HA/seal/activation/recovery state. Historical restoration then runs through its dedicated original-Actor owner. |
| Real restore and terminal gate | [historical receipt 41–55](https://github.com/TrillionniumFoundation/HeptaBao/blob/49503322c7f446e5eb41e7744f1fdbd7f1192ecc/crates/heptabao-server/src/service_snapshot_v6_ha_restore.rs#L41-L55), [completion 745–901](https://github.com/TrillionniumFoundation/HeptaBao/blob/49503322c7f446e5eb41e7744f1fdbd7f1192ecc/crates/heptabao-server/src/service_snapshot_v6_ha_restore.rs#L745-L901) | Successful restore retains original Auth separately from restored Auth. Terminal clock, mandatory audit, exact installed epoch/root, current quorum proof and original Actor checks precede successful delivery. A post-commit veto preserves the operation reference, fences and prohibits retry. |
| Completed forwarding | [completion types 19–150](https://github.com/TrillionniumFoundation/HeptaBao/blob/49503322c7f446e5eb41e7744f1fdbd7f1192ecc/crates/heptabao-server/src/ha_forward_completion.rs#L19-L150), [delivery 217–574](https://github.com/TrillionniumFoundation/HeptaBao/blob/49503322c7f446e5eb41e7744f1fdbd7f1192ecc/crates/heptabao-server/src/service_forward_delivery.rs#L217-L574) | CompletedForwardReceipt is constructed only by the authenticated exchange and is affine. MAC, nonce, request/response digests, prefix, audit proof, actor/owner and original deadline are checked before and after local audit. A Ready acknowledgement is not this receipt. |

## Minimum proposed change, not existing implementation

### 1. Preserve one real admission owner

The inbound peer handler should invoke the actual native snapshot admission once under the writer, with the original request deadline and authenticated enrolled-member transport context. It must retain the entire resulting PendingExternalRequest. A peer Ready may identify an admitted transfer slot; it cannot authorize arbitrary content, imply a completed restore, or allow the origin to reauthenticate the token later. The original Principal, post-debit source and historical original-Auth checks remain inside the existing plan/finalizer.

At the origin, keep routing and authenticated exchange custody distinct from leader Actor admission. Do not consume the client's finite token once at each node. Do not use the newly restored Auth owner as a replacement for the original admitted Actor. Existing before-authentication redirect refusals are not evidence that a new stream was admitted.

### 2. Add one bounded, non-authorizing settlement slot

Before the admitted plan leaves the writer, transfer its negative completion custody into one uniquely keyed settlement cell. The plan carries the matching affine guard; Service retains an observer for that exact cell, not an ambient native_request_binding from another request. The cell binds the original fingerprint, token clock/start/deadline, nonce/data-dir, intended direction and operation/exchange identity. None of these fields grants Actor or payload authority.

The slot has explicit states such as admitted, outside-I/O, terminal-audited, cancelled-before-restore, and unsettled-effect-possible. Normal finish claims the same cell once, restores the negative binding and consumes it only after terminal handling. An abandoned guard can mark only its own cell; Drop must not block on the Service writer, perform network/audit I/O, grant a new budget, silently inject a binding into idle Service, or manufacture a successful audit. Capacity is reserved/bounded and exhaustion refuses admission within the existing deadline.

This is a proposed ownership contract. Its atomic transitions and exact authenticated durable representation still require implementation review; an Arc or an enum alone would not prove crash recovery.

### 3. Close negative audit without disguising effect status

| Known state at loss/cancellation | Required behavior |
|---|---|
| No admission occurred | Preserve the existing routing/refusal audit behavior; no token debit, archive authority or restore completion is claimed. |
| Admission occurred, no historical/remote effect was dispatched | Do not refund or replay the actual finite-use debit. Retain the original request's negative settlement/audit obligation. A provably no-restore cancellation must not be mislabeled as committed restore or indiscriminately poison unrelated requests. |
| Remote effect may have been dispatched, or local root CAS was attempted | Return no successful body/file and no replay permission. Keep the exact operation reference and an unsettled fence until read-only reconciliation establishes the authoritative state. A timeout or missing final message is not evidence of no effect. |
| Terminal audit/final custody fails after a completed restore | Preserve the existing historical uncertainty semantics: clear deliverable data, retain reference, block unsafe delivery, and require reconciliation. Re-running admission/upload is not a recovery action. |

Negative settlement after an expired HTTP budget must not extend that original business request. If final writer acquisition fails, store a bounded unsettled obligation accessible to a later guarded maintenance/recovery path, rather than dropping the last owner and pretending completion was audited. Later reconciliation may close a negative record; it cannot revive a successful response or authorize the original action again. Mandatory negative audit failure remains a fail-closed condition, with the scope of the fence explicit.

### 4. Persist uncertainty before crossing the remote effect boundary

A memory-only cell disappears on process death. Before the remote endpoint can perform a restore, there must be an exact operation identity whose admission/effect status survives either endpoint restarting. Reuse the actual historical restore Begin/Stage/CAS/reconciliation owner for the restore itself. The relay also needs authenticated durable handoff/settlement metadata which maps that actual operation to the original exchange and negative audit obligation. Do not invent success from an unmatched audit row or treat the existing in-memory NativeRequestBinding as such a journal.

Only a read of the authoritative current operation ledger may resolve an uncertain exchange. No reconnect, new grant, token re-login, replayed upload, reconstructed Actor or same-path request can convert missing completion into known rejection. The current source analysis has not implemented or qualified this durable handoff; it is an explicit remaining prerequisite.

### 5. Publish completion only after the existing owner finishes

The leader may issue a dedicated completed stream proof only after the actual native owner has finished its terminal clock, mandatory response audit, original-Actor and installed-root/epoch checks. Bind the proof to the actual archive descriptor length/digest, exact exchange nonce/direction and original deadline, plus real effect identity/prefix/audit facts. A download should remain in a bounded owned spool until this proof and local terminal delivery gates pass.

The origin validates that completed proof under the enrolled member transport and original HA/seal custody, obtains the necessary real current prefix/owner checks, runs its mandatory terminal audit and only then publishes the response/file. If the origin's final writer is unavailable, it retains the unsettled obligation and withholds the file or success response. It must not relabel a Ready response or deserialize untrusted metadata into CompletedForwardReceipt.

Existing ha_forward.rs uses closed JSON request/response profiles with specific size bounds; neither a 32 MiB profile nor a root-SSH original-reply profile is a generic archive stream authority. Add a separately closed streaming exchange rather than encoding an archive in those JSON frames or raising their limits.

## Necessary focused validation when an implementation exists

1. Cancel after real admission but before restore dispatch: exact token-use accounting, one negative settlement and no unrelated idle-Service binding pollution.
2. Lose final writer acquisition after upload parsing: no successful response, no hidden restore invocation and no new deadline.
3. Lose origin finalization after the leader's actual committed restore: real new epoch/state, exact recovery reference, no repeated upload/admission, no success before audit.
4. Change seal, HA Arc, original Actor or ownership between Ready and finalization: actual gates veto; restored Auth does not replace original Auth.
5. Fail negative/terminal audit and exhaust settlement capacity: bounded resource use, explicit fence, no silent deletion of unsettled custody.
6. Restart either endpoint with an unsettled operation: reconcile from authenticated durable state without re-executing it.
7. Verify byte/length/digest framing and final proof independently from audit status and CLI exit code; keep all original 15 s / forward 8 s limits.

These are implementation gates, not executed results. Phase B CLI qualification remains a separate fresh runtime fixture and cannot establish these failure paths by composition. Full OpenBao replacement remains false.
