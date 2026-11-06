# Public Node --version comparison: original actual chain

## Result and scope
Original job `mac/1a1b2feebf1-fc05-8067` completed with controller exit 0, complete durable output and confirmed terminal publication. The exact 11,541-byte stdout is retained without reformatting; stderr is empty.

The restricted arm ran the exact previously observed 6,909-byte consumer.sb profile and real Node binary with `--version`. Its child PID 11162 terminated with known exit -6; retained WNOWAIT status is code 2 / status 6. Its stdout and stderr are both empty. The matched public baseline without that test profile used the same Node binary, explicit environment, cwd and HOME; PID 11171 exited 0 and returned `v25.9.0\n` (8 bytes). No JS entrypoint, SDK, provider, credential, listener or launchd action was requested.

This comparison establishes a difference associated with the test-profile invocation for this exact public experiment. It does not identify a particular rule or underlying libignition failure. The unrestricted baseline does not qualify SDK execution. It does not reconstruct old private business progress or establish the cause of an older abort. Those scopes and historical UNKNOWN remain unchanged.

## Original observations and closure
There are exactly 11 original Native calls: one process_start, two operation_start, two operation_status, and six operation_result calls. Both observers completed/inactive before their immutable payloads were reconstructed: authority has one 8 KiB page, streams has five pages at offsets 0, 8192, 16384, 24576 and 32768. No original operation, Native page or business action was replayed, and this run has no transport error or reconciliation path.

Both direct children have their actual custody and retained exit records, were reaped, and have empty groups before and after reap. No cleanup signal was sent. All 14 returned application descriptors closed: four fixed-input descriptors, six control-root descriptors and four empty-root descriptors. Both final HOME fences passed. The original 45-second deadline and restored handlers passed; elapsed time was 0.1172417919151485 seconds. The descriptor scope excludes interpreter/loader-internal descriptors. Path execution is not represented as atomic exec-by-FD, and the empty directory was not exhaustively inventoried after the children.

The final context has no pending call, active observer or Native future. A has released its observation lane. No further Native action is authorized by this completed packet.

## Reproduction interface
Evaluate `pure-helper.original.js` followed by `original-chain.verifier.js` in a plain JavaScript environment with no host calls; call `verifyNodeVersionComparisonR1OriginalChain(files)`, where `files` maps each exact flat path in this tree to its original UTF-8 string. This verifier was actually executed once over the captured originals and passed all 356 checks. It does not execute the controller or source component.

The verifier checks each external request/intent/armed Merkle binding, original SDK-before-native contents, exact original IDs, completed/inactive states, immutable offsets/totals/SHA/base64 payload reconstruction, native payloads, stream hex/text/EOF, authority, and actual result/closure semantics. Correct stdin typed digest and uint64 fingerprint are compared with the frozen GO and actual START ACK; the old pure helper's unrelated stdin_text binding routine is not invoked.

## Immutable inputs
GO `be3fda34d624811838bfd20bfe3fe018c90f7213`; source `20eac10fb145c74da8915d114bafaf1575f745b8`; exact request `983e0a1699b05466ce4f29a4daa4b578d331d7d7`; journal `dabdffa04433d6a5890ed033ffaf85d864924571`. Source31 remains a separate immutable packet `82d50e15efc1508c052f8a750ed845d8ffdfc205`, including the preserved first source-checker whitespace comparison failure and its comparator-only correction.

The standalone minimum release tree is `f5e41e0250c59dee3d05f387879c8f0643470dcf`. Its release object is byte-identical to RELEASE.public.json here. The Linux 576 normal-release phase declaration is not promoted to whole-build or issuer qualification: root has reported the full build failed exit 1 and its final report/artifact identity gates remain outstanding.
