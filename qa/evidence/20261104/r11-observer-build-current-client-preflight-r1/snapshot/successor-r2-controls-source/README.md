# Observer successor 3cb8739: fresh ROG source and normal-build controls

This is a source-only control packet for commit 3cb873919170cc77101b27f6a3ab9e98f41f8d93 / tree 7f4d48a647a81ca96e8a24a0a057c2c829459060. Its only product-source change from bf0aaec is the explicit local Result<Option<NativeV6IngressRead>, String> annotation. The previous normal build is a retained failure, not a successful precursor. The main PR remains on 6d3040.

## Fresh layout and unchanged execution

New ROG root: /home/qian-qi/heptabao-phaseb-fresh-ingress-observer-normal-20261104-r2. The prior r1 root is read-only input. Source stage creates only this new root, independent Git checkout and public control files. It performs no compiler, HeptaBao, provider, snapshot or production operation. Both source stage and normal build require their separate root authorization and exact stable keys in DISPATCH.v4.json.

The original normal runner is retained as complete original bytes: 20791 B / c46efcee52b0b836f8c6539e86a02114c10828b0a295f4571178643dcc0f0273. The six original groups still contain exactly 44 tests. Seven existing ingress/timing tests remain separately recorded under the same shared 600-second extra-group cap. Source stage retains Git90 / clone180 clamped to its original NEW300 stage budget and NEW330 external cap. Normal build retains release1800, Linux libtest3600, listing30 and six runtime600 caps, plus the accepted NEW12000 aggregate supervision. No cap, feature, profile, retry or test predicate changes.

## Narrow differences

The stage and launcher bind the new commit/tree, new r2 root and source history 3755. The chain is 3cb8739 -> bf0aaec -> 6d3040 -> 495033. The original R10 clone source and all R8/R9/R10 launcher gates remain. New source validation checks the exact one changed runtime file and the complete independent Git tree/index/worktree. The full canonical Git tree was independently retrieved and all 358 tree objects verified; its 3911-leaf index is 5cb27cb400dc0896da98a5d4c740f2d5c9a83b6c60eb59dbec4eb7acd1a6ce00 over 62194197 tracked bytes. Reversing the one runtime leaf reproduces the prior actual stage index 4257a2bae92cb041ed45920b2ed9d4c8ae35d4db54da7073e6a3ef29a5fcd1fd.

Both controls add a fixed failed-observer fence. The stage reads the old bf0 clean source identity and exactly 12 known files before and after its work. These include the original stage result, admission, build intent/result, child receipt, both complete Cargo logs, original three Python controls/group file, and the failed runtime source. Each read uses the existing same-FD/name/owner/nlink/whole-byte checks. The new fence additionally retains named identity before and after each read and requires the whole before/after fence record to be equal. It never opens old private credentials or native data.

The fourth carrier member is the exact 726-byte authoritative failed-job terminal receipt, copied without reserialization into the fresh control directory. This is a preserved authoritative observation, not a newly queried job status and not a fabricated file on the old host root. Its job ID, failed exit 1, durability, no-timeout and no-retry semantics must match the original failed core and Cargo child. The same failed-fence record must still equal the stage receipt in the normal launcher's admission, before exec. Root acceptance after a future build must retain the distinction between these recorded admission fences and any independently obtained post-build observation; the unchanged runner does not gain a hidden post-build old-root scanner.

The two schemas advance only to describe these new control records. All existing launcher function bodies are unchanged. All existing stage function bodies are unchanged except the three exact runtime size/SHA/blob literals. No new runtime result is claimed by source span equality; the source-invariance receipt describes textual comparison, not Python execution.

## Actual failure preserved

Old job: 1a1a87f578a-fc05-2ee0. Authority failed exit1; Cargo exit101 after62.09384498698637s under1800, direct child reaped and no remaining group. Original44 and extra7 did not run. Complete failed packet tree94bc1904b020caebc231f14fa3a5992156f77a86 binds raw logs, all original SDK/payload evidence and the original bf0 source-stage packet. This successor does not restart that job or reuse its root/key.

## Phase B boundary

No Phase B execution is authorized by this packet. After actual normal release and all required tests pass on this exact new source, public artifact/source transport and a fresh concrete binding still require review. The already reviewed Phase B main61210/10816, four retained helpers and all business deadlines remain. The planned binding filename is binding.private.json, as required by the unchanged custody guard. Existing unresolved artifact hashes remain unresolved. Earlier B01 remains unknown and its live-r1 material is never reused.
