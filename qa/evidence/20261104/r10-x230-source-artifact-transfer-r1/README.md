# X230 R10 standalone source and artifact transfer — source review

## Current authority and scope

This is a new source and artifact preparation flow. It is not an execution of the 31-check full34 suite or the two 69-case acceptance runs, and it does not inherit their R8 results. The current R10 Linux and Mac normal44 gates and the shared desktop artifact input gate have independently passed. The new desktop full-source export has also completed with a separate root review.

The current source-only receiver is 24,595 bytes, SHA256 5de344fdae21c1852513f21b891121246cff649b2fff001c2791c026ebb70521. Its only change from the separately reviewed 24,529-byte draft is an os.walk onerror callback that re-raises the original scandir error. The old draft and review remain available. No X230 transfer or product process has run under this packet.

## Fixed route and new paths

The controller runs on desktop. It uses the already captured strict x230-ts identity: hostname 192.168.0.13, user qian, port 22, HostKeyAlias hepta-node-x230, IdentitiesOnly yes. It pins the original desktop SSH config and hepta-transport known_hosts bytes, retains strict host-key checking, disables multiplexing, agent forwarding and host-key updates, and preserves the original single connection attempt and ten-second connection timeout. It does not introduce a no-ProxyCommand assumption.

Controls will be create-only under /home/qian-qi/heptabao-ha-closure-20261103-r1/normal-r10-x230-transfer-controls-r1. The parent evidence root is /home/qian-qi/heptabao-ha-closure-20261103-r1/normal-r10-x230-transfer-r1. The receiver creates only /home/qian/heptabao-blocker-closure-r10-49503322-20261104-r1. It neither opens an old X230 repository nor assumes an old prerequisite exists.

The three existing R10 desktop artifacts are read from normal-r10-shared-artifacts-r1/incoming. The bundle and export receipt are read from normal-r10-x230-source-export-r1. Every source file is bound to exact size, SHA256, mode, device/inode/size/mtime/ctime version, UID 1000 and one link. No private credential is read by these scripts; SSH uses its existing configured identity normally.

## Transport and ownership

A local sender and a remote X230 receiver share one SSH stdin stream. The sender uses the unchanged reviewed same-FD implementation: verify all five files before payload dispatch, stream exact bytes, verify each stream digest and all original identities afterward. The sender's functions are unchanged from the already executed shared artifact sender. Only the fixed file table and schema changed.

The receiver requires exact concatenated lengths and trailing EOF. It creates each file exclusively, verifies bytes and SHA, chmods and fsyncs the same FD, rereads that same FD and compares its identity with the still-pinned path. It preserves both build receipts verbatim; only the normal build receipt's target basename changes to result.public.json for the existing X230 controllers. The original proof record still names its original ROG build path.

The receiver verifies native-build and normal-build source, binary, ABI, default features, original raw receipt digest, successful build and cleanup fields. It also verifies the exact previously qualified export receipt and standalone bundle header. The export receipt is evidence of source preparation; its own success is not inferred from a candidate status alone. Its real authority and terminal were independently checked before admitting this fixed input.

The remote Python command carries the exact reviewed source as the original -c argument and its SHA. The receiver hashes sys.orig_argv's actual -c text and writes that source into its new control directory. It accepts no alternate source path or executable.

## Standalone source materialization

The 20,091,909-byte Git v2 bundle has SHA256 6fb2b73c52a880475ce8c45c67a4179575834313ee24ed761af94ea3faaaa858, exactly one HEAD at 49503322c7f446e5eb41e7744f1fdbd7f1192ecc, and zero prerequisites. The new source is cloned directly from this bundle with no hardlinks. There is no borrow or alternates phase on X230.

Admission requires the exact tree 1d4211f91e1b34a2ed087a3bbef2e2884bac88e9, sole parent 1d12abc45a83d4b32e7185d01a876eb93110b1e2, root 67d79b3b5442ed033d38929eab2010403463e56d, 3,752 commits, full strict fsck, clean independent .git, no partial or shallow clone, no alternates, grafts, shared commondir or sparse checkout. The 3,911 expected tree entries must equal the index; every actual worktree file must match its real Git blob, executable bit and pinned FD/path identity. The full new source walk rejects symlinks and hardlinks, propagates traversal errors, and fsyncs the files and directories. This does not claim that old X230 roots were recaptured or globally quiescent.

The receipt is new artifacts/transfer.result.public.json. It is initially private 0600; other received raw data files are 0400 and the binary is 0500. The new root/artifacts/control directories remain private 0700, matching the original X230 preparation contract. No server binary is executed.

## Exact deadlines

The parent keeps a single 300-second monotonic deadline. The local sender remains at 90 seconds. The remote receiver keeps the original X230 300-second envelope, default Git limit 60 seconds and clone limit 90 seconds; every command is capped by its original enclosing deadline. The parent grants that remote source operation its 300-second cap, always bounded by the parent's original deadline. This is an explicit change from the shared artifact receiver's 90-second child because that receiver did no Git materialization. There is no timeout retry or new request budget.

Root has accepted a NEW outer supervisor cap of 360 seconds for this source transfer. It is not presented as a recovered old X230 outer value. Cleanup can consume its existing bounded wait only to stop owned children; it cannot restore a successful deadline.

Separately, root has specified NEW 1,800-second outer caps for the later full34 and comparison69 wrappers. Their old outer values were not recovered. All original inner HTTP 15-second and migration 360-second limits and all original 31/69 business assertions remain unchanged; no timing equivalence to the old outer caps is asserted.

## Failure and durable completion

The owned Git lifecycle comes from the already reviewed R2 source controller. Spawn registration defers Python cancellation only across Popen plus registration. Cleanup signals only a directly owned live child group; a reaped group is observed rather than signalled. The original bounded TERM/wait/KILL/wait handling and final group checks remain in place.

An unknown SSH result, malformed endpoint result, deadline crossing, SHA/identity drift, partial stream, clone/fsck/materialization failure or cleanup uncertainty fails the chain. The new partial target remains for inspection. The controller does not retry the operation, replay input, delete an old root or start acceptance tests.

The parent's success requires both real zero exits, complete endpoint records, exact source and target file records, receiver Git proof and clean groups, unchanged trust/source/helper pins, and publication within the original deadline. The receiver's formatted receipt is a candidate result until its final terminal and real exit are known. Failure after receipt fsync does not turn into admission. The remote completion flag remains false until the full receiver record has been validated; local SSH cleanup never proves remote cleanup by itself.

## Review and next steps

Root and Compat have reviewed receiver v1; root requested only the fail-closed os.walk correction included here. Root has accepted the complete parent and sender and the receiver walk-error correction. Compat has independently reviewed the complete three-file source chain without a blocking finding. Source code has been frozen in Git objects, but these new three files have not been compiled or executed on a host.

After the current HA quiet window and a separately coordinated transfer window: distribute the three source files with the already reviewed create-only carrier, compile-check and read back their exact bytes, run this transfer once, then collect its full receipt/authority and independent target file_info. Only after that gate will the comparison wrapper's single pending transfer-receipt SHA be replaced with the actual accepted SHA. That later frozen wrapper and root authorization are prerequisites for the 31 and 69 executions.
