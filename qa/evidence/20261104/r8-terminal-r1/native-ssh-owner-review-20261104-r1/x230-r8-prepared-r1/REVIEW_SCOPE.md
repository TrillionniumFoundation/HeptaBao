# X230 R8 storage and scoped OpenBao 2.7.1 qualification — prepared only

This packet prepares two existing X230 qualification controllers against the normal R8 Linux artifact. It has not created the new X230 root, transferred the release, started a server, or made an HTTP request. R8 is not yet qualified across platforms: the independently retained Mac exact33 run currently has 32 passed and one failed HTTP/TLS component test. These independent X230 gates must report their own complete outcomes and cannot erase that failure.

## Frozen inputs and narrow changes

The original controllers and their successful normal33 receipts were read from `/home/qian/heptabao-blocker-closure-33cafa4c-20261104-r1`. The candidate scripts differ only in string constants: new owned root, physical source commit/tree, normal binary and two normal build receipt hashes, report labels, and a pending new transfer receipt hash. An AST comparison with precisely those string substitutions passed. All request code, numeric limits, case predicates, module selection, cleanup conditions and failure handling remain unchanged.

| Binding | R8 value |
|---|---|
| Fresh X230 root | `/home/qian/heptabao-blocker-closure-r8-384c9576-20261104-r1` |
| Physical Linux commit | `384c957612186d64c5a530044af0ae62c568cc3d` |
| Complete source tree | `d5a0f91a4d47f7c8d5f34170ea167d10dc036e04` |
| Normal Linux server SHA256 | `666370dba0a1e2df4cb2b3177f54b1e190bc2a281aa64fd8501c4625f30e74ed` |
| Normal receipt SHA256 | `f96740372ada668a566aa1b90b2cd8daf463c009de8eed5ba86cb20a2883b8f9` |
| Complete build receipt SHA256 | `2dad4d882854850cbe05825785e77532656da255a11ce7a551969bd7439456a5` |

The normal build receipt was read as exact bytes from the independent HA readback. It records default/native-v6-ha/native-v6-storage features, release opt3/CGU16/no LTO/debug0/assertions and overflow checks enabled, successful build, unchanged source and no owned build-group survivors. No test-fixture feature or altered request budget is introduced. The physical source identity is retained independently from a GitHub publication commit.

The copied `native271_comparison_final_r1.py` remains byte-identical (`fd88ed0b8f1c1010e79f9393dfbf6464cabcac48ece8c6e448a64b7ccc45272e`). The full34 core remains `383176647f0670837f40f3989496c6d1c902f8503dfa006d386b75877436b581`; acceptance remains `8312c400ec5f0946f8a87fb3241bf8db832ddd04763010af7245d6557f55f94d`. Their current X230 whole-file hashes were obtained independently, and exact GitHub 054d source bytes were matched to those hashes after read transport timeouts. Timeouts are not recorded as test failures or successful runs.

## Old SSH refusal audit

Neither the full34 core nor acceptance contains an SSH route or SSH mount refusal expectation. The only `501` in the full34 core is `NativeInstance.start` accepting uninitialized/sealed `GET sys/health` readiness responses `200`, `501`, or `503`; it is not a mount assertion. Acceptance has neither an SSH module nor a `501` assertion. The dedicated native SSH root-owner and mount tests remain separate from these gates.

The unchanged comparison wrapper defaults to thirteen modules and passes that exact set explicitly to acceptance: core, kv, token, transit, pki, totp, userpass, approle, identity, wrapping, edge_tls, system and operations. Acceptance's own independent CLI default has twelve modules, omitting identity; it is not the path used by this wrapper. The controller still requires the original observed inventory of 69 cases on each side, every case passed, none failed or not run, case equality, and complete owned cleanup. No case is removed or reclassified because SSH support was added.

## Necessary create-only staging and review boundary

1. Use a previously verified strict host-to-host transport chain. The controller's `x230` operator mapping alone is not evidence that an alias or identity exists on ROG. The original transfer receipt read timed out; its authenticated transport route still needs to be recovered or independently verified before use. Do not guess SSH identities, disable host verification, or add new trust entries.
2. Create the fresh private root only if absent. Preserve all normal33 roots and original receipts. Transfer the exact normal server, original normal receipt bytes and complete build receipt bytes under `artifacts/`. Preserve the original origin paths inside the build receipts; their destination names are simply `native-build.public.json` and `result.public.json` to retain the original controllers.
3. Create an independent source checkout from the already pinned normal33 source without hard-linked object ownership or a worktree dependency on a cleanup candidate. Verify and import the existing two immutable bundles: normal33→physical R7 (`a0f284839b4a1e781af62464bcea919f938f9037a23f7269c403b4f122ed9244`, 41551 bytes), then physical R7→R8 (`b9a64f258aa6c0ecfac366d57c675d4f9d712edf5f1fe7ddc0929b69d5769aef`, 1259 bytes). Require final HEAD, complete tree and clean status to match the table above. Do not build on X230 or substitute a reconstructed unrelated commit.
4. Verify every transported file with fixed file descriptors, regular/single-link ownership, complete bytes and SHA before and after copying; create-only destinations, private modes, file and parent-directory fsync, and source before/after pins. Save the new transport receipt. Its actual SHA must replace the one explicit `PENDING_CREATE_ONLY_X230_R8_TRANSFER_RECEIPT_SHA256` placeholder in the comparison controller, and the final controller hash/diff must be frozen. The draft comparison controller cannot pass with this placeholder.
5. After runtime GO, run full34 once in its new owned root. Its unchanged HTTP budget is 15 seconds and migration budget is 360 seconds; it requires all 31 original checks, full34 qualification, owned-process cleanup and unchanged source/binary. Do not replay an unknown request.
6. After full34 reaches terminal and owned cleanup, run the original comparison wrapper once in its separate owned root. Preserve the original TLS OpenBao 2.7.1 oracle binary/archive, synthetic fixture initialization, 13-module selection, requests, per-request deadlines and 69-per-side predicates. Do not interpret fixture Shamir 1/1 as a production custody decision.
7. Read and retain exact intent, result, summary, stdout/stderr and authoritative job status for each run. A failure remains that run's failure; no partial phases from another run can complete it. A scoped PASS does not set full replacement, cross-platform, production cutover or full OpenBao compatibility to true.

The actual transfer implementation and final transfer hash binding remain pending review. No production AuthBus config, role, native credential store, service, backup, or old installation is modified by this packet.
