# Exact df026 cold/H2 normal source and build controls — draft 2

Status: source-only review candidate. No source stage, normal build, product fixture or artifact transfer has been submitted by these controls. The completed four-file formatter is a separate format-only result.

## Canonical source

Both hosts must use commit df026fe323dd7cf0f0ec57d7d2d9c5a79897053c, tree 424463ccd2310ddc1e7b2bbcd7b7af29ae58c825, sole parent 6304a898192bfdf7eabec3c4ea40f7166e59a137. The dedicated source ref is refs/heads/codex/heptabao-cold-h2-normal-20261105-r1. PR152 remains on 6304; these controllers never create or update a remote ref.

The root-approved source consists of the original 6304 tree, the four actual formatted files, and exact 3cb ha_native_v6_runtime.rs (3289da21ebb25a1efd04ae0d0fd1013ac7ac8fb3) retaining the existing fresh ingress observations. The controller independently requires 3913 tracked leaves, 62,212,769 tracked bytes, and full leaf-index SHA256 e7fee633b64acffd6520587c85ff6f4206e0b12c7db42a0cdeb36dff66350d54. Every tracked blob, executable bit, index entry and full strict fsck must match.

The complete parent chain between the new commit and actual R10 is df026 -> 6304 -> e5de554 -> fab39e28 -> 6d3040 -> 495033. Each parent is checked individually. The actual anchor count remains 3752; the new actual count must be 3757, with precisely the five declared additional commits and the same original repository root commit.

## Fresh paths and source flow

| Host | New controlled root | Original read-only source |
| --- | --- | --- |
| ROG | /home/qian-qi/heptabao-cold-h2-normal-20261105-r1 | /home/qian-qi/heptabao-native-ssh-owner-20261104-r1/r10-native-state-helper-r1/source |
| Mac | /Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261105-cold-h2-normal-r1 | /Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261104-native-http-r10/source |

Each root contains source, control, build-control-r1 and normal-release-tests-r1. All are fresh, independent and create-only. New source clones use --no-hardlinks --dissociate --no-checkout and an empty template. No shared common Git directory, alternates, promisor object files or hardlinked object files are accepted.

The ROG stager derives from actual 3cb stager 7087d818c7913dcf502e3cf253c439f42f7becf1. It retains the known bf0 failure fences. It fetches only the exact new commit into its new clone with the original bounded Git command, performs full history/tree/worktree verification, and exports control/canonical-cold-h2-from495.bundle. The cut is exactly HEAD ^495033. The five individually verified single-parent links establish the single boundary 495033; the actual bundle header must contain exactly that prerequisite, the sole HEAD df026, version 2 and no capability or extra head. Its size is capped at 4 MiB; the same file is hashed and identity checked around verification and fsync.

The Mac stager uses the same reviewed source lifecycle and the actual Mac R10 diskutil guard, which checks VolumeUUID FB804D1B-24CB-4D6E-AEA7-A9E180807758 before any candidate directory is written. It imports only the local fixed /Volumes/T5/hepta-vnext-recovery-20261013/canonical-cold-h2-df026-from495.bundle. GIT_ALLOW_PROTOCOL=file; no public Git fallback. Actual exported bundle bytes/SHA and an independently verified create-only transport are required before its request can be bound. No transfer is authorized or implemented by this packet.

ROG source is fully bound but awaits root execution approval. The Mac source request deliberately contains UNBOUND_ACTUAL_BUNDLE_BYTES/SHA256. Both build templates deliberately contain UNBOUND_ACTUAL_SUCCESSFUL_STAGE_SHA256. These placeholders must never be submitted; replace them only from whole-reviewed actual receipts and freeze a distinct exact request before a single submission.

## Budgets

| Phase | ROG | Mac |
| --- | --- | --- |
| Source stage shared internal cap | 300 seconds | 300 seconds |
| Source clone / each Git | 180 / 90 seconds, each clamped to stage remaining | 180 / 90 seconds, each clamped to stage remaining |
| T5 guard | not applicable | original 30 seconds, clamped to stage remaining |
| Source outer supervisor | explicitly NEW 360 seconds | explicitly NEW 360 seconds |
| Normal outer supervisor | original 12000 seconds | original 8280 seconds |
| Normal release / libtest compile | original 1800 / 3600 seconds | original 1800 / 1800 seconds |
| Each listing / original six runtime groups | original 30 / 600 seconds | original 30 / 600 seconds |
| Existing ingress 7 / additional cold-H2 9 | separate shared 600 seconds each | separate shared 600 seconds each |
| Direct owned child termination | original TERM 5 then KILL 5 seconds | original TERM 5 then KILL 5 seconds |

The build launcher captures one monotonic start before its original preflight, carries that same value and PID through os.execv, and the runner checks the same PID. Each extra group is bounded by min(group start + 600, original launcher start + outer cap). It cannot receive a new outer budget on exec. The external supervisor starts earlier than the Python launcher and retains its original cap; the carried Python clock does not claim to be a measurement of the supervisor's exact start.

Only additional-group calls use the optional owned(..., deadline=...) path. The original default None behavior and original 44-test loop remain unchanged. The new path checks the same absolute bound immediately before Popen, before wait, and after return. A late exit 0 is marked timed_out and cannot qualify. An expired deadline prevents a new child. Finally and post-publication exit also reject expiration of the carried outer cap. Cleanup retains the original finite limits and never signals an already reaped numeric process group.

The Mac local caps can sum to more than its original outer cap; that does not enlarge the outer cap or promise that every local maximum remains available.

## Exactly 44 + 7 + 9

The original group JSON 302e5d5a5bfe501dcaf75f8c4cfc166acd58ea5f is unchanged: ssh25, mount1, redirect5, actor2, ordinary5, no_forward6. Original test_count remains 44 and original group_results retain that denominator.

The seven existing ingress/timing names are byte-identical to the actual 3cb runner. They run only after original44 succeeds and have their own ingress_observer_regression result. The nine incremental names are listed in TEST_INVENTORY.public.json and run only after 44+7 succeeds, under cold_h2_regression. Every one of the 7+9 selections has an actual --exact --list identity check and requires an actual one-passed/zero-failed/zero-ignored footer. The nine consist of two actual cold observer helper tests, the complete unchanged actual ReadIndex cold missing/corrupt repair test from 45e7121f8d8b567f9ac80b33f8090aceacf8e5ff (original 15-second request bound), and six H2 worker tests. No copied materialize-match simulation or new fixture feature is introduced.

All 60 are disjoint. This count is selected normal-component qualification; it is not a CLI, three-host HA, archive or whole OpenBao compatibility denominator. Actual test names remain predictions until the retained new libtest produces the exact listings.

The normal Cargo commands, default features, Cargo/rustc roots, target directories, offline/locked mode, build profiles, jobs 1 on ROG and 2 on Mac, raw Cargo JSON streams and retained artifact copies are unchanged. The production_changed deployment-fact field remains false in all six controls. Exact commit/tree identify the candidate source changes. A passing older 495/3cb build is only a preservation fence, never new candidate qualification.

## Preserved evidence and source lineage

The ROG launcher retains its original R8, R9, R10 and failed-bf0 fences and additionally binds actual completed 3cb 44+7/source/retained binaries. The Mac launcher retains its original R8 and R9 fences and additionally binds the actual R10 44/source/retained binaries. The two old R9 terminal/authority files are read from their real original R10/control paths; changing the new root must not invent copies in the new control directory.

The ROG and Mac runners respectively derive from actual 7fd97c088c538c7b4d1968964b8d8eaa67826885 and 031ab151262f50ed7db4ecad16cb9c04750c5930. The launchers derive from actual 8909a7add36d43e3be7a5175adb4f184e72f7fed and af34201f8930265a8813028ba6cc21a07166e43d. The Mac stager is explicitly a platform adaptation of the executed ROG source stager plus the executed Mac T5 prewrite function, not a byte-identical rerun of the old Mac stager. Complete bases and six exact diffs are included.

## Validation performed before host admission

All six draft-1 complete Python sources have actual local AST/compile-only success. Draft 2 changes only the production_changed deployment-fact boolean back to false plus the corresponding fixed control hashes, carrier, and request bindings. Strict whole-file inverse checks prove that every behavioral function body, path, budget, test name and caller is unchanged; those component runs are retained under their actual draft-1 source identity and are not relabeled as new executions. Each platform has 27 actual AST-selected runner checks, including default-None equivalence with its original owned function, expired-before-spawn, expiry after capture-open, group/outer clamping and late-zero-exit rejection. These use synthetic clock/process/stream objects: zero actual children, files or network operations.

The path/parser component has 26 ROG and 28 Mac checks. It verifies the actual root/runner/argv clock contract and invokes only the actual selected bundle-header parser on a valid control and seven malformed boundaries. Its first harness mistakenly counted a local argv inside the unchanged holders helper as the actual runner argv; both failed local reports are retained. The corrected harness selects the actual PYTHON-list assignment. Candidate source bytes did not change.

Six strict base-to-draft-1 unified diffs and six tiny draft-1-to-draft-2 diffs reconstruct every final candidate exactly. The original seven helper ASTs and original44 loop AST remain equal on both platforms. These are source/finite-component checks only. No normal build, source stage, SSH, Git command, artifact transfer or product test has been executed by this packet.

Next admissions remain separate: root source review; one ROG stage; exact exported bundle and create-only transport review; one Mac stage; root actual stage review; exact build requests; independent normal builds; complete authority, retained binaries and 44/7/9 records; then separately reviewed X230/Pocket whole-artifact receipt and LAN/client qualification.
