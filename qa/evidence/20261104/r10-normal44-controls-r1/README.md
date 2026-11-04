# R10 normal 44 controllers - source-only review packet

This packet prepares the next isolated normal build and test attempt. It does not execute a host command, compile Rust, run a test, start a service, transfer an artifact, or update a GitHub commit/ref. The R9 source and failed result remain separate.

## Fixed candidate and source scope

- R10 canonical commit: 49503322c7f446e5eb41e7744f1fdbd7f1192ecc.
- R10 tree: 1d4211f91e1b34a2ed087a3bbef2e2884bac88e9.
- Sole parent / common physical base: 1d12abc45a83d4b32e7185d01a876eb93110b1e2, tree e1faeaa3ed49d26fb01a7617a8879cb693a12907.
- Complete parent ancestry contains 3,751 commits; R10 contains 3,752. Root commit remains 67d79b3b5442ed033d38929eab2010403463e56d.
- The sole changed repository file is crates/heptabao-server/src/service_no_forwarding_ha_tests.rs, mode 100644. Before blob 5614d8249c36d66fa037238f36e40360d7b45593; after blob 89da5923651abd6d8ea87479bb66520375f7fe3d, 16,529 bytes, SHA256 3c5e9b2e8f306786e1c5ce1ef1a02b5442bb1dc12e9de08bfed78e0dfcec808f.
- Root already reviewed and published that canonical test-only change. The remaining 12,674-byte suffix beginning at finite_actor is unchanged. This controller packet does not introduce another product change.

## New roots

ROG base is /home/qian-qi/heptabao-native-ssh-owner-20261104-r1. The new root is r10-native-state-helper-r1, with source, control, build-control-r1, and normal-release-tests-r1 beneath it. Its old source is r9-http-routing-r1/source.

Mac base is /Volumes/T5/hepta-vnext-recovery-20261013. The new root is continuation-20261104-native-http-r10 with the same four child paths. Its old source is continuation-20261104-native-http-r9/source. Mac must first finish the separately reviewed R2 canonical resume; the R10 stager refuses f0c or any other materialized identity in place of canonical 1d12.

Every new root, source control output, retained binary, and receipt uses a fresh path or exclusive creation. No R9 or R8 result is rewritten. A failed fresh attempt is retained and is not automatically re-run.

## Minimal runner reuse

The Linux and Mac combined runners each change exactly three lines from their fetched, whole-hash-verified R9 originals: the title, fixed tree, and receipt schema version. All function bodies and all other bytes are unchanged.

The exact groups file is unchanged: 6,249 bytes, SHA256 0566f7f98ea16a4c1df43ebaf992172646ad91623c18f68fcc59f7c08b53d1f1. It contains 44 unique fully qualified names in these groups: SSH 25, original mount 1, redirect 5, actor 2, ordinary response 5, and NoForward 6. Every group retains its original 600-second cap and one test thread; exact listing remains 30 seconds. The prior 33-name R8 file is also retained unchanged and the first four current groups must still equal it.

Both retain Rust 1.98.0, normal default features, opt-level 3, codegen-units 16, LTO false, debug 0, debug assertions and overflow checks true, unwind, and the original shared caches. Linux retains one build job and release/libtest limits of 1,800/3,600 seconds. Mac retains two jobs and 1,800/1,800 seconds. Protected Popen registration, TERM/KILL/wait, group observation, failure handling, and retained artifact creation remain byte-identical.

The original build_normal.py is retained only as a provenance control file, as in R9. The combined runner performs the actual build; retaining this file does not invoke a second builder.

## Source stager

The stager is based on the exact 18,846-byte R3 original. Its original owned Git function, signal handler, stop_owned, group observation, stable file reads, create/fsync functions, and ordinary freeze remain byte-identical.

The new bindings permit exactly the single approved test file and the exact 44 groups. The same independent local clone uses --no-hardlinks and no alternates/shared common directory. Original per-Git 90 seconds and independent clone 180 seconds are unchanged.

The Mac diskutil UUID check keeps its original 30-second process cap and exact UUID FB804D1B-24CB-4D6E-AEA7-A9E180807758. It now runs before new ROOT/CONTROL creation. Its direct process uses the same protected registration and owned-group cleanup; its bounded logs remain in memory until the volume guard passes. A guard failure writes no result onto an unverified volume and reports the failed, unpublished result to stdout.

The Git wrapper also disables repository fsmonitor and log signature helpers, lazy fetch and replace objects, and limits protocols explicitly. This follows the already reviewed offline R2 transport safeguards; it does not change the compiler or runtime budgets.

The approved one-file content is materialized and its index tree checked before canonical checkout, retaining the original local materialization proof. The final actual head must be canonical 495033, with a clean exact tree.

ROG alone may fetch the fixed canonical commit from the existing GitHub origin into its new independent clone. There is no alternate remote or retry. It then exports control/canonical-r10-from-r9.bundle, version 2, unique HEAD 495033 and sole prerequisite 1d12. Sole-parent validation and the one-commit difference make this particular bundle boundary exact; this does not repeat the earlier incorrect multi-parent R9 boundary assumption.

Mac receives that bundle separately at BASE/canonical-r10-from-r9.bundle. Its command requires actual byte count and SHA256 from the reviewed ROG export. It verifies a stable private regular file and exact header before file-only fetch, checks identity and full bytes again afterward, and runs full strict fsck and all parent/tree/count assertions. GIT_ALLOW_PROTOCOL=file and explicit protocol policy apply on Mac; its configured https origin is not used for transport. No network fallback exists.

The actual R10 Git bundle does not exist yet. No byte count or SHA for it is invented in this packet. The expanded source payload in payload/source-bundle.json is a different artifact: it carries the one approved file and five frozen controls for the stager, and can be zlib-encoded for its unchanged bounded input contract.

## Launcher and preserved history

The original launcher startup-only target lock probe, platform target-holder inspection, R8 retained release/native/test/libtest gates, source checks, and final exec remain in place. This probe is not described as a build-long lock; root still coordinates the shared target window.

ROG additionally binds:
- R9 failed44 result: 24,242 bytes / b4d3f25c0694dfa7cc24dd3d2a8bdf780ec9eb43716abb61a4581b26c8cc676f.
- R9 normal release: 3,202 bytes / 103bbb68367a13ec3df53a8b437f6e33bd44c75a4ad23a6a792692ef858deb3d.
- R9 native receipt: 793 bytes / 771f53ae44858d9bb73809b997103edfd69bc564e152d9ee40f3a45ca7f854d5.
- R9 retained libtest: 188,176,568 bytes / 9b871dd8d12c063e6ea042d5bb4415d9a042da0e4d18d83fca3e184396879cf4, mode 0500.
- Both R9 release artifacts, their normal feature identities, the real five successful groups and failed no_forward6 group, and complete owned cleanup.

These files remain outside the shared target so later compilation cannot destroy the prior result. The original 42/44 failure is not relabeled or counted toward R10.

Mac has no claimed R9 build/artifacts. Its new checks retain the exact four files of the failed R9 fetch attempt and require the real offline R2 resume result. Before launch, root must preserve the actual R2 terminal stdout JSON and authoritative process_status JSON as create-only files at:
- R10/control/r9-canonical-resume-r2.terminal.public.json
- R10/control/r9-canonical-resume-r2.authority.public.json

The launcher takes separate SHA arguments for those two originals and for R9/control/canonical-resume-r2/result.public.json. It requires the actual result, canonical source, full ancestry check, deadline flag, terminal prepared/publication-within-original-deadline state, and authoritative succeeded/exit0/complete/durable/non-timeout/non-truncated state. A prepared receipt alone is insufficient. These future exact hashes are deliberately not supplied before the actual resume has completed. No R9 build artifact is manufactured to fill that gap.

## Review and execution boundary

All five original controls were read completely from their already authorized ROG paths, with their returned whole-file SHA verified independently. Two auxiliary original controls were also captured without changing them. The R10 test file was fetched from the fixed canonical GitHub commit and its bytes and Git blob verified.

source-invariance.public.json records whole-function source-byte equality for 32 existing functions, both whole-runner three-line reversals, and the original group file. This is static text verification, not a Python AST parse or a host syntax/runtime test. The unavailable shared execution environment was not replaced with an unauthorized host compiler.

The draft objects and diffs may be reviewed through their unreferenced GitHub tree. They do not alter a repository branch or create a commit. Actual payload upload, clone/fetch/export/import, launcher preflight, compilation, and the new 44 tests each remain unexecuted and require root's coordinated execution decision. R9 failure and prior transport failures remain independent records.
