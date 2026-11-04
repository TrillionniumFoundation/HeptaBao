# Independent normal observer: fixed source and build controls

This packet prepares a new ROG checkout and a normal native build of bf0aaec1dcafbf476c0ab3a75544bb0eafaeff24 / ac4027db88fec69381ea0c6bba953d9a99c4e82a. Its sole parent is 6d3040a2dbd06661a67f5c62df259ff446eb8515. The main PR/CI branch remains unchanged. No script in this packet has been dispatched to a host.

## Review order

1. `DISPATCH.public.json` gives the precise fresh paths, source IDs, three control pins, actual dispatch shape, gates, and budgets.
2. `stage_source_phaseb_observer.py` is the new ROG-only source stage. Its complete original 6,183-byte owned-child helper section and 260-byte source freeze function are retained. The original helper file is under `reference-r10/`; the full comparison is in `diffs/`.
3. `launch_normal_phaseb_observer.py` retains all original R8/R9 checks and adds a finite exact R10 source/normal release/native/44-test/retained-artifact fence. It uses the existing target holder and nonblocking lock probe. That probe ends before exec; exclusive scheduling remains a parent responsibility.
4. `normal_phaseb_observer_build.py` retains all eight original functions, the normal release profile, and the complete original 44-test group loop. Only after those 44 have passed does it enter the separate seven-test group.

## Actual source preparation

The fresh root is /home/qian-qi/heptabao-phaseb-fresh-ingress-observer-normal-20261104-r1. The only clone source is the known immutable R10 checkout. Git uses --no-hardlinks --dissociate and an empty template/hooks directory; the new origin is the fixed public GitHub repository. The one fetch names the exact diagnostic commit. Parent links, full strict fsck, 3,754 reachable commits, no alternates/shared object links, and all 3,911 tracked worktree blobs plus index/modes must match. The exact formatted runtime file is additionally pinned at 61,578 bytes / cf0e9e69bf295591d3a904458500bfcf7b01acaa0987ae1da8761f76b9ee136d. Before/after old source commit/tree/status must be identical.

The stage creates only this new root and its files. It compiles the two inert Python controls before writing them, without executing those controls. It does not run Cargo, a HeptaBao server, a CLI fixture, a provider, or any credential operation. Every registered Git child is cleaned using the original ownership rules; a residual group after direct-child reap is reported as failure and is never authority to signal a potentially reused group. The source stage has a NEW 300-second absolute envelope with original 90-second Git and 180-second clone leaf maxima clamped to remaining time. The proposed outer stage envelope is NEW 330 seconds. Late cleanup/publication cannot produce an exit-zero result after the 300-second check. A failed stage remains in place; this proposal does not rerun or overwrite it.

## Normal build and test denominator

The original release command uses normal default features and the original Rust 1.98.0 release settings, jobs=1, release build cap 1,800 seconds, libtest cap 3,600 seconds, each original listing cap 30 seconds, and each of the six original runtime groups 600 seconds. The original 44-name groups file is byte-identical. The new seven existing ingress/timing tests are listed separately by exact name. Their listings and execution share one NEW 600-second total; each listing is additionally capped at 30 seconds. A missing exact test, a timeout, a nonzero exit, an ignored/nonexecuted test, or source/binary drift fails the new group. The original 44 status remains separately recorded. No test predicate or product behavior is changed by these control scripts.

Root accepted the NEW overall supervisor bound of 12,000 seconds. This is a NEW external bound, not a claim about any historical aggregate cap. It does not enlarge any original child or request deadline. Root must accept the actual stage result before build dispatch. The stage-result SHA remains an explicit future value in the build template; it is never substituted by a draft hash.

## Existing evidence and later Phase B

R8/R9 checks stay intact. The added R10 fence reads only exact public receipts, the known clean source, and the retained server, seed, and libtest artifacts; it does not read old fixture data or credentials. Old failed and unknown fixtures stay preserved. Successful normal44+7 is a prerequisite, not proof that the prior B01 snapshot failure is repaired.

The subsequent fresh Phase B remains a separate reviewed operation. Main controller 61,210 bytes / 10816 stays byte-identical. The independently reviewed binding change uses string keys only for the returned API/Raft port maps so that the final full equality test has the same representation after JSON round-trip. Runtime integer node keys, HTTP routes, native startup, CLI/HTTP 15-second caps, forward 8 seconds, and all five case predicates stay unchanged. Source/artifact identities will be filled only from actual normal build receipts, into fresh desktop source/control/live roots. No B01 request, old private credential, archive, restore, or cold restart from the unknown prior root is reused.

## Evidence scope

This package contains source-byte invariance and strict unified-diff checks only. It does not claim host AST/runtime checks, a completed checkout, successful compilation, successful seven-test execution, a successful native archive, or production deployment. The previously completed actual rustfmt returned the candidate bytes unchanged; that evidence and the independently published diagnostic source remain separate inputs. Full OpenBao 2.7.1 replacement remains false.

## Revision 2

The first draft tree e679d4dac259bbc1dbce4a6560a730eba7dd6f28 remains immutable. This revision changes only the new seven-test group's final timing sample to one extra_completed timestamp used by both the deadline assertion and elapsed field. Runner bytes change by 96 bytes; its hashes propagate to the inert carrier and the stage control tuple. The launcher remains byte-identical. The exact small deltas are retained under diffs/draft1-to-draft2-*.diff. No host execution occurred between drafts.
