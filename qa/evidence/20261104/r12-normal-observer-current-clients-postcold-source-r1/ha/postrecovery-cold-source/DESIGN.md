# Fresh post-recovery cold scope B — source draft 1

Status: source-only. No new physical host action, stage, prepare or product fixture has been submitted. R3's succeeded roots and its 98/98 qualification remain unchanged. This is a new QA scope on the same canonical R10 normal products.

## Why a fresh fixture

The original Direct98 runs its full cold restart before missing-cipher recovery. Its final application step then deletes the synthetic metadata. Restarting the succeeded R3 roots now would test persistence of those deletions; it would not retain the recovered history. B therefore creates new roots and inserts an independent cold scope after the successful missing-cipher history/ReadIndex checks and before the original deletion step.

The 19 historical version numbers include version 1 soft-deleted and version 2 destroyed. There are 17 live large versions, totaling the original 34 MiB target. The actual current leader re-reads all 17 large values and both retired-state responses. Every node separately rechecks the exact version metadata, retired 404 semantics, the original denied quorum write's absence, and every acknowledged small read through normal ReadIndex. This does not add a requirement that all standbys directly deliver every large body.

## Product and source boundaries

Product commit is 49503322c7f446e5eb41e7744f1fdbd7f1192ecc, tree 1d4211f91e1b34a2ed087a3bbef2e2884bac88e9. The normal Mac/Linux binaries and both complete original 44 gates remain separately pinned. Canonical source and its QA5 files are never edited. The new control root contains four exact QA copies in `deadline_qa/`; all changes have full original files and unified diffs. The new pinned runner loads only those four copies before importing the unchanged canonical official-history module. Its 30 additional cases are not run.

Default `parent_deadline=None` keeps the old call behavior. B explicitly supplies the new parent deadline. The original request assertions, data history, R3 source3/actual-empty1 guard, natural election preparation, original 98 case names/order, final metadata deletion sequence, and cleanup remain. The standalone source path for the unchanged peer-preflight helper is fixed to the canonical tree because the copied Direct module lives outside that tree.

## Shared budgets and custody

The launcher creates one absolute 2400-second controller deadline before dispatch and passes it to the same desktop Python child. The new phase uses `min(phase_start + 300, controller_until)`. Each B stop/start, helper/SSH call, readiness/leader/frontier loop, unseal, history/metadata/retired read, and small ReadIndex call receives that deadline. Per-call caps remain 15-second HTTP, 8-second native admission, original 60-second process/election bounds, original 45-second listener bound, and original five-second owner stop. No new request or process is intentionally dispatched after its caller deadline. Each completed observation is checked again before it grants a successful check.

Linux control scripts retain the actual pidfd/start-identity ownership logic and bound their original internal sleeps/observations to the allocated duration. Mac retains actual direct-Popen/WNOWAIT custody, reserved PID until live group empty, and the original final wait. The new optional protocol carries a relative allocation; it does not assume shared monotonic epochs across hosts. The same desktop absolute deadline controls whether the phase can succeed. Original failure-only cleanup budgets remain available to stop owned work, but they cannot turn a failed or expired phase green.

## Exact recovered reference

The old recovered inventory only returned count, bytes and quarantine digest. The new fixture requests an additional observation during that same actual recovered scan. Every original leaf is still read once and compared to its original quarantine SHA/size. That scan additionally binds named-before/opened-FD/named-after identity and the held directory chain; it returns the exact names, hashes and identities.

B does not hardcode R3's observed 338. It uses this fresh fixture's actual recovered set, bounded to 4096 leaves, 1 MiB per leaf and 64 MiB total. The caller writes that one captured record once under its fresh private root. After all three owned stops, a new fixed Mac helper reads only those captured names. It never enumerates or reads unreferenced ciphertext. It verifies before/open/after identities and bytes/SHA, plus final named parent directory identities. Across phases, directory object identity/protection must match; directory mtime/size may legitimately change during stop and is only compared within each observation.

The separate stopped numeric reader retains the accepted R3 parser and directory named checks, with only its fresh root bindings changed. Its current persisted index is compared with the pre-stop passive applied frontier. This remains passive numeric evidence, not a ReadIndex capability and not a historical election-cause proof.

## Counts and failure handling

The original 98 checks remain the main denominator. Twelve named extra checks live in a separate `post_recovery_cold` report. There are exactly three extra planned mutating operations, the original-key unseals after the new cold restart. Unknown or failed outcomes stop the chain and are not replayed. No API write is inserted to force a term, leader or successful outcome.

A late publication, identity mismatch, wrong direction, incomplete reference, or failed semantic check leaves the new scope failed. Original cleanup still runs and is reported independently. Old R1/R2 failures, old strict-wire unknowns, and the succeeded R3 receipts remain protected by 24 exact before/after fences.

## Proposed execution

`proposed-dispatch.public.json` records exact inert carrier/inputs, a future prepare-only invocation, and a non-executable live template with a null prepared digest. Inert staging parses/compiles every exact file before creating the new private control directory; the nested four-file overlay is created only there. Prepare retains original source/build/QA probes and verifies the extra contract. Actual live still requires root's whole source/component review, real prepare receipts, and a separate quiet window after current ROG work terminates.

Local /tmp Python 3.12.14 can parse the source and compile the generated remote scripts; no source main or remote script has been run. Pure components are being consolidated separately before this draft can be considered ready for runtime. The prior failed local exec used a missing default cwd and started no Python process.
