# Actual continuation checkpoint — 2026-11-06

The current full-replacement gate remains **not qualified**. Product source is unified with canonical candidate `4bde9aee03fcd27c59e13607e529b1cee594b249` (tree `f08493a23f8ea0637073651231865ea9607b790e`). The only tracked product-file difference from the prior 6d456 checkpoint was the JWT test fixture; this checkpoint takes the canonical test bytes. Files outside `qa/` and `docs/` match canonical 4bde9. This merge retains both histories.

No production traffic was switched. No legacy production Bao service, binary, data or backup was deleted. The retired Mac R2 registration below was an explicitly owned failed QA wrapper.

## Actual Mac normal build and all 107 cases

The [retained canonical receipt](mac-4bde9-canonical/result.public.json) and [original terminal](mac-4bde9-canonical/runtime-terminal.original.json) bind actual job `1a1b116ba98-fc05-75a6`: succeeded/exit 0, complete and durable output, no timeout or cancellation. All **107/107** required cases passed: 90 server and 17 HA-service cases, zero failed/ignored/unexecuted. The original controller reports 1002.514604 seconds, normal release features, matching source/artifact pins, and all original processes retired.

The exact build receipt is 181226 bytes, SHA-256 `90753d3b4f9b966c43d3e29919239f8d9aa879616c821a3d9ce0b6aa854054d6`; the selection is 46133 bytes, SHA-256 `7da0b1e3efe257b66d31d50af7c1327a4d320c512c1c8f82df30020898c66595`. The separate progress file has different bytes and is not substituted for the result. [The offline verifier](mac-4bde9-canonical/verify_evidence.py) checks retained bytes, original terminal, exact enumeration/group results and source bindings; it does not claim a new remote binary rehash.

The prior 6d456 fixture's actual 49-case API diagnosis and formatter proof remain historical evidence. That alternative product campaign was **not dispatched** on Mac or ROG. Its source-only staging is retained separately. The old Mac 09c14 and ROG r8 campaigns remain failed (102 passed, one failed, four not executed); no result is relabeled by this merge.

## Actual Mac full34 / DR25 failure and QA correction

The canonical owner's actual job `1a1b137be71-fc05-76fa` is **failed/exit 1**, complete/durable, with no timeout. It ran for 50.712132 seconds. The original baseline recorded 21 passing case entries but did not complete all 31. DR25 recorded four passing obligations and one failed archive-binding obligation; recovery into a fresh directory was not reached. Its final process-custody receipt reports all 277 original children retired with no cleanup failures.

The [original wrapper result](mac-dr25-4bde9-failed/result.public.json), original terminal/stdout and [read-only failure projection](mac-dr25-4bde9-failed/failure-projection.stdout.original) preserve this failure. Both real CLI and HTTP archives passed outer checks and had equal seal identity, generation 4, and encoded `state_bytes=9009418`. The QA predicate incorrectly required that encoded transport length to be at least the logical history size, 35651584 bytes.

The source transport emits each registered immutable object once; repeated chunks can share objects. This checkpoint corrects only QA: it requires the actual full34 logical capacity and original API/raw/cold-history observations, and identical CLI/HTTP source metadata including generation, encoded size and seal identity. It retains all original 31 baseline and 25 DR obligations, authenticating real restore, negative controls, cold reopen, deadlines and custody. Three added semantic regressions reject missing/small/unobserved history and different source metadata. The complete controller guard file passed 34 local unit tests; those fixtures do not qualify an actual restore. A new, separately bound actual Mac attempt is still required.

## Current AuthBus source and read-only WAL qualification

The [current configuration observation](../mac-authbus-current-source-20261106-r1/current-config.result.public.json) is an actual successful Mac run. Five agent paths agree; 70 profiles are registered (69 OAuth), and AuthBus is still enabled with the retained J3160 endpoint. No provider was called, no credential database was read by this configuration-only observation, and no raw profile IDs, credential values or client-configuration digest were exported. A private 0600 allowlist remains on the Mac. Registrations are not active-consumer counts.

The source-bound launchd parser now preserves `(never exited)` as unknown and handles the observed unrelated `UID=-2` process row without weakening related PID/PPID/PGID/UID ownership. The second parser qualification passed 18/18 actual Mac checks, using the real source AST without executing the manager.

The first Auth WAL qualification passed 10/10 actual Mac cases. The enhanced [second qualification](../mac-authbus-auth-wal-20261106-r2/result.public.json) passed 18/18 with complete durable output and all original children retired. Nonempty WAL uses the qualified named read-only transaction; only stable empty/missing WAL may use the held-file immutable route. Registered/missing/unregistered profiles remain distinct; explicit missing selections refuse rather than fall back. File replacement, WAL creation, concurrent commits and unauthorized SQL remain rejection cases.

`authbus_current_auth_wal.py` is **not a standalone portable repository import**. Its exact staged Mac dependencies and source bindings are specified in [source-dependencies.public.json](../mac-authbus-auth-wal-20261106-r2/source-dependencies.public.json). The qualified runner pins those original files before staging/importing them. An unredacted remote dependency contains an unrelated client-config hash and is deliberately not published as a substitute artifact. Original r1 library/reader bytes are retained with r1 evidence; r2 supplies the current library.

Actual current credential-generation capture, SDK inheritance, active consumer binding and AppRole/TLS/KV/policy/renewal/revocation remain a separate ongoing qualification. Historical frozen credentials do not establish current active-source coverage.

## Old Mac R2 QA wrapper cleanup is independently closed

The [complete recovery record](mac-r2-recovery/README.md) preserves all failures and original outcomes. r1 failed before any signal. r2 sent one known successful TERM, then failed at a later process observation; it did not send KILL or bootout. r3 was a separately reviewed KILL-only recovery with a new absolute 60-second budget and its own full 20-second observation. It sent one KILL and one bootout, no new TERM.

r3 job `1a1b134587a-fc05-76e5` succeeded/exit 0 with complete durable output. Eight create-only journal files were independently read back. Independent job `1a1b13ae3a0-fc05-771f` checked two complete rounds: the exact GUI label was absent, original PID 32527 had ESRCH, and its PID/group/parent relations were empty. The system-domain-only service observation is explicitly not used as GUI-domain proof. Original failed business evidence/data are unchanged; recovery closure does not qualify AuthBus business.

## Linux and remaining execution gates

The X230 admission controller's actual 24/24 guard tests remain admission-only evidence. The exact current-candidate Linux normal build and complete 107 selection are still required; competing ROG compiler owners are preserved and the original no-compiler preflight is unchanged. 6d456 preparation was archived as source-only, not a successful campaign.

Still required: current-candidate X230 full34 and the bounded official OpenBao 2.7.1 comparison; a complete fresh-directory DR25 run; physical multi-host HA evidence; current independent AuthBus source and real credential lifecycle; each registered client's credential I/O, restart and rollback; then production cutover. Legacy cleanup becomes eligible only after every registered client and backup/restore path has migrated. The accepted finite inventory is retained; new actual active configuration evidence may refine its existing client bindings.
