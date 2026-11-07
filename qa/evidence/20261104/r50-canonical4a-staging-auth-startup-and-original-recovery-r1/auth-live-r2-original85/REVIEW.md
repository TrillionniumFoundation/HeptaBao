# Public Node live denial R2: complete original observation

## Result and scope

Original job `mac/1a1b33bc0d5-fc05-814d` completed with owner exit 0, full/durable/confirmed output, 16,263 stdout bytes and zero stderr bytes. All 13 original Native calls, two observers and eight immutable pages are present. A is released: no active call, future, pending request or active observer. No error, lost acknowledgment, retry or recovery occurred in this Native sequence.

This is a completed public diagnostic. It is not a successful Node launch, an admitted denial event, an SDK test or a credential qualification. The exact original 6,909-byte profile was unchanged.

## Actual children and timing

The public carrier PID 29053 had original parent 29051, PGID/SID 29053 and UID 501. Its captured birth string is `Sat Nov  7 07:40:00 2026    `. Both fixed ready/released markers appeared; total stdout was 53 bytes, consisting of those markers, with no version text and zero stderr. Its retained exit was code 2 / status 6 and observed return code -6. The markers and exact source support the same-PID exec attempt. They do not independently observe the Node kernel image or prove an earlier private run's progress.

The log child PID 29055, with the same parent and its own PGID/SID, exited 0 with 167 stdout bytes and zero stderr bytes. Its fixed predicate used the complete `node(29053)` subject and the closed node/kernel/sandboxd process set. It requested ndjson, debug level, and an eight-second timeout.

The first observed Node exit plus all output EOF completed before its five-second deadline. That completion remained latched while the log child continued. Both children completed before their respective deadlines. The owner finished in 8.701107333879918 seconds. Protected once-only cleanup ran immediately after observation, before cached output projection and final input fences.

Queue timestamps establish that log launch/custody preceded gate release and that the log process was still observed alive after the Node exit. They are not a log subscription acknowledgment.

## Log projection

Two rows were observed; zero denial events were admitted; two rows remained unknown.

- Ordinal 0 was not admitted as a JSON line. No semantic label was assigned.
- Ordinal 1 was an object without any of the nine recognized message/process/PID/timestamp fields. All event admission predicates were false.

Neither row is called a header, statistics record or harmless content. Unknown raw text and hashes were not exported or preserved by the public owner. The 167-byte underlying log output cannot be reconstructed from this public projection. Zero admitted events does not prove absence of denial, and the fixed prefilter may exclude redacted or differently attributed messages.

## Resources and unchanged boundaries

Twenty returned application descriptors were enumerated: five admitted inputs, ten HOME-control descriptors, and five parent pipe descriptors. All were closed once, with no pending acquisition or registration uncertainty. Both direct primary children were reaped with empty group observations before and after reap; neither cleanup sent a signal. The original helper custody/cleanup receipt is preserved for each child. Internal ps helpers remain additional direct observations; the count of two refers to the two primary children.

The two exclusive-create public HOME roots now exist and must not be treated as fresh again. The original profile was written and read back exactly. Final held/name fences passed; current owned-root full9 and named full9 agreed; object identity used the already-reviewed first five fields after this run's exclusive create. No prior root, service, private capsule, T5 business file, provider, credential or logging setting was modified.

R1 source defects, all earlier managed/PID custody UNKNOWNs, and prior business failures remain unchanged. Original R1 source was not executed. R2 fixes only completion latching and cleanup ordering; its SOURCE30 and root/C reviews are referenced by the exact GO.

## Reproducible pure verification

`verifier.public.js` exports `verifyLiveDenialR2OriginalChain(files)`, where `files` maps each path in this flat packet to its complete original UTF-8 text. Load `pure-helper.original.js` first for Git hash, UTF-8, base64, lossless integer and flat Merkle functions. The verifier uses no tools, network, filesystem, Python or Native execution.

The actual run produced 467 passing checks in `verification.actual.json`. It verifies every external exact intent and three-leaf arm tree, original SDK and one-leaf SDK tree, lossless Native interpretation, same-ID completed/inactive status, immutable page offset/total/digest, original payload and its tree, Native stream text/hex/cursors/EOF, whole stdout and release. Additional checks bind exact source/request/journal and the observed closure, timing, fixed-profile and limited public projection facts.

No author component test was rerun, and these 467 archival checks are not product cases. A future source or Native action requires its own exact scope; this packet authorizes none.
