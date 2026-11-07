# Fixed setuid ps: original known failure and complete observation chain

This packet preserves the single authorized Mac diagnostic, job 1a1b39a2fb0-fc05-83ca. It is an original failure record, not an overall success or SDK qualification.

## Actual result

- Parent exit 1, error Refused/typed_process_row; stdout 5208 bytes, stderr zero; complete, durable terminal publication.
- Original 9 Native calls, 2 returned observers, 4 immutable pages. All original IDs completed/stored/inactive and payload/stream EOF; no retries, rekeys or recovery calls.
- The fixed /bin/ps primary PID 74835 was actually admitted with PPID 74832, PGID 74835 and effective UID 0, all three matching the original fixed expectations. Same-name full9 checks passed. The primary exited 0 with 21402 bytes stdout and empty stderr.
- Original WNOWAIT custody retained exit status 0; the direct child was reaped, the owned group was empty before and after reap, and no signal was sent. Two held input descriptors and handlers closed. Current outcomeUnknown is false.
- The enclosing diagnostic refused a process-table row at its five-field/first-four-isdecimal predicate. The original table, its hash and unrelated PID/UID values were not exported. The precise offending column/value and historical causes remain unobserved.
- Final input verification after table parsing was not reached; allFixedHeldNamedFencesPassed remains false. observationComplete, executionSucceeded and ok remain false.
- Old ps 84947/85012 and all prior managed/custody UNKNOWN records remain unchanged. No SDK, credential, T5, launchd, directory scanning or public file writes occurred.

## Pure verification

actual-verifier.js exports verifyFixedPsCustodyR1OriginalChain(files), where files is a flat path-to-exact-text map. Preload pure-helper.original.js for UTF-8, Git/SHA and lossless integer helpers. The verifier also uses the supplied actual-stdin-binding.original.js and never invokes Native, Python, SDK modules or the candidate.

The actual run passed all 290 checks against original requests, external intent/arm and SDK Merkle bindings, START typed digest/fingerprint, sequential original IDs, immutable offsets/digests/bytes, original payload/native reconstruction, stdout text/hex, observed failure, finite custody and lane closure. These are evidence checks, not product test cases.

GO.original.json is the original execution authorization. lane-GO.original.json changes only its scheduling condition; request, source, key and budgets remain unchanged. Each external arm retains the original execution GO binding.

## Exact inputs and budget

Full source59: eee0363103afb513ebc602eb37cec78405320caf; source, request and journal in this packet are byte-identical. Original budgets remain 35/45/60 seconds, command 4 seconds plus cleanup reserve 9 seconds, 262144-byte streaming per primary stream, two application input FDs, original internal ps samplers, bounded immutable delivery.

Minimum12 already published: f932973c64a516304a34eaa2ff5b75d03a34b41c. RELEASE.public.json and final-state.public.json are identical here. A has zero active calls/futures and no pending or active observer; follow-up is pure SOURCE only until another exact authorization.
