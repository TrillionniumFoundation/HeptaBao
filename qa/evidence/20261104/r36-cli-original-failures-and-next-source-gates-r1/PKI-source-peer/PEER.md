# PKI exact400 — independent limited SOURCE peer

Scope: immutable packet 6e4bf23de8f7fdac6dd9b152232a905bedb87744. All 15 original files (769828 bytes) were fetched whole and checked against Git blob/byte identities. No candidate module, author checker, Rust build, Rust test, Python acceptance, SDK or Runtime was executed. No file was modified.

## Finding

No new blocking source finding in the three requested changes. This is source review, not compilation or product qualification.

1. pki.after.rs 691–719: the entire production delta is confined to Pki::lease_lookup(&self). Exactly the missing-record and retired/nonleased/revoked/deadline branches change not_found to bad("invalid lease"). The clock max, precise deadline, successful response fields, and every byte outside this method remain identical. It introduces no state mutation. revoke_lease, certificate retrieval and the rest of the engine remain byte exact. This packet does not separately reproduce the enclosing bad() HTTP mapper or every caller; no broader routing/parity conclusion is made.

2. Official exact references support the narrow target: logical_system_paths.go 2607–2625 connects leases/lookup Update to handleLeaseLookup; logical_system.go 1961–1975 returns ErrorResponse("invalid lease"), ErrInvalidRequest when FetchLeaseInfo returns nil; response_util.go 127–128 maps ErrInvalidRequest to StatusBadRequest. This does not prove when asynchronous expiration removes a live OpenBao lease. The proposal correctly preserves that limitation.

3. service_native_pki_tests.rs 1185–1261 adds two tests only. Each issues a real synthetic lease through the existing normal configured File V6 Fixture and requires a successful lookup before retirement. The expiration case requests 2s, then advances f.now by 3 before the two rejection checks. Existing call() advances one second per request and anchors RequestClock to that controlled value (41–72). restart() carries the same now, reopens the existing files and unseals (212–229); it does not reset the clock. Both warm and cold branches require exact 400, nonempty errors and absent data, while fetching the retained certificate successfully. Unrelated KV roots, cluster/replay identity and the KV sentinel remain asserted. These are controlled-time test assertions, not evidence of wall-clock or network execution.

4. acceptance.after.py 221–235 tightens only the two existing accepted status sets to 400 and removes their string overwrites. check() 69–77 retains the original numeric response.status and fails a mismatch. The original 2.3-second wait, issue TTL, request order and all other source stay identical. A delayed OpenBao 200 remains a failure; there is no retry or status normalization to hide it.

5. PLAN/README explicitly keep the earlier 69 observation at 67 exact numeric plus 2 normalized. The missing historic numeric values cannot be reconstructed from this source proposal. Neither the future 12-case PKI selection nor these two new unrun Rust tests upgrades that historical result. Formatting/integration/build/live remain pending as declared; the extra blank line in the appended test delta is within that unformatted source status.

## Mechanical checks and review limits

Three supplied one-hunk diffs apply strictly to the supplied before files and reconstruct their after files byte for byte; reverse reconstruction also passes. Twenty-one limited pure text checks are recorded. The first local checker cut the inserted tests after their added blank line and therefore reported a prefix-removal mismatch. The corrected check uses the original archive-module offset and exact common prefix/tail; original failed output is retained. No candidate bytes changed.

Inputs, raw whole-source identities, the first local checker failure and corrected result are included. This peer does not assert integrated canonical-tree membership beyond the packet's recorded base, successful compilation, timing under actual load, a new official-oracle run, or production/cutover/cleanup qualification.
