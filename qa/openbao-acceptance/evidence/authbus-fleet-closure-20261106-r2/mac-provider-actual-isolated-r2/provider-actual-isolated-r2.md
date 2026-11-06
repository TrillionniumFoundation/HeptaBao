# Actual Mac provider-hook isolation: R1 failure and R2 pass

This evidence qualifies the current SDK import and dispatcher compatibility, followed by an explicitly synthetic OAuth flow boundary. Actual provider requests, production credential reads/writes, production mutex acquisition, gateway mutation, and production once-ledger operations remain zero. It does not establish provider liveness or real native socket closure.

## Authoritative original jobs

| Attempt | Job | Authority | Actual cases | Original children |
| --- | --- | --- | --- | --- |
| R1 | `1a1b2695a45-fc05-7df2` | failed, exit 1, complete and durable, no timeout | 3 passed; M04 failed; remaining 12 unexecuted | three original children known reaped, no live group members; aggregate custody failed because the qualification raised |
| R2 | `1a1b26d6ce1-fc05-7dff` | succeeded, exit 0, complete and durable, no timeout | 16/16 passed | three original children known closed; custody passed |

R1 complete stdout is 4843 bytes. Its original worker stdout is 5078 bytes, SHA256 `b43ad7d8fdac4495646e20b736b25bd37838bf99cddcf3bd4635b1656942005f`. R2 complete stdout is 63392 bytes, SHA256 `232ad35e18e321e41708d7f5d00a542e445f44dfb1b6c02128b3162f403a7dec`; four original process-read pages were checked byte-for-byte against their hex representation and assembled losslessly. R2 original worker stdout is 51749 bytes, SHA256 `5570573cbaf5528eb241c77b1773bfa24573d07e2b060bbd4370289a77c7e082`. Both stderr streams were empty.

Each attempt had its own create-only root and stable idempotency key. R1 was neither rerun nor overwritten. The original 45-second shared budget, three-child shape and 70-second supervisor limit were retained. R2 completed in 0.530351 seconds; the worker took 0.240306417 seconds.

## Precise R1 qualification defect

The actual `DispatcherBase.destroy()` sets the destroyed flag and does not set the closed flag. R1 incorrectly required both flags for its destroy-only case. The actual Mac result was `destroyed=true, closed=false`, matching the captured source. The prepared production observer already accepted the correct terminal distinction and was unchanged.

R2 changes only the fixture's M04 expected closed flag and its reporting name, plus new root/version bindings. M04 still requires the known fulfilled original destroy Promise, one Promise call, and one internal callback call. Its output retains `closed=false`. The aggregate `allExpectedAgentTerminalStatesObserved` means exactly that each case's expected flags were observed; it does not relabel destroy-only as a close operation. Four local regression cases check this expectation. The intentionally rejected acknowledgement case continues to report transport closure unknown.

## Actual Mac coverage

The first seven cases exercise the installed Mac sources and original Agent implementation: kernel refusals for protected reads/writes and two network connection attempts; eight SDK modules loaded through the source-bound hooks; eleven public source pins; exact SDK-anchored Undici resolution; real empty Agent close and destroy callback overloads; the original 100 ms close helper with a deliberately delayed acknowledgement; lost-acknowledgement refusal; and production-loader rejection of the official test runtime override.

The production loader is then disposed before nine explicit fixture cases. Those cases use the original loaded OAuth flow, guard, response-limit and identity parser, actual empty Agents, a fixed fake DNS answer, and synthetic Response objects at the native fetch boundary. Eight synthetic native-boundary invocations occur; the final source-change case reaches zero invocations. Success captures the complete raw synthetic response and fsyncs both file and directory before the SDK returns normalized data. Negative cases cover redirect rejection without a second send, HTTP error preservation, invalid JSON, missing account identity, capture failure, the original one-MiB limit, native-boundary rejection, and source change before sending.

All 657 recorded file descriptors closed exactly once. Thirteen Agent instances matched their case-specific terminal observations; the original method Promise checks and negative acknowledgement behavior remain explicit in the worker results. No fixture global runtime override remained, no child creation or database access was attempted by the worker, and all original supervised children and streams closed.

The next actual-provider operation still requires concrete running-writer exclusion and a safe restore/cutover configuration. A rotated credential must never be rolled back to its expired pre-refresh value. Restoring a gateway that would publish the new credential to the old J3160 AuthBus path is not an admitted recovery action.
