# SDK r3 runtime evidence and bounded wire diagnosis

## Result

The original SDK r3 campaign failed. Its process outcome is known, its owned service and helpers are retired, and one original plugin HTTP response remains incomplete/unknown. No retry, replacement response, provider request, production cutover, or production-store rollback occurred.

| Observation | Original job | Outcome |
| --- | --- | --- |
| Create-only staging | `1a1b2863fc1-fc05-7e69` | Succeeded; all 27 Python sources and 13 assets read back |
| Mac qualification | `1a1b288bce4-fc05-7e78` | Succeeded; 173 guards, 15 actual TLS cases, 7 pure plugin seed checks |
| Actual SDK campaign | `1a1b28a4d4c-fc05-7e81` | Failed, exit 1; 60,948 original stdout bytes, empty stderr |
| Independent service absence and worker projection | `1a1b28f03ca-fc05-7ea0` | Succeeded; two exact GUI-label/PID/group/direct-child absence observations |
| Original wire fixed-field projection | `1a1b294512b-fc05-7ebe` | Succeeded; 2,336 original stdout bytes, six read descriptors closed |
| Separate synthetic two-case wire observation | `1a1b29bacf3-fc05-7ee7` | Succeeded as a diagnostic; original wire rejected request 2 in each independent case |

The actual product remained the normal canonical `4bde9aee03fcd27c59e13607e529b1cee594b249` Mac server, SHA-256 `5f75acb9822defded2ed21f2f0ed1c21895c5e7d8d8d595e9f1c4ee9b9eaa85c`. The new r3 network rule permits one port across this machine's local addresses; the separate unchanged wire restricts the business endpoint to exact IPv4 `127.0.0.1`, CA, and leaf identity. It is not a kernel-only IPv4 rule.

## Original campaign boundary

The same-parent source capture completed under its original 45-second ceiling, its three inner children closed, and the original full9 source fence admitted the new private capsule before service effects. The normal native-v6 setup performed 27 successful outer checks and obtained 17 complete outer HTTP responses. These setup counts do not prove a complete plugin/SDK cycle.

The SDK worker ran as original PID 70395 and exited 1. It established the actual default main SDK scope, five empty fixture baselines and six fixture cache absences, and loaded the actual plugin service. Its fixed failure was `actual_complete_plugin_cycle`. It did not save the candidate, attempt the inverse, or complete a second generation. All 40 original SQLite handles closed once; 47 worker read descriptors closed; the plugin stopped; the owned HTTPS agent, requests and sockets closed; hooks were restored. There was no forbidden child attempt, unexpected diagnostic output, provider request, production change, or J3160 contact.

The worker dispatched two requests. Login returned a complete HTTP 200 with TLS 1.3 and a 589-byte Content-Length response. The manifest GET was sent once and a status 200 was observed, but the wire rejected response admission before recording verified TLS or reading a response body. That request retained `outcomeUnknown=true`; status 200 alone is not successful TLS or complete-body evidence. See [the original fixed-field projection](original-wire-projection/stdout.original.json).

The original campaign's 41 helper outcomes are known. Its sole server lifetime, PID 70272, received one recorded KILL and one bootout during failure cleanup, both known zero. The separate absence job observed the exact GUI label missing twice, native PID ESRCH twice, and no matching PID/group/direct-child rows. Original business failure was not changed by cleanup or absence.

## What the separate synthetic experiment establishes

The experiment used the installed Mac Node v25.9.0, a new create-only synthetic root, newly generated synthetic TLS material, and the byte-identical original wire SHA-256 `2b06342e30703611729788a522ba764ae30adfe1e47c4f4673b7aa8f647170e2`. It imported no actual SDK or plugin and read no real credential source. It ran two deliberately separate cases, each with a new fence and Agent and two once-only requests:

1. A `Connection: close` peer matching the canonical server's response-close semantics.
2. An explicit keep-alive peer as a mechanism control.

The second response in each case was a valid synthetic JSON body larger than 2,048 bytes, encoded as complete chunked HTTP. Both cases reproduced the original wire's `sdk_wire_response_admission` refusal on request 2.

For both cases, request 2 used a different observed socket object; `req.reusedSocket` was false; both client and peer reported no session reuse; and a new secureConnect event occurred. At both secureConnect and response admission, the socket was authorized, connected to the exact endpoint, not destroyed, and returned the matching complete leaf certificate. Nevertheless, the request-2 checkServerIdentity callback was not invoked, so the original request-local `pinVerified` value was false by the pinned source's sole assignment path. The request-1 callback had two successful invocations in the final counters.

These are source-derived values, not direct reads of a lexical local variable. The experiment did not record timestamps for each callback invocation; the final counters alone do not establish which handshake invoked the first callback. It does establish that a per-request callback side effect is not equivalent to the validity of that request's actual TLS response. No keep-alive or session-resumption cause is claimed for r3.

The experiment completed in 0.45305991591885686 seconds. Its three original child processes exited zero without signals; all 38 parent descriptors, accepted sockets, peer threads and listeners closed. A successful diagnostic does not qualify the original wire or the failed business campaign. See [its complete original stdout](original-wire-sequence/stdout.original.json), [authority](original-wire-sequence/terminal.original.json), and [the reviewed source](original-wire-sequence/observe_original_wire_sequence_r1.py).

## Archive scope

This incremental map contains runtime originals, complete paginated reads, independent absence, all five critical journals, and both complete diagnostic evidence groups. The parent publication separately contains the 58-entry r3 source/preparation package. At this checkpoint, 53 of the 58 original campaign journal files and the three recorded launchd events plus two inline-capture public files still await independent file-API readback and individual immutable archival. Their pinned paths and digests remain recorded in the complete original campaign stdout. This document does not claim full journal archival yet.

Original private stdout, credential values, profile IDs, configuration/capsule digests and error text remain private. All later corrections require new source pins and new attempt identities. The original r3 result remains failed with one business HTTP outcome unknown.
