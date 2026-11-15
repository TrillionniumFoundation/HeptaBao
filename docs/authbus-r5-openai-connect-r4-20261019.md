# AuthBus OpenAI fixture R4: exact CONNECT authority and observed socket retirement

The actual R3 run completed 27 of the required 32 scenarios, with all 359 checks reached passing. It then failed at the first real Undici scenario: the owned CONNECT proxy refused the request before opening an upstream connection. The original controller, Node stdout and public receipt are retained byte-for-byte under `evidence/authbus-openai-connect-r4/actual-r3-02`. They are failure evidence, not a completed OpenAI or native result.

## Precise root cause and change

The actual installed Undici 8.5.0 `node_modules/undici/lib/dispatcher/proxy-agent.js` is 10,538 bytes, SHA-256 `7502726331f06700e4b3f396f119f5f59a272bc0c5aa17e6cb6d2071bac9326f`. Its CONNECT setup adds the default port to the request target while retaining the portless URL hostname in the Host field. The old fixture required both strings to contain `:443` and therefore rejected that request. The source was read from the owned actual SDK; it was never edited.

R4 keeps the exact request target `auth.openai.com:443`. Its Host field may contain only `auth.openai.com` or `auth.openai.com:443`, and exactly one raw Host field must exist. A duplicate field is rejected even though Node normally discards duplicate Host fields when constructing `request.headers`. Wrong hosts, other ports, aliases, absent or duplicate Host fields, Content-Length (including zero), and Transfer-Encoding remain rejected. The active Undici case, method and initial-head bound are unchanged. Every upstream address is still the constructor-bound loopback provider port; no request field selects a destination or DNS lookup.

A real local Undici dispatch regression exposed a second fixture issue after successful TLS requests. Node can mark `socket.closed` before the asynchronous `close` event removes it from the fixture's tracked Set. The old cleanup skipped that pending event and could return while `isClosed()` remained false. R4 registers a close-event waiter for every still-tracked socket before destroying it. It does not add a sleep, extend a deadline or weaken the final closed-state check. The intermediate failure and its public cleanup diagnostic are preserved.

Only one runtime file changes: the owned CONNECT fixture helper. Fourteen runtime files, the complete 32-scenario main runner, both shared SDK adapters, trusted UNKNOWN/CAS protocol, original clock/lease, provider guard and ticket/final-send logic remain byte-identical to R3. The separately pinned native four-case rerun therefore has no source drift from this change.

## Local verification and its scope

All original 11 proxy checks remain and pass, with 12 additional authority/framing checks: 23 total. The unchanged ticket test passes all 30 checks. A separate real installed local Undici 6.28.0 test uses both ProxyAgent and EnvHttpProxyAgent against only the owned loopback proxy and verified TLS provider; five checks cover exact authority, successful requests, zero proxy denials, close-event retirement, CA restoration and library metadata stability. The frozen old fixture fails that same real-library test with its original CONNECT 403. Local Node is v24.19.0; these are not execution of the actual main SDK or its Undici 8.5.0. No credentials or external provider are involved.

The new actual main run must independently complete all 32 original scenarios, including the five real SDK/Undici cases with provider/CONNECT counts 1, 0, 1, 1, 0 and zero mapped fetch in those cases. All original outside-network/process/write/home counters and source/SDK/config/trust/cleanup gates still apply. The native backend and cold SDK remain outside this OpenAI fixture's qualification.

## Exact packet and controller

The new tar has the same 15 QA runtime files plus one source manifest: 16 regular mode-0644 members. The complete 35 SDK JS bindings, one activation metadata binding, and package/bin inputs are identical to R3. The actual SDK retains its normal dependencies; the manifest is not a recursive attestation of the installed SDK or Undici.

The outer controller is the exact actual-02 R2 implementation with only five packet/manifest/overlay size/hash constants changed. Every other AST node is checked identical, including private-ancestor SDK input custody, fixed 180-second original budget, single-submission claim, WNOWAIT session ownership, cleanup, failure preservation and final qualification. Its fixed run-root profile remains `authbus-r5-openai-r3-actual-20261019-NN`; the next revision uses the fresh `-03` directory. Old packets, byte-changed packets and the prior incomplete 27-case receipt are explicitly rejected by the new exact checks.

The source packet and launcher transfer chunks are transport intermediates. Source, exact manifests, narrowly scoped changes and raw public evidence belong in Git. An unknown submission result must be reconciled against the existing claimed directory and controller journal before any further action; it must never trigger an automatic retry or adoption of an older run.
