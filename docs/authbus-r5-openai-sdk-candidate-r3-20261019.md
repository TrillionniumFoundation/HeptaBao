# AuthBus R5: actual OpenAI caller and final Undici transport candidate R3

This is a frozen candidate for a new actual installed-SDK run. The local results are 30 ticket/request boundary checks, 11 owned CONNECT/TLS checks, six QA file syntax checks, and successful rendering/syntax checks of 32 locally available exact SDK files. Three inherited SDK files are unavailable locally; all 35 SDK bindings are checked by the actual runner before and after execution. No actual OpenAI SDK, Undici refresh, native backend, cold SDK, real provider or production result is claimed by these local checks.

## Evidence retained and change boundary

The base is the exact owner R5 source set that passed 127 checks in 11 actual main-host scenarios. Its original `authbus_refresh_sdk_caller_live.mjs` stays byte-identical. The original seven files in the native/cold R1 overlay also stay byte-identical. That separate actual native run passed 120 controller checks plus 59 warm, 57 cold-before-server and 57 cold-after-server checks. Those are 293 assertions over four synthetic-credential scenarios, not 293 credentials and not an OpenAI qualification.

R3 changes only two existing adapters: the SDK source hook installer and its refresh registry. It adds a separate OpenAI caller runner and loopback transport helper. The actually tested Boolean SQLite bridge, trusted coordinator, original UNKNOWN protocol, original authority clock, scope/epoch binding and original caller files remain unchanged. Changes to the two shared adapters require a separately pinned rerun of the native four-case controller before extending that native evidence to this revision. The historical R1 failure receipts and owner R1/R3/R4 failures remain retained; this candidate does not rewrite any prior outcome.

## Caller and final-send protocol

The exact installed SDK shared OAuth manager enters the trusted registry before adopting another agent's credential. A usable scoped credential is read from the actual local SQLite owner. Expired credentials require a durable closed local record and an acknowledged trusted `UNKNOWN` CAS before a private async context exists. The actual provider function must match one of the bootstrap-recorded SDK function identities.

The OpenAI provider path uses the real SDK plugin activation policy, facade loader, runtime factory, flow implementation and SSRF guard. Its activation manifest is hash-bound, parsed and left unchanged. The runtime factory accepts only the exact originally imported dependencies for a managed refresh. Direct low-level refresh entry points and a replacement provider/factory cannot manufacture the context.

The guard receives a private single-use ticket before its asynchronous work. Runtime-fetch rechecks that ticket before loading its real Undici dependencies and again immediately before final dispatch. Exact provider, original refresh token fingerprint, persisted owner digest, local closed-record digest and the original coordinator deadline all remain bound. A token request cannot escape classification through a URL/Request wrapper, a default port, a query or an encoded token path. The accepted final request remains the canonical OpenAI token URL, POST, exact three form fields, expected client ID and redirect denial.

Final validation now materializes request-init getters once and owns the headers/form string it validated. A local regression reproduces the unfinished R2 draft's first-value-validation/second-value-send bug, then demonstrates the fixed boundary. This reproduction uses an inert private-context harness and synthetic tokens. It is not an actual SDK or production incident.

## Two explicit transport scopes

The first 27 scenarios use the real SDK with a mapped, owned HTTPS provider transport. The SDK creates its actual request, while the explicit mock-fetch marker selects its existing mapped branch. These cases do not qualify Undici dispatch.

The final five scenarios remove that marker and require the SDK's actual runtime-fetch and actual `require('undici').fetch` identity. The normal SDK managed environment-proxy route creates its own dispatcher. No test-runtime dependency override, DNS override or replacement SDK fetch is supplied. Only the isolated fixture process receives a loopback HTTPS_PROXY value. No inherited managed proxy is adopted.

The owned proxy accepts CONNECT only for `auth.openai.com:443`, only during one of those five scenarios. Its upstream is the construction-time loopback provider port; request input cannot select an arbitrary destination. The provider certificate includes `auth.openai.com` and `127.0.0.1`, and the provider checks TLS SNI and the HTTP Host. A process-local CA API temporarily adds this owned certificate. TLS verification remains enabled. Cleanup restores the exact original DER certificate trust set, original proxy environment and original global Undici dispatcher, and closes every owned socket. Node canonicalizes/deduplicates CA lists, so exact trust-set comparison is used instead of PEM list ordering or duplicate counts.

The five Undici cases are manager success, UNKNOWN commit acknowledgement loss, provider acknowledgement loss, SQLite abort and fence closure during guard await. Their expected provider/CONNECT/TLS counts are respectively 1, 0, 1, 1, 0. All five require zero mapped-fetch calls, and the total accepted CONNECT count must be exactly three. Every failure preserves UNKNOWN and closes admission; retry and cold authority objects must not resend. The actual OpenAI facade and actual Undici receipt flags become true only after positive scenario checks, never merely because functions were bound or source rendered.

All sockets are restricted to the three owned loopback listener ports. External DNS, external network, external subprocesses after the one owned certificate generation, writes outside the fixture and private home reads outside the actual SDK/fixture are rejected and counted. The actual run fails if any such counter is nonzero. There is no external provider connection or real credential in this runner.

## Exact source packet and SDK inputs

The runtime packet contains 15 repository-relative QA source files and `source-manifest.json`: exactly 16 regular archive members, no symlinks. The unchanged original caller is included as a baseline anchor. The manifest records mode, length, SHA-256 and Git blob for each source and contains the complete `sdkInputs` object. `packet/sdk-input-manifest.json` is an identical standalone presentation of that object; it is not an extra runtime archive dependency.

The SDK input manifest has 35 exact JS source hashes, the actual OpenAI activation metadata hash, and the package.json/openclaw.mjs hashes observed in the successful owner R5 run. The caller explicitly verifies both package-discovery hashes before SDK imports. SDK metadata remains unmodified. The normal Undici package is resolved relative to the actual SDK module, must stay within that SDK root, and its metadata and entrypoint are bounded and hashed before/after. This is not a recursive attestation of every installed SDK/Undici dependency; that limitation is explicit in the receipt. The actual runtime must provide the process-local TLS CA APIs and is expected to be the already observed main Node 22.23.3 with SDK 2026.7.1-2.

Local source preflight can read 32 of the 35 pinned SDK JS files. The three missing locally are `order-CeBlX0NH.js`, `model-auth-CJEm9SNp.js` and `stream-BcRkg2P0.js`, inherited from the previously actually tested R4 dispatch overlays. Their absence is not counted as a local pass; the actual runner must still verify them. No third-party SDK source is copied into the candidate overlay.

## Actual main execution

Use a new source extraction directory and a nonexistent fixture leaf. Verify the archive and every manifest path/mode/length/hash before launch, using the parent's existing owned-process controller and its original 180-second deadline. The manifest is an input to that controller; the Node runner accepts only the two flags below. Do not relaunch a process after an unknown result without reconciling its original PID and receipt.

```sh
/usr/bin/node <owned-source-root>/qa/openbao-acceptance/authbus/authbus_refresh_sdk_openai_live.mjs --openclaw-root /home/qian-qi/heptabao-next-gates-20261017/authbus-admission-sdk-20261018-01/openclaw --work-dir <new-owned-fixture-root>
```

The original coordinator lease remains 10,000 ms. The original expiry fault waits 11,000 ms. The SDK refresh timeout remains 30,000 ms. The parent controller's 180-second budget is not reset for scenarios, uploads, retries or cleanup. This candidate does not increase any product deadline or migration/request size limit.

The exact 32-scenario inventory is present in the source manifest and local validation receipt. Completion requires all 32 scenarios, all assertions, the exact five Undici rows and counters, zero forbidden side effects, exact SDK/source/config hashes after execution, and successful process-context cleanup. The new actual receipt must be preserved even if one gate fails. Store the original public receipt and controller receipt separately from this frozen candidate.

Even a complete pass would prove actual SDK/OpenAI facade and owned Undici/TLS transport over the TLS control emulator with synthetic credentials. It would not prove native OpenAI refresh, a cold OpenAI SDK process, real provider token rotation, migration of live credentials, production cutover or complete OpenBao replacement. The separately passing native four-case R1 receipt preserves its narrower scope and binary provenance.
