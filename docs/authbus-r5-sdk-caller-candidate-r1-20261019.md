# R5 SDK caller and final token transport candidate, r1

This is an isolated source candidate. It has not qualified the real AuthBus
deployment or a native HeptaBao backend. Local Node 24 syntax checks and exact
source substitution checks are recorded separately from actual SDK execution.
The earlier actual SDK store 21/21 result proves the Boolean SQLite bridge;
it does not prove this new refresh caller path.

## Code and authority

`authbus_refresh_sdk_registry_candidate.mjs` extends the existing trusted R5
registry. It uses the existing coordinator's acknowledged durable `UNKNOWN`
intent and `REFRESH_PENDING` assignment. Only after that acknowledgement does a
private `AsyncLocalStorage` context exist. The context is closed in `finally`
after provider completion or failure, including failure of a wrapper promise
while its SDK continuation is still alive. A later continuation cannot recover
the context's authority by retaining a function, token string, or parameters.

`authbus_refresh_sdk_candidate.mjs` composes the prior R4 order, eligibility,
profile, model and final model transport patches with the actually tested R5
strict Boolean SQLite commit bridge. It inserts the managed branch at the start
of the real SDK `resolveOAuthAccess`, before main-agent or external CLI adoption.
It retains the SDK's original refresh-call timeout. A successful managed
refresh passes the old profile permit through the existing private successor
mapping; API-key and token branches retain their existing checks. The existing
R4 managed-error catch still prevents fallback and retry.

Each managed token request checks its provider, token, method, original HTTPS
origin, body format and operation. Immediately before calling the coordinator's
one-shot dispatch closure it rereads the actual SDK credential and the closed
local admission record. A changed credential or local fence refuses the send.
No await separates the final synchronous checks, the original deadline check,
the single dispatch consumption, and the transport callback. Redirects are
disabled for this operation because an automatic redirect would replay a
refresh request without another one-shot check.

## Provider scope

The r1 actual runner exercises the SDK's **Anthropic** path with synthetic
credentials. The source candidate also contains explicit Chutes and GitHub
Copilot token transport boundaries, which still require actual SDK positive
tests. For Chutes, the client ID must be credential-bound; an ambient client
secret that is not part of the bound credential is rejected before sending.

Managed generic plugin refresh callbacks are deliberately not invoked. The
managed path falls through to the SDK's bound builtin implementation. The
bootstrap records builtin function identities; replacing a provider callback
cannot acquire qualification. Unmanaged provider behavior remains unchanged.
This does **not** qualify arbitrary custom OAuth providers or plugins.

**OpenAI is not qualified in r1.** The SDK public facade and its first literal
runtime target have been located, but its final token implementation has not
yet been incorporated into this frozen candidate. The qualification set does
not allow an OpenAI manager refresh. Direct OpenAI public runtime exports are
outside this r1 scope. Do not use r1 as a production bootstrap for OpenAI scopes
or describe the r1 runner as covering them. A separate exact-base revision will
close and test that path.

## Actual SDK runner

Run only against the owned frozen SDK in a **new**, absolute work directory:

```sh
node qa/openbao-acceptance/authbus/authbus_refresh_sdk_caller_live.mjs \
  --openclaw-root /absolute/owned/openclaw \
  --work-dir /absolute/new/authbus-r5-sdk-caller-fixture
```

The runner uses the real installed SDK source through disposable module hooks,
real SDK SQLite transactions and readback, and a real loopback HTTPS provider
server. It maps the original token URL to that owned fixture only after the
actual SDK constructs the request. It generates one fixture TLS certificate;
all other child processes and external network destinations are refused. Its
filesystem guards permit writes only in the new fixture and refuse reads from
the existing host home outside the SDK or fixture. The complete candidate
module hashes and the original/candidate SDK hashes are in its receipt.

The control endpoint is an explicitly identified, fsynced **KV2 emulator**.
The receipt keeps `actualNativeHeptaBao: false`, `syntheticCredentials: true`,
`syntheticProvider: true` and `actualColdSdkProcess: false`. New control-source,
coordinator and authority objects exercise cold authority refusal, but they do
not constitute a process restart. The runner never contacts a real provider.

The 11 separate SQLite cases are: scoped usable credential with a newer main
credential present; successful actual SDK manager refresh; intent response
loss; provider response loss; actual SQLite abort triggers; a concurrent actual
SDK credential change before sending; a changed local fence; a duplicate
actual SDK token send; a late actual SDK continuation after rejection; the
original refresh deadline; and a cross-provider SDK entry. Fault-adapter cases
are identified separately from the unmodified caller's execution: they inject
the fault inside the registry and call the actual SDK builtin provider, rather
than claiming the injected adapter is the SDK's shared manager.

Success requires exact provider counts, `UNKNOWN` observation at the HTTPS
server before a token is accepted, actual SQLite readback, durable retained
unknown results, refused retries, and unchanged installed SDK sources. Public
receipts contain fixed case names and hashes; no credential values are emitted.

## Remaining qualification

Run this candidate on the owned actual SDK and repair any real failures while
retaining their original receipts. Then finish the OpenAI source closure and
positive tests; repeat against a real native HeptaBao control backend; and
perform genuine fresh-process/restart and owner-transition tests. A passing
emulator-backed SDK runner is not a substitute for those gates or for host
cutover, rollback and final credential migration evidence.
