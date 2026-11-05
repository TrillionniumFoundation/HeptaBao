# OpenAI R3 independent review — 2026-10-19

This is a source review of frozen overlay `bc348a4e5c509b3c9512f4be4467e70ef9e508f87aed7ef99aac67f19a075aa0`. No frozen source was edited and no SDK, provider, native backend or remote process was run by the reviewer. All fourteen frozen files match their work copies exactly. The thirteen recorded base files match their required base hashes; only the two declared shared adapters differ in the candidate. The original caller, SQLite Boolean commit bridge, trusted coordinator and authority are unchanged.

## Result

No concrete blocking defect was found in the reviewed custody and dispatch paths. This does not qualify the candidate as an actual OpenAI or native refresh pass. The complete runtime packet and its separately owned process controller remain execution prerequisites.

The coordinator persists the negative local admission before remote intent. Its acknowledged CAS installs UNKNOWN and REFRESH_PENDING before invoking the provider callback. A lost CAS acknowledgement exits without invoking that callback. The SDK registry creates its private AsyncLocalStorage refresh context only inside that callback. The WeakMap ticket is tied to this exact open context, and is consumed before send, including synchronous send failures. Both the guard-to-runtime boundary and the final runtime dispatch recheck the owned credential digest and the closed-record digest. The last send closure checks the original coordinator monotonic deadline and a dispatch count of zero. Both the registry context and coordinator dispatch closure close in finally blocks, denying late asynchronous reuse.

The five Undici rows remove only the existing SDK mock-fetch selector. The caller verifies the actual SDK runtime dependency fetch is the actual installed Undici fetch, rejects the runtime-dependency override, and checks all five rows have zero mapped-fetch calls. It requires the exact provider/CONNECT/TLS counts 1,0,1,1,0 and three total accepted CONNECTs. The other twenty-seven rows are explicitly mapped HTTPS transport and do not qualify Undici.

The CONNECT helper accepts only auth.openai.com:443 in an active owned Undici scenario. The upstream is the fixed loopback provider port supplied at construction, with no request-controlled hostname or DNS. TLS SNI and HTTP Host are checked by the owned provider; TLS verification remains enabled. The additional CA is process-local. Success requires restoring the exact original DER trust set, proxy environment and global dispatcher, and closing the helper sockets. Scenario credentials, both scoped and conflicting-main stores, AppRole values and provider responses are synthetic. The socket and subprocess guards reject external destinations/processes; the actual run requires all forbidden-operation counters to remain zero.

## Boundaries retained

The source constructs exactly 32 unique scenarios and checks completion of all 32. It separately requires exactly five qualified Undici rows. The coordinator lease is still 10,000 ms; the expiry fault still waits 11,000 ms; the SDK provider timeout is unchanged. The Node caller does not implement the outer 180-second deadline. At review time its owner is preparing a separate controller, `authbus-r5-openai-r3-controller-r1-20261019/work/qa/openbao-acceptance/authbus_openai_sdk_once.py`, which is not part of this frozen R3 overlay. The outer deadline therefore needs its own frozen-source and actual receipt review; it is not inferred from documentation.

Three of thirty-five inherited SDK JS pins are absent locally: order-CeBlX0NH.js, model-auth-CJEm9SNp.js, and stream-BcRkg2P0.js. The runner must verify all thirty-five plus SDK discovery and OpenAI metadata before and after the real execution. The Undici package and entrypoint hashes do not recursively attest every transitive dependency.

The two shared adapter changes invalidate any automatic extension of the old native four-case receipt. A same-pinned rerun is required. Even an actual complete 32-case pass would prove SDK/OpenAI facade and owned Undici/TLS transport over the control emulator with synthetic credentials. It would not prove a native OpenAI backend, a cold OpenAI SDK process, real provider rotation, live credential migration, production cutover, or complete OpenBao replacement.

## Reproducible source bindings

The companion review receipt records every frozen SHA and every base-file comparison. Primary reviewed files are the SDK hook installer, SDK refresh registry, separate OpenAI caller, CONNECT/CA helper, unchanged TrustedRefreshAdmissionRegistry and TrustedControlCoordinator, and the rendered runtime-fetch module. No claim here promotes the retained 30 ticket checks, 11 proxy checks or 32 source-render checks into runtime evidence.
