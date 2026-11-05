# Native OpenAI/Undici and cold SDK profile R1

This is a new, unexecuted integrated profile. It combines actual native control state with actual installed SDK OpenAI/Undici refresh, then repeats the ownership checks in distinct cold SDK processes before and after a native SIGKILL/reopen. The already completed native R2 120-check run and OpenAI R4 32-scenario run remain independently scoped evidence; neither result qualifies this new run.

## Fixed scenario and assertion inventory

| Scenario | Warm entry | Native outcome | Expected provider/CONNECT count | Additional sends in either cold process |
|---|---|---|---:|---:|
| manager-success | Actual SDK shared OAuth manager | Published only after actual SQLite commit and native CAS | 1 | 0 |
| intent-ack-lost | Actual SDK shared OAuth manager | UNKNOWN; proxy drops acknowledgement only after native CAS 200 and exact native readback | 0 | 0 |
| provider-ack-lost | Actual SDK shared OAuth manager | UNKNOWN after one provider request | 1 | 0 |
| sqlite-abort | Actual SDK shared OAuth manager | UNKNOWN after 18 real SQLite abort triggers refuse the commit | 1 | 0 |
| guard-after-await | Registered fault adapter into the actual SDK refresh and guard | UNKNOWN; local fence closes during the real guard await | 0 | 0 |

The new exact denominators are **141 controller checks**, **87 warm worker checks**, and **80 / 80 cold worker checks**. Ordered names are fixed in the source manifest. The extra guard case is described by its actual entry: it is not relabeled as a shared-manager positive case. Missing, duplicated, reordered or false assertions cannot satisfy the outer qualifier.

Each cold process uses the actual existing fixture SQLite database and authority files. It creates new in-memory source/authority objects. The published credential needs a fresh native grant with a higher epoch; an old boot proof or original credential remains inadmissible. The four unresolved histories stay UNKNOWN and do not send another provider request. The parent SIGKILLs only its original owned native fixture server, reopens the same durable directory with the same pinned binary, and checks the 21 captured pre-restart bearer revocations after reopening.

## Native and final-send custody

The disposable native instance issues the AppRole roles, policy and credentials. The parent alone holds its root/recovery material. The SDK receives only the fixture reader/issuer inputs and CA. The control proxy forwards actual native response bytes and Date; it neither stores authoritative control documents nor mints a grant. The injected lost acknowledgement is downstream of actual native CAS acknowledgement and a separate exact readback.

The provider uses a separate leaf signed by the same disposable native fixture CA, with `auth.openai.com` SAN and exact SNI admission. Both leaf-generation commands use the original `owned_process.run` exec gate and the same inherited deadline. The SDK worker uses the actual installed Undici 8.5.0 fetch function, the actual OpenAI facade/guard/runtime hooks and the frozen R4 CONNECT helper. CONNECT is restricted to `auth.openai.com:443`; the actual TLS request terminates only at the parent-owned loopback provider. Global fetch is a denial path in this profile and is never replaced with a provider-response implementation. Provider input is the actual three-field OpenAI refresh form. Its token-shaped response is entirely synthetic.

The provider reads native UNKNOWN before responding. It rechecks the original profile clock after the durable observation fsync. The 10-second refresh lease, SDK's actual 300000-ms usable-credential margin and original actor/fence/CAS constraints are unchanged.

## Exact inputs and source closure

The packet contains **22 runtime files plus one manifest**. Three new profile files are isolated copies with the OpenAI/native integration. The other 19 runtime dependencies retain their exact frozen bytes, including both R3 adapters and the R4 CONNECT helper. No original native4 or SDK32 source file is edited by this overlay.

The actual candidate is bound to SDK 2026.7.1-2, Node 22.23.3 and the 35 SDK JavaScript modules, activation metadata and package/bin inputs already observed in the R4 SDK execution. Undici package metadata and entrypoint are independently checked in the actual worker; this is not a recursive attestation of the complete installed SDK dependency tree. All hooks are process-local, and the SDK files remain unchanged.

The selected native binary is the newly completed actual main R5 artifact, with its own 55/55 build/test receipt:

- Source commit: `b24c6de7831a7389e39ac069277a9e85e858ef98`
- Source tree: `3356f0a94616e9e1804f497239f33546e16db577`
- Binary SHA-256: `71b90de8a6ddb1723454a2623b970e915d64565b570cd8dd8342f5f0ffa6dc53`
- Binary bytes: `779962728`
- Build receipt SHA-256: `39c4990b541f8ca827791088c1ef1e669a6cc7f45f000728aa664e22b0765d73`
- 3142-file source manifest SHA-256: `739ffe3589e8b8c6ddca5efe56b4ef3d33a2633fce4451853413b14a6be6c3e1`

The large debug artifact is hashed by bounded streaming reads. This artifact allowance does not change any product HTTP, KV2, storage, lease or profile limit, and the result does not qualify a later Rust cohort.

## Original deadline and process cleanup

The new outer controller reuses the actual R4 owned-session and private-ancestor input helpers. Its sole mkdir claim admits one submission into a new fixture directory. One original 180-second deadline starts before input verification and is passed directly to the native driver, then to the native Owner and all three Node workers. Cleanup and terminal publication cannot extend a passing deadline.

The native driver retains the existing owned-process registry for its separate native/SDK/OpenSSL child sessions. Success requires every original Popen's completed wait and retired SID, together with the outer driver's retained original-session cleanup. Unknown or failed runs keep their original output and receipts and do not acquire a passing qualification. No PID inferred from a service name or unrelated session is signaled.

## Local validation completed before freeze

The local Python suite passed 12 tests, including real loopback TLS/SNI/Host/framing, the two owned provider certificate commands, synthetic control preconditions and expiry after durable observation. Its native oracle is explicitly `NativeDouble`; it did not run HeptaBao or the installed SDK.

The local Node guard suite passed 11 tests. It has no live network connection and proves that mapped/global fetch, unowned destinations, external DNS/process creation and private reads/writes are refused while owned store access and restoration remain usable. The outer packet suite passed 9 tests, and the real prior 120/432 public receipts were independently rejected by the new profile's qualifier.

All actual integrated qualifications remain pending. This profile imports no existing real credentials, contacts no external identity provider, makes no production switch, and does not by itself establish full OpenBao replacement.
