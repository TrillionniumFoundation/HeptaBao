# AuthBus R5 native control and cold SDK: actual main R1 evidence

The original main-host run completed successfully on 2026-10-19, from
05:49:31.848326 to 05:50:33.047949 UTC. The controller passed 120 of 120 checks;
the warm SDK process passed 59 of 59; each of the two independent cold SDK
processes passed 57 of 57. These are **293 assertions over four synthetic
credential scenarios**. This count is not a credential-migration inventory.

The five JSON receipts in
`qa/openbao-acceptance/authbus/native-cold-r1-actual-main-20261019/` are copied
without reformatting. `evidence-review.json` records their original byte
counts and SHA-256 hashes, cross-checks their source and process references,
and separates this local evidence review from the original host execution.
The frozen seven-file native R1 source candidate is unchanged.

## What the original run establishes

| Original phase | PID | Actual checks | Provider sends by scenario |
| --- | ---: | ---: | --- |
| Warm SDK | 1760446 | 59/59 | 1 / 0 / 1 / 1 |
| Cold SDK before native restart | 1761730 | 57/57 | 0 / 0 / 0 / 0 |
| Cold SDK after native restart | 1762822 | 57/57 | 0 / 0 / 0 / 0 |

The scenario order is manager success, lost UNKNOWN acknowledgement, lost
provider acknowledgement, and SQLite transaction abort. The real installed
SDK 2026.7.1-2 ran under Node v22.23.3 with its actual SQLite owner stores,
shared OAuth manager and owned HTTPS provider transport. All 21 QA runtime
files remained exact; each worker reported the same 15 QA module pins and
14 bound SDK modules loaded. Installed SDK and fixture configuration hashes
remained unchanged. All worker external-network, external-process, external
write and private-home read attempt counters were zero.

The control backend was the actual native V6 HeptaBao binary. The fixture
created its own TLS CA, native store, AppRole identities, policies and four
KV2 control keys. Reader write denials, real token renewal and revocation,
and final AppRole secret-ID destruction and reenrollment refusal passed.
No root bearer was given to the SDK worker.

The lost UNKNOWN acknowledgement was injected only after a real native CAS
success and an independent full native readback. Each of the three provider
requests independently observed its committed native UNKNOWN attempt first.
The three unresolved scenarios retained the exact control-document digest,
KV version 2 and attempt digest throughout both cold SDK starts and native
SIGKILL recovery. They issued no second provider request. The successful
scenario retained its stored successor credential and acquired fresh epochs
4, 5 and 6 across the three SDK processes. Its native KV versions were
4, 5, 5 and 6; the unchanged middle pair straddles the native restart.

Native PID 1760174 was stopped with the original kernel pidfd using SIGKILL
and reaped with exit -9. The same data directory reopened under PID 1762381,
started sealed, was unsealed, retained native graph format 2, and preserved
all four control documents and KV versions before new SDK writes. Previously
revoked bearer tokens remained denied after reopening. All nine owned
children completed their original wait and retired their original SID;
there were no observation gaps, survivors or fallback signals.

The run used 61.012099723 seconds of the original 180-second outer deadline.
The shared process helper retains its existing maximum profile of 360
seconds, but it inherited the shorter absolute original deadline. No lease
or process budget was renewed or reset for either cold phase.

## Qualification limits retained

The binary SHA-256 was
`a45ebe3e4d7b845ca5392431bdae9ba8348e16d2fe88489c3347049a07a7b8d2`.
It came from commit `0f1c996136aae94e99c2b709a5797ffea479f6cd`, tree
`8befd5cedfb7ccafee5f707e5985d49eeb78fb60`, and the upstream build still had
its separately recorded 53/55 scoped test result. This AuthBus success does
not change that prior result.

OAuth credentials and responses were synthetic. The provider HTTPS server
was owned by this disposable fixture; no external provider or production
credential store was contacted. The actual native backend, process death,
reopen and two cold SDK processes are established by the parent controller
receipt. Worker receipts deliberately leave native-backend qualification to
that controller; their own `actualNativeHeptaBao` fields remain false.

This native run covered four scenarios, not all 11 scenarios and 127 checks
of the separate owner R5 emulator run. OpenAI facade qualification remains
false. Production caller installation, real credential migration, all
configured providers, multi-host cutover and complete OpenBao replacement
remain separate work and evidence.
