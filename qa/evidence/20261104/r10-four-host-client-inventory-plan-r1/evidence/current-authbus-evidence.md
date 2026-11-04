# Current AuthBus source and real consumer evidence (2026-11-04)

These acceptance programs are separate from the server implementation. The normal
candidate used for the Mac and X230 lifecycle receipts below is commit `36076db5f5afe00db75eba9b607dee7802dae554`,
tree `ae71c4b243afd4099db66e7d9882b3f28c777a95`. No fixture binary or provider mock
qualifies as a replacement for the real lifecycle.

## Final normal candidate: demonstrated boundaries

| Host / scope | Original evidence | Result |
|---|---|---|
| X230 real credential transport | `/home/qian/heptabao-authbus-real88-36076-20261104-r1/live-r1/result.public.json` | 44 parent + 44 actual Node child assertions; two real cold restarts and exact credential KV rollback |
| X230 independent assessment | Same root, `assessment.public.json` | SHA256 `4336a6e7dd4d6e31c83fd6d6cb339e4b9887a048f8345a4e8f9f7d003de0fc5f` |
| Mac installed AuthBus plugin, installed SDK default resolver | `/Volumes/T5/hepta-vnext-recovery-20261013/authbus-profile2-selector-c138-20261104-r1/final360-core-r2/result.public.json` | 54 parent assertions; two consumer phases of 51 assertions each; two SDK rollbacks of 40 each |
| Mac final core receipt | Same receipt | SHA256 `3ac84a78cb6f6fb145508adbb6918cf7de40478ec92854eeb4427ec5c04242a7` |
| Mac actual registered Codex native consumer | Same Mac root, `final360-native-codex-live-r5/result.public.json` | 60 parent; initial/cold native 95 each; initial/cold full-store CAS rollback 62 each; exact four terminal phases |

The X230 actual receipt SHA256 is
`87e8182fd7a04e4194800811737f5b2f48d7d20b6455641421c3bfdd19132d61`.
Its normal Linux server SHA256 is
`3d9fdf79e26abf4c33fa57568ae7a4c88c79c5def569d92d571c639b855f3df8`.
The Mac normal server SHA256 is
`b924baba30b1fdc0e6f7e7f32ee0974fae7990b97544c0fbae877f85b420450d`.

The final Mac core run makes **zero new provider requests**. It explicitly links
the prior successful provider receipt to the byte-identical credential actually
selected by the unchanged installed default resolver. Its qualification scope
does not assert current provider connectivity or a production gateway cutover.
The initial final-core attempt `final360-core-r1` failed on an incorrect capture
file path after four version checks, before starting a server. It is preserved.

The X230 wrapper changes exactly five original runner identity literals: two
commit occurrences, one tree, one binary digest and one normal build receipt
digest. All test criteria, 10-second token lifetime, 30-second request deadline,
90-second child deadline, source contract, Node child and production transport
module pins are unchanged. Each execution uses a fresh private source capture
from the already provider-validated ROG account. Capturing and transporting it
does not refresh the provider credential. No installed production OpenClaw
consumer was found in the standard `/home/qian` paths; the transport lifecycle
must not be described as an existing X230 production gateway migration.

## Earlier Mac provider proof and corrected rollback checkpoint

The original c138 attempts remain independent terminal results:

* `live-r4/result.public.json`: SHA256
  `16632d0e27df280960ced8255876825c1d5529f98b6c63777925e1d35e2f3eee`.
  The actual selected credential obtained HTTP 200 from the provider, but the
  first logical-store rollback precondition failed. Overall result is false.
* `live-r4/selected-account-provider-read.public.json`: SHA256
  `2a7df051464c3036b9d5d50ab17647c93ea75b6d7bcfd320415166c52fbf4867`.
  The actual installed usage reader made one TLS-verified GET. This was not a
  model request or a refresh.
* `live-r5/result.public.json`: SHA256
  `f51dfdabdfa4742403e620d56e7c87f0076fc0c692281ab96db5b9cb37924e37`.
  Initial and cold installed consumers passed; both full logical-store rollbacks
  passed 39/39. The independently attempted provider GET timed out before a TCP
  connection, so this overall result also remains false.
* `independent-evidence-link.public.json`: SHA256
  `a7fe385b4e7b77e05c65ba2bf83147ea5acab7270e4ae5ed7990009acc487726`.
  It binds the same selected credential and installed source pins across the
  attempts. `sameRunCompletePass` and current connectivity qualification remain
  false; the linker never manufactures a combined all-green run.

The precise rollback root cause is reproduced in
`live-r4/rollback-checkpoint-root-cause.public.json`, SHA256
`b749346cfb8ff6119730d6f99e6401eb5fc322b01d08cf3f7282e4800277c90e`.
The installed order resolver calls `clearExpiredCooldowns`, which updates only
the in-memory store. For profile ordinals 2 and 3 it removed expired
`blockedUntil`, `blockedReason`, `blockedSource`, `errorCount` and `failureCounts`
state. No credential or ordering field changed, and the committed database
remained unchanged. Calling only that order resolver on a clone reproduces the
incorrect r4 checkpoint exactly:

* committed store: `1171996211c6ba4ccebe9378be3ed2492992e01896e11c5d038ec0e9104a8627`;
* in-memory checkpoint: `c19103c46071d5716254d2f2f4cc758229ce723133089b96b335eb171c746654`.

The correction clears the SDK snapshot cache and reloads the committed store
before recording the rollback checkpoint. It additionally asserts exact selected
credential and managed ordering. The original rollback requirements are intact:
whole-store equality before the transaction, whole-store equality again under
the installed SDK transaction lock, restoration of every baseline key, and full
logical equality after reloading the committed rollback. No comparison excludes
usage metadata, and no baseline field is silently discarded.

## Trust and identity constraints

Profile 2 is independently bound to the real account in current Mac native Codex
authentication and to its prior actual provider proof. Profile 1 now has a fresh
ROG-to-Mac capture whose account, provider/type, email and JWT account claim match
the existing Mac profile exactly. Its binding receipt is
`/Volumes/T5/hepta-vnext-recovery-20261013/authbus-profile1-source-36076-20261104-r1/source-binding.public.json`,
SHA256 `e23d1276a9d3a35da0ccb997b8b67179f5f97045bea4f036ce27401bd1fd0722`.
This source binding alone does not certify an SDK import or production switch.

Profile 3 was not declared invalid merely because its access token expired. A
separate, single native refresh was subsequently performed under the installed
SDK's global per-profile lock, with a source-generation compare immediately
before dispatch. The original response was sealed and fsynced before the native
SDK parsed it. Its HTTP 401 response explicitly contains `invalid_refresh_token`;
there is no unknown outcome and no retry. Details and limits appear below.

The legacy bridge is a separate consumer. It hard-codes selector `a96c1647e34a`
and refuses other selectors at startup. A valid existing profile must not be
renamed to impersonate that identity. Its installed source has not been found in
the searched readable Mac/ROG/desktop work roots. The live egress guard still
requires Germany and denies access: independent TLS probes found real geography
disagreement and no Germany result, not a stale cache. Diagnostic receipt:
`guard-diagnostic-r1/result.public.json`, SHA256
`c0a4f4e85fd1e3cac12c2b8534a39b0189a4e1cbddd78cc48fb3174fe30d667c`.
Neither guard semantics nor VPN or legacy selector were changed.

The production Mac/ROG/Pocket4 AuthBus clients still point to their old J3160
endpoint until a separately reviewed, reversible per-host switch is completed.
Private SDK or isolated gateway rollback is not production gateway rollback.
These receipts do not authorize deleting the old services, their usable recovery
material or the remaining unmigrated credentials.


## Final Mac actual gateway: independent failed business request

`final360-gateway-r8/result.public.json`, SHA256
`f93f529a2e4b30e18e729856d141b8c0ae6d4b29988180c50504bf53f04726de`,
is **57/58, overall false**. Actual installed OpenClaw 2026.7.1-2 gateway startup,
TLS/AppRole credential import, cold restart, exact stopped full-file-tree rollback,
installed SDK whole-store rollback and restored baseline gateway startup passed.
All production configuration, five auth stores, native authentication, installed
sources and legacy relay processes remained unchanged; every owned service stopped.

The only actual business probe used a fresh synthetic workspace and history,
`openai/gpt-5.6-sol` (the unchanged default), and the installed built-in HTTP provider path
`https://chatgpt.com/backend-api/codex/responses`. It sent one harmless short user
message and no tools. The real installed Undici dispatcher, original response
object and strict TLS verification were preserved. Exactly one POST was dispatched
and fully answered HTTP 429. The durable single-request ledger is sealed. Cold
restart and rollback performed no additional provider request. This path does not
use the old relay and does not establish that relay's migration or readiness.

The provider's structured error log reports `usage_limit_reached`; the gateway
reports `rate_limit_error`. Classification receipt
`final360-gateway-r8/business-provider-classification-r2.public.json`, SHA256
`f8bd706ced854db71e1029bfb0aaa16382eb8aa445c57ed531a4bce170db4323`, records
that scope precisely. The raw provider response body was not retained, so raw
JSON error code, reset timestamp and account-specific limits are not invented.
The first extractor receipt is retained separately; it did not identify the
structured log fields and was not overwritten.

Earlier gateway attempts retain separate failure receipts:

* `final360-gateway-r6/result.public.json`, SHA256
  `dd726744a2adab61f75b663ac2f0cc5666fcf3cc535a156a2dd04f9b6f9a0b83`:
  startup/cold-start/full-state rollback worked, but DNS resolution failed.
  There were three pre-dispatch DNS attempts and zero provider POSTs; claiming
  that the SDK never retried would be inaccurate. The actual runtime used the
  installed Undici export rather than only global fetch.
* `final360-gateway-r7/result.public.json`, SHA256
  `a8a62309050625fc3fc7f72d7ebe1b8bcadad0344a453478f82e55f5ff1afc22`:
  the observer rejected a missing account header before dispatch. No provider
  POST occurred. Actual pinned `openai-transport-stream-B0WkSqXp.js` does not
  synthesize that header. Its authentication is the bearer token whose JWT
  account claim matches the native account and selected credential. The corrected
  observer validates all three identities and exact Authorization bytes; it also
  validates the account header if present. It never adds or substitutes a header.
* Earlier r1-r5 sandbox/schema/initialization failures likewise remain separate
  terminal records. None dispatched a provider POST.

The r8 transport source SHA256 is
`82712e39d2863f055210df3a33f4a725872bcbf3dfef1b7ba181dba882f60edc`.
DNS permission was restricted to the actual macOS resolver socket. Native
subprocess permissions cover only the observed read-only mount, hardware-model
and OS-version probes. Channels, autonomous tasks, other-account refresh,
provider fallback, model changes and all further provider POSTs remained blocked.

### Runtime scope correction: built-in HTTP and the production Codex registry

The r8 isolated configuration allowed only `openai` and `openclaw-authbus`.
It did not carry the production `codex` plugin registry into the private gateway.
Consequently its real HTTP 429, cold restart and private full-state rollback
qualify that precise built-in HTTP configuration, not the complete production
runtime collection. The original r8 program, receipt and failed outcome remain
unchanged. Native Codex consumption is a separate necessary qualification.

The read-only current Mac audit is
`runtime-contract-source-r1/result.public.json`, SHA256
`37617ffc49187da02e24d0b2a5c9380a1e2fa5430ab01af7a9975b444562e9e8`.
It passed 22 static source/configuration checks without starting a gateway,
native app-server, OAuth flow or provider request. The exact installed-plugin
index row declares enabled global `@openclaw/codex` 2026.7.1-1 with harness
`codex`. Current default `openai/gpt-5.6-sol` has no explicit matching runtime
override. The custom ChatGPT endpoint does not meet the separate official
`api.openai.com` implicit-Codex predicate, so the source policy resolves to auto.
The installed auto selector chooses a registered supporting harness by priority;
the installed Codex harness supports `openai` and `codex` at priority 100.
This static audit does not inspect the live process registry or a live session's
runtime override, and does not assert which harness an existing session used.

Current Mac Codex app-server configuration omits command, transport and
`homeScope`; installed defaults resolve agent scope and the managed stdio
command. The observed service wrapper environment has no CODEX_HOME or Codex
command override. In that default scope the shared-client builder resolves the
SDK's `openai` auth order and sends its actual selected credential as
`chatgptAuthTokens` to local `account/login/start`. A caller's explicit null
auth-profile sentinel would instead use native auth; no such sentinel is
invented for this audit or for a subsequent positive consumer test.

`runtime-contract-source-r1/native-pin.public.json`, SHA256
`fce8536b33a83b920accd7264991759a13011057cac3502b0ce14fffc075339e`,
pins the actual managed launcher and selected native executable. The executable
SHA256 is `718724d7221cf1298071ca92411cb74caa8422809154150cedca7b569a4518e3`;
its sandboxed `--version` returned **0.144.3**. This is distinct from the
separately installed **0.133.0** CLI prepared for human recovery below. Only the
version command ran during the native pin audit. No app-server or account RPC
ran. The current main agent's `codex-home/auth.json` was absent; the existing
user native source was unchanged.

### Exact managed Codex 0.144.3 source contract

`runtime-contract-source-r1/official-source-contract.public.json`, SHA256
`f9de7db17bf33d0195ccad087b333bf8a83957b35417be0ca4712fda33775adc`,
records official `openai/codex` tag `rust-v0.144.3`, annotated tag object
`13307a9036baccd2c51b685d1457a4b89b5b2f3b`, resolving to commit
`78ad6e6bfd1d3b6a209acd3ef82172a96b25179c`. Thirteen source files were obtained
through the official GitHub connector; their complete bytes were checked against
their Git blob SHA identities. No fetched code was executed.

The version-specific findings matter for the isolated consumer's network guard:

* The 0.144.3 account-processor constructor only initializes state. Unlike the
  separately audited ROG 0.159.2 implementation, it does not spawn an initial
  `read_account` workspace-discovery task.
* The 0.144.3 `account/read` RPC with `refreshToken:false` skips the explicit
  refresh branch and obtains account state from the cached auth. That particular
  RPC is not evidence that the entire app-server stays offline.
* App-server startup immediately spawns an online models refresh worker. External
  token login replaces the cloud-config loader, whose startup and background
  tasks can request remote bundles for eligible business-like plans. Its retry
  and unauthorized-recovery branches can ask the parent external-auth bridge
  for refreshed credentials. Login completion can also start remote plugin-cache
  refresh. These are real background network-attempt paths.
* `chatgptAuthTokens` is installed through `set_external_auth` and mirrored into
  an Ephemeral process store. It does not use the ordinary File backend to save
  these external tokens into `auth.json`. The ordinary CLI File default is a
  separate contract, not proof about external-token persistence by itself.

The exact primary source entry points are:

* https://github.com/openai/codex/blob/rust-v0.144.3/codex-rs/app-server/src/request_processors/account_processor.rs
* https://github.com/openai/codex/blob/rust-v0.144.3/codex-rs/app-server/src/message_processor.rs
* https://github.com/openai/codex/blob/rust-v0.144.3/codex-rs/app-server/src/models_refresh_worker.rs
* https://github.com/openai/codex/blob/rust-v0.144.3/codex-rs/login/src/auth/manager.rs

A subsequent native consumption check must use actual installed registration,
the actual harness selector and the original agent-scope auth builder. The
isolated factory and production leased/shared factory both call
`resolveCodexAppServerClientStartContext` and
`startInitializedCodexAppServerClient`; the isolated factory changes client
cache/lease lifetime, not the process/auth construction. The callback may observe
or reject RPCs; it must not replace token parameters, native responses or SDK
selection. Kernel network denial must include all native descendants. Background
attempts cannot be reported as zero merely because egress is blocked. No native
factory success or business availability is claimed by this source-only audit.

### Actual Mac native lifecycle: one complete normal360 run

`final360-native-codex-live-r5/result.public.json`, SHA256
`6caa9ebfc2a3bf3ae637676a8055022817ec0efa85b09c6ffc304ac854ca6236`,
is the accepted complete native run. It passed 60/60 parent assertions, 95/95
in each initial/cold native consumer, and 62/62 in each complete logical-store
CAS rollback, in 14.113 seconds. The actual terminal sequence is exactly:

1. `consumer-initial`;
2. `consumer-cold-new-process`;
3. `consumer-initial.rollback`;
4. `consumer-cold-new-process.rollback`.

The real installed registry row was captured in a read-only SQLite transaction
and staged with its original schema. The actual installed loader registered the
enabled harness owners `codex`, `google`, and the `openai` provider. The real
selector chose the registered Codex harness for the unchanged main default
`openai/gpt-5.6-sol`; no runtime, model, preferred profile, `authProfileId`, or
`authProfileStore` override was supplied to the native factory. Original managed
command, argv, stdio and agent home-scope semantics were retained. The isolated
factory shares the pinned process/auth builder with the production leased factory;
its lifecycle is private to this test.

Actual AuthBus TLS/AppRole reads imported the two real, same-account generations.
The current SDK selected ordinal 1 in both phases, rather than fixing the earlier
ordinal 2 selection. The captured ordinal-1 quota timestamp had elapsed; its
committed quota metadata was retained. Each real native 0.144.3 process completed
`initialize`, its own `account/login/start` with exactly the selected access token
and account, and `account/read` with `refreshToken:false`. The original RPC
parameters and response objects passed through unchanged. Both native responses
and the exact isolated native home were checked. No model or explicit refresh
RPC was dispatched. Native startup background network attempts were not counted;
all external egress was blocked by the kernel. Local success does not certify
model quota, current provider connectivity, or production gateway availability.

The caller's existing process-lifecycle test hook keeps Node, its actual npm
launcher, and the actual native executable in the owned parent process group.
Before the first RPC, the outer Python owner reads only that lineage through
macOS libproc. It binds the exact executables, UID, PPID, PGID and microsecond
birth identities, then rechecks the complete chain. Its response pipe's write
end belongs only to the outer owner. Node waits for the matching nonce and real
identity acknowledgement before returning the spawned child to the installed
transport. The three-second observation deadline is capped by the unchanged
120-second parent deadline, including the second observation and successful ACK;
the native initialization budget remains 15 seconds.

One inherited kernel policy covers Node and native. They share the fresh run
directory and the exact test HeptaBao loopback endpoint. Other files below the
external-disk BASE are denied except exact pinned QA source files; production
agents/state/credentials, user Codex authentication, and production OpenClaw
configuration are denied. Signals are allowed only to children, so the actual
SDK can close its own transport. There is no native-exclusive home/tmp sandbox
or blanket local-network-denial claim. Four control files' bytes are hashed in
Node memory before native startup and compared after close: plan, original SDK
baseline, committed rollback checkpoint and private configuration. The committed
SDK store also remains completely unchanged by native consumption. Native
external tokens stay Ephemeral: no `auth.json` is created, and no literal provider
access/refresh token appears in native-home files.

`native-outer-observer-preflight-r2/result.public.json`, SHA256
`339368eb94ec0058bffcac531b343c941aa4f1cac161b6d89f3fac2fe7403f5a`,
proves the actual receiver/outer observer with synthetic processes: the real
lineage passes, a forged launcher-parent claim fails, owned children accept
SIGTERM/SIGKILL and are awaited, while signal 0 to this fixture's owned outer
ancestor is refused. No production PID, credential, app-server or provider is
used by that probe. Its prior r1 receipt, SHA256
`440782b784c154f3fd42c621d49bc7f7315e320271718eacf4135b730d23973d`,
remains failed because the original sandbox also refused child signals.

The complete r5 also proves policy denial, AppRole token renewal, revocation and
rejection of the revoked token, formal V6 persistence, actual SIGKILL/wait, cold
sealed startup and unseal. All four owned process groups were reaped with no
survivors or unknown outcome, and the HeptaBao process stopped. All five live
auth stores, user native source, production agent native inputs and legacy relay
PIDs stayed unchanged. This is a main-agent isolated native qualification, not a
restart or cutover of the production gateway or every live session.

The private full store differs from production in a deliberate, bounded way.
All three original identities remain. Ordinals 1 and 2 receive their independently
bound new generations and captured quota states; ordinal 3's credential remains
unchanged. The private managed order is 1,2, whereas the unchanged production
main SDK currently falls back through 1,2,3. This test does not authorize dropping
ordinal 3's production fallback, identity, failed-generation record or recovery
material. Both full-store rollbacks restore their own complete original baseline.

The final executed program hashes are:

| Program | SHA256 |
|---|---|
| `authbus_native_codex_consumer.mjs` | `a0faff4f0da0f9afd505476715495bf2ae4af040693020cf46e56b707aa7a733` |
| `authbus_native_codex_live.py` | `c384de8d1ada71f5fc4461a1cb5c03faaa178d42d88bfe6a652aa77c0ca101d0` |
| `authbus_native_process_observer.py` | `5cdebff7fc0f3350838abf02f0cbcd4a2b98862cd11b54a5d7ee683d48d3ca51` |

### Native attempts retained separately, including the r4 accounting defect

The native r1 receipt, SHA256
`0814acbe73fafc28e743916cad6a98e4717ca09db4396704d6179cf0edab4483`,
failed because the observer demanded `shell:false`; the actual POSIX spawn
contract uses undefined for no shell. Native r2, SHA256
`4f6869e6edf7dc39b199da31976eb0ef56aae7fff2315c38b45d37db33d32598`,
failed before any native RPC under the nested sandbox design. The independent
no-credential nested diagnostic, SHA256
`0035f98d5770db4a374876cc61666847959ae6c127903856b83dcd9c74c83eac`,
reports `sandbox_apply: Operation not permitted`; it is not retroactively
represented as r2's native stderr.

Native r3, SHA256
`0168c4a3a0703f2240145117366a42dbc31f7cd1ecdc5647282c53b369f5b4e6`,
used the single sandbox but its in-sandbox `/bin/ps` observer was refused. It sent
no native RPC. The original 120-second Node timeout remains `outcomeUnknown:true`;
the owner killed/reaped the group, and its one reached strict rollback passed.
Numbered checks before an exception are not an overall successful consumer.

Native r4, SHA256
`2c79b976d1cb3bdc18735a2e5c6d313515fb9b41be804154bfbbd21df2884086`,
contains two actual 95/95 native phases but is **not accepted as a complete
lifecycle**, despite its original `ok:true`. `consume(name)` reused `name` in
native-config loops. Both plan registrations used `requirements.toml`, so the
cold plan replaced the initial plan and only the cold rollback ran. This is a QA
accounting defect, not a successful initial rollback or a server rollback failure.

The initial rollback had never been attempted. A separate, create-only cleanup
used its exact original committed checkpoint and one installed-SDK CAS, passed
62/62, and reaped all owned processes. Its receipt is
`final360-native-codex-live-r4/initial-missing-rollback-cleanup-r1/result.public.json`,
SHA256 `8ebbdc7b15818d2dc4e213eccddf0486b112bb123b5a3c1e080c040e72c10024`.
That independent cleanup does not convert r4 into a same-run complete pass.
The original r4 bytes remain unchanged. R5 fixes the loop variable and requires
exactly two named plans, two distinct attempted/successful rollback guards, and
the precise four successful terminal phases. The fix patch SHA256 is
`8d912e7c344263ed04c73719d8ce49764bbe26a118553f89c49cc204d97b030e`.

### ROG's parallel native-user consumer is a different contract

ROG's independently read source-binding receipt is
`/home/qian-qi/heptabao-installed-authbus-consumer-36076-20261104-r1/native-production-binding-r1.public.json`,
SHA256 `3b301f822d896fa9a6435de03a8c8d78894600ebd396ecb718003e5aa0393dd5`.
Its current default is `codex/gpt-6.1-sol`, with explicit Codex runtime,
ChatGPT Responses API and **homeScope=user**. The fixed native executable is
0.159.2. Exact process-environment projection confirms the native CODEX_HOME is
`/home/qian-qi/.codex`; no access-token/API-key environment source was present.
In the actual shared-client builder, user scope sets `usesNativeAuth`, passes
the null sentinel and skips SDK credential injection into `account/login/start`.

That user native file belongs to a fourth independent account. Its stable
identity and generation match none of manifest profiles 1, 2 or 3. It is retained
as a parallel native source; no migration authority is inferred to replace it
with an unrelated managed profile. Future access expiry alone is not a provider
validity or quota proof. AuthBus imports into SDK stores with
`syncExternalCli=false`; its Codex recycler only retires/closes shared clients.
Rebuilding such a client continues reading the independent user native source.

The original generic SDK consumer failure remains **41/42**, failed case
`single_managed_default_candidate`, with strict rollback **39/39**. Its receipt
SHA256 is `eabde73457dcb83695f19034abb36a600cb269059ab96100c6ba862203d1dfba`.
Generic provider `codex` does not automatically alias to `openai`, but this
failure does not establish an alias defect in the production native path.
Changing the model, forcing agent scope or adding an unused alias would not
qualify the actual consumer. A separate isolated native preservation test and
later production restart/rollback must preserve this fourth account and actual
home scope. The source-binding receipt is not a successful runtime test.

The later ROG native-preservation run has a separate, narrower successful scope.
`/home/qian-qi/heptabao-installed-authbus-consumer-36076-20261104-r1/native-preservation-live-r3/result.public.json`,
SHA256 `4c905377b40663d972839117579fa3e0a317528ac6e6b9fddfd0765cd18c7472`,
passed 60/60 controller checks, 94/94 for each initial/cold consumer and 64/64
for each complete rollback. Its scope assessment SHA256 is
`bdcc830eb0d5becb0a26f5cb3f601ed34c31ab55e57fa2e1ad19ee7f872470a5`.
SDK source 1 is imported while the independent user-native source 4 is preserved.
Actual native CLI traces bind the copied native auth/config; the actual 0.159.2
factory initializes with the isolated user home. No explicit native login,
account-read or turn RPC is sent. Startup background attempts are unmeasured and
external egress is blocked. This does not claim source 1 drove native source 4,
or that the actual production gateway restarted or changed its auth binding.
The original generic 41/42 failure remains unchanged.

### Pocket's current default identity is a separate source

The bounded current runtime projection is
`/home/alex/heptabao-installed-authbus-consumer-36076-20261104-r1/pocket-native-runtime-source-r2/result.public.json`,
SHA256 `7668332584a3a7194f6579fbb899ecc0e329ee3588a18f3d057158ac5921329f`.
The default `openai/gpt-5.6-sol` has an explicit matching Codex runtime override,
agent home scope, and the managed 0.144.3 executable. The main store contains five
identities and its current `openai` order contains only local ordinal 5. That
identity/generation is distinct from the earlier imported ROG source 1. The
separate user-native file maps to local ordinal 4, not this default agent choice.
Earlier generic SDK import success must not be presented as preserving or
qualifying this current native consumer.

The actual installed registry/policy/auth-plan/native selector was separately
run on both configured agents, with no native process or provider request:
`actual-native-selector-r6/result.public.json`, SHA256
`79e232c4282796ffb07c174fbc32c5e4a4cb5f87167ec42851fd042cc8a8f3ea`,
passed 30/30. Both choose ordinal 5. The second agent inherits main's effective
profiles/order/usage through the real SDK. Its local profile map is empty, but
its raw SQLite representation contains one profile-free `primary` store row and
no state row. The shape correction receipt, SHA256
`158fb3da106d0b81abb110a002938aa2df86a1a76cc85d927e8dd6306b249adb`,
binds complete rows and timestamps to digest
`76f1ceb53832209d67692c17ba4967df8fa0114f2365989fa5a8c963b095c4e6`.
That distinction is necessary for exact rollback; an empty profile map does not
authorize deleting the original row or changing its timestamp.

Two subsequent Pocket native scopes were independently read in full. They use
normal server commit `33cafa4c6e29f0bde1553e041550d21b4c725d9c`, tree
`cdc2376e7b39c1d8bbbeb10a813d58bfe923f336`, Linux binary SHA256
`7dc5bc5157d62fd92e8cb10f1270f9ea776a929fde77a87eeb284509e82f1bba`.
They must not be relabeled as the Mac/X230 normal360 build.

| Pocket scope under the same host root | Receipt SHA256 | Original checks and observed effect |
|---|---|---|
| `current-native-full-r2/live/result.public.json` | `9006c6d0eae73de89dd62ed381877c873cabd1fff94f790ded7c3e2e2241c7dd` | 49 parent, 111 per initial/cold consumer, 80 per strict rollback; full-current import was idempotent in both agents |
| `current-native-missing-r2/live/result.public.json` | `133e1060d327bd14cae5b0673d3c5649c92d99c5d306f946114bcd480c691b41` | 49 parent, 110 per initial/cold consumer, 80 per strict rollback; real current ordinal-5 insertion into the owned main store, inherited by the second agent |

The latter private fixture removes only the current fifth credential from a
copy; production is kernel read-only. Real HeptaBao TLS/AppRole import restores
the exact full five-profile source. Main's raw auth rows change; the second
agent's raw row remains unchanged while its effective profile set inherits the
restored credential. Both retain current order and usage exactly. The real
installed loader, explicit default runtime and unforced native selector choose
ordinal 5 for both agents. Each factory performs real initialize and exact
`chatgptAuthTokens` login, and checks the native response type without replacing
the response. Native version/home, full local SDK store, inherited effective
store and complete original raw rows are separately verified.

Each scope has the four expected initial/cold/initial-rollback/cold-rollback
terminal records. The SDK transaction's actual local store is captured using
its updater-return-false contract; it is not confused with the merged effective
view. Each rollback guard is consumed once, including failures or unknowns.
Raw-row CAS preserves the profile-free primary row and original timestamp.
Both production auth tables, configuration, metadata, native inputs and held
unit registrations remain unchanged; all owned native groups and servers stop.
Private PID/network namespaces, read-only production mounts and the original
10/70/35-second HTTP/consumer/rollback budgets remain in effect. Startup backend
attempts are unmeasured, with no external network egress or model request. The
production held gateway is not restarted or released by these isolated results.

The earlier `current-native-full-r1` preflight remains 12/13 and overall false,
receipt SHA256 `9ea170dd126fdcd936c9d05ebf06c054596b1472f89610e4ecc23e10061097f2`.
It started no HeptaBao, SDK consumer or native process. Its incorrect raw-empty
premise was replaced by exact equality to the already captured profile-free
primary row; the native, CAS and budget requirements were retained.

The confirmed old-OpenBao consumer on these hosts is the installed AuthBus
importer/order service. It still points at J3160. Its SDK-store imports, Mac's
agent-scope external-token bridge and ROG's independent native-user path must be
evaluated separately. The finite source audit does not prove there are no other
business consumers or backup/startup dependencies.

## Two-source manifest and real installed consumer

`multisource-prepare-r2/prepare.public.json`, SHA256
`bb4f2e2c421102f9a0a31c70db7c26457a97a8a5bfac8227a3e372a2f3923228`,
passed 16/16. It binds the provider-verified ROG generation to the existing Mac
profile 1 and the native Mac generation to existing profile 2. Exact accountId,
provider/type, email and access-JWT identity match their existing owned accounts.
Profile 3 is excluded from the new manifest because of the explicit terminal
refresh rejection. No profile ID is renamed and no old selector is impersonated.

`multisource-prepare-r1` remains a failed preparation: an owned copied public
usage receipt had mode 0640 and was rejected by the private-input custody check.
Only that owned input's mode was corrected to 0600, preserving its byte hash;
r2 used a fresh directory.

`multisource-prepare-r2/order.public.json`, SHA256
`728b4b7b3bd51daf1294905d8837be0826d468579d0be9ec7ea8f7856667160e`,
passed 10/10 using the actual installed SDK on a private auth-only database.
The two configured order IDs are absent from the current store. The unchanged
SDK's original fallback order is 1,2,3. The prepared managed list preserves the
relative order 1,2 and excludes only the confirmed invalid account. After carrying
observed quota states, the actual SDK resolves 2,1. No new priority is invented.

Profile 1's captured source state has `subscription_limit`, source `wham`, and a
`blockedUntil` of 1793774885494 that was future at the original capture. A later
test must re-run the actual SDK's time-dependent ordering rather than assuming
that this timestamp is still future or fixing profile 2 as the selected account.
Profile 2 has the separately observed actual
model `usage_limit_reached` response. Both facts remain in the receipts. Valid
access tokens or a prior usage HTTP 200 do not demonstrate available model quota.

`final360-multisource-live-r1/result.public.json`, SHA256
`7a6ee0da71910aa58a8d95b517b4c2516a6f3fbf3ad4fac4e1fc5b55b07a7fcb`,
passed 45/45 parent assertions, 55/55 for each of the initial and cold installed
consumers, and 39/39 for each full SDK logical-store rollback. Runtime was 8.298 s.
It uses the same final normal Mac binary and real formal V6 storage. The installed
plugin reads both exact credentials through TLS/AppRole, imports both into their
original identities, preserves every other credential, and applies the prepared
managed order. The actual default resolver selects profile 2 without a profile or
model override. Both observed source quota states are carried with an installed
SDK transaction under a full-store CAS and remain exactly committed after import
and resolution. Expired in-memory cooldown normalization is not substituted for a
committed checkpoint. The exact whole baseline is restored under the SDK lock.

The HeptaBao process is SIGKILLed and awaited, restarts sealed, is unsealed, and
serves a fresh consumer process. AppRole policy denial, token renewal, revocation
and rejection of the revoked token also pass. Provider/model/refresh requests are
zero. Production endpoints and stores remain unchanged and ownedServerStopped
is true. These are isolated logical-store rollbacks; they do not constitute a
production gateway cutover or business availability proof.

## Explicit profile 3 refresh rejection and classification

`/Volumes/T5/hepta-vnext-recovery-20261013/authbus-profile3-native-refresh-36076-20261104-r1/result.public.json`,
SHA256 `3926b7f90c408c6bc0381a2cf98dc906c250cf2d31891a9e69dd4222e1a7d81d`,
is 26/27 and overall false. One installed native `refreshOpenAICodexToken` POST
went to `https://auth.openai.com/oauth/token` using its original client and exact
source refresh credential. TLS was verified. The 198-byte HTTP 401 response was
fully captured before parsing; its SHA256 is
`7f4779a716146c8192f86c11b7e4d8376209d61b8c5ad5e7b4f5bd25de86322f`.
The global lock was released and all production credentials/configuration stayed
unchanged. No new generation was produced and no request is replayed.

The initial QA reporter omitted `invalid_refresh_token` from its descriptive
rejection-code list. Therefore its old `refreshCredentialRejected` field is false,
while its terminal failure and overall failure are correctly recorded. The
independent `terminal-classification.public.json`, SHA256
`4b2f6683d202694efd2f0e0f72f33a7c180ddac4e040c2a002b9b667afe233bf`, correctly
classifies the exact sealed response as `invalid_request_error` /
`invalid_refresh_token`. The QA list is corrected in source without modifying or
rerunning the original receipt. The executed original QA script SHA256 was
`eae740106398d8d689cfcb5705ddfc193887076dff8caceeaa76e9a60e115506`.

The installed AuthBus permanent-error module already recognizes
`invalid_refresh_token`. The actual installed OAuth manager and outer resolver
wrap the native error with the required OAuth-refresh prefix; AuthBus then returns
`auth_permanent`. Runtime quarantine selects only an unambiguous recently failed
OAuth generation and retains exact credential-digest ownership; ambiguity is
fail-closed. This is distinct from the QA descriptive-field omission. The offline
real-error fixture first attempt stopped during SDK module import after ten
source/native-error checks, before semantic classification assertions. Its failure
receipt `refresh-classification-fixture-r1/result.public.json`, SHA256
`1399182b4cee06cf7c27695863525fa9a3a4a27f0985ddc7b1993588b3262ca2`, is preserved;
no full runtime classification pass is claimed from it.

The r2 fixture preserved another distinct failure:
`refresh-classification-fixture-r2/result.public.json`, SHA256
`f92d8d2dcff8edf81c0322dd6a0efc469fa99931f17b0dc0b70a3cf744295df5`.
It correctly classified AuthBus but artificially added an explicit HTTP status 401
to the generic SDK signal. That different shape is classified as `auth`; the real
native Error and OAuthRefreshFailureError do not have a status property. The
actual embedded-agent path calls the message-only classifier, while the generic
error path uses the installed nested-error extractor.

`refresh-classification-fixture-r3/result.public.json`, SHA256
`ff19118500187543a005b7669708e9aa98aebdca1b6bba0a54c0ad3acd1f738a`,
passed 26/26 with the exact sealed native error message. It constructs the actual
installed OAuthRefreshFailureError shape, invokes the original
`resolveFailoverReasonFromError` and `coerceToFailoverError` plus the embedded
message-only path, and verifies `auth_permanent` for both manager and outer
wrappers. The installed OAuth reason is `sign_in_again`; AuthBus retains the more
specific `invalid_refresh_token` reason. The synthetic explicit-401 signal is
still recorded separately as `auth`. Unique permanent-generation selection,
ambiguous-tie refusal and other-provider refusal also pass. No installed SDK or
plugin source was modified. These are offline classification/selection tests;
there was no production quarantine event or new provider request.

Read-only standard-source searches did not find a newer same-account generation:
ROG native/main stores have no target account, desktop and Pocket4 retain exactly
the same rejected generation, and the confirmed ai395 `/home/qq` standard native
and main-store paths are absent. Pocket4's exact comparison receipt is
`/home/alex/heptabao-installed-authbus-consumer-36076-20261104-r1/known-source-generation-comparison-r1.public.json`,
SHA256 `ac60715ada039f141c2ba40255790580c5fb72aba1f6a9c88b5d59b63995c01d`.
No J3160 access or whole-disk credential search was used.

### Finite current-consumer attribution of the rejected generation

`profile3-current-bindings-r1/result.public.json`, SHA256
`6a059b7f4b69b5cb37808b2e447eea6a89dda4a003d2eb5c4816510a0d0aba4e`,
uses already captured Mac configuration, five auth stores, the actual original
main SDK order and the replacement manifest. It performs no new provider request
or broad credential search. Exact nonmetadata configuration references to profile
3 were zero, but the original main SDK fallback is 1,2,3: profile 3 remains the
third candidate. This is not proof it is inactive or only historical. No current
session-specific profile override was observed. Its identity, rejected generation
and recovery materials must remain available in a migration; the private two-source
test's 1,2 order does not authorize removing that production fallback.

On Pocket, the same rejected generation remains stored, but both configured
default native selectors were actually evaluated and choose only ordinal 5.
Its finite exact configuration-reference count for profile 3 is zero. The
applicable source/reference and selector receipts are
`current-profile3-reference-r1/result.public.json` (SHA256
`eaa993fce1a8ce57c2d485344b7895de01c4713303d7057ff78c46fa0d20747b`)
and the 30/30 two-agent selector receipt above. ROG's user-native default source
is the separate fourth account. These bounded facts do not prove every possible
future/manual session choice, but they do not establish that restoring profile 3
is necessary for either Pocket default consumer or ROG's independent native path.

The exact rejected refresh is an external account-recovery fact. Existing model
quota limits and this failed generation are reported separately from HeptaBao
TLS, AppRole, KV, policy, persistence and rollback capability. They are not
automatically expanded into new prerequisites for replacing the credential store.
The human login helper remains prepared only; no rejected refresh, unknown login
or sealed business POST is replayed.

## Native authentication backend and prepared human recovery

The separately installed user CLI used for recovery preparation is Codex 0.133.0;
it is not the managed gateway binary described above. Its actual user configuration does not
set `cli_auth_credentials_store`. Exact official tag `rust-v0.133.0`, commit
`9474e5cfc4494b0ba319352aa86ce436c59e65c8`, declares CLI File as the default and
loads it with `unwrap_or_default`; the separate MCP OAuth backend defaults to Auto.
File storage reads CODEX_HOME/auth.json. No Keychain service was probed or dumped.
Backend receipt `codex-backend-source-r1/result.public.json`, SHA256
`e5a40bbec021717a51bbc69ec48a8bc9d6ecc6b537b1cf678a27ea754d91465b`, records
installed/config/source pins and the observed launch scope. This does not claim
that arbitrary unrelated future launch overrides are impossible.

The official versioned sources captured for review are:

* https://github.com/openai/codex/blob/rust-v0.133.0/codex-rs/config/src/types.rs
* https://github.com/openai/codex/blob/rust-v0.133.0/codex-rs/core/src/config/mod.rs
* https://github.com/openai/codex/blob/rust-v0.133.0/codex-rs/login/src/auth/storage.rs

`authbus_profile3_login_prepare.py` prepared the new private directory
`/Volumes/T5/hepta-vnext-recovery-20261013/authbus-profile3-isolated-native-login-20261104-r1`.
Its `prepared.public.json` SHA256 is
`21821d8152363bcf03d983505aaeb063d4fda52c2be763649a218269639ac845`.
The helper SHA256 at preparation is
`6cd350f8ecaf9950e665f013146d697d6d859f21f9d9a65cc7238a340ce7868a`.
Preparation verifies the unique original profile 3, the explicitly rejected source
generation, actual CLI version, current other native account, and unchanged five
production auth stores. It creates private recoverable baseline copies and checks
sandbox syntax with `/usr/bin/true`. **No login is started and no login code is
requested during preparation.**

When the operator is ready, the local `run-native-login.sh` invokes the actual
native device login in a TTY. Only its native CLI child receives a new CODEX_HOME
and explicit File backend. HOME remains the existing value; the caller shell is
not modified. A create-only attempt ledger prevents automatic second invocation.
The sandbox restricts writes to the new private root and denies reading the old
native auth and production agent stores. No logout, account refresh or production
pointer update is performed. On native success the helper requires the original
profile 3 accountId and JWT account, matching optional ID-token identity, a new
refresh generation, future access expiry, and unchanged native/config/all-store
baselines. It seals the same-account generation create-only with mode 0600 and
fsync. A wrong account or unknown result is retained privately and refused; no
credential or account identity is pasted into chat.

## Login preparation review revision r2

The initial login preparation r1 is retained as a superseded review artifact.
It has not started login. Review identified four concrete custody gaps, all fixed
in a fresh `authbus-profile3-isolated-native-login-20261104-r2` directory:

1. The final wrapper verifies the Python interpreter and bootstrap SHA256 before
   execution. The bootstrap verifies every frozen helper/dependency, the capture
   helper, reviewed runtime, sandbox and private intent before importing any task
   code. It executes copies in `frozen-program`, independent of mutable worktrees.
2. The native child may write only `native-login-home` and `tmp`. It cannot read
   the old native backup, auth-row backup or prepared intent, and cannot write
   those control files or create the attempt ledger.
3. The CLI runs in an owned new process group. Timeout, interruption and normal
   completion all stop any remaining members and reap the primary child before
   verification. Unknown/partial outcomes retain their attempt ledger and forbid
   automatic replay.
4. The exact installed native CLI is resolved using the reviewed npm launcher
   rules, hashed and version-checked. Login executes this exact native binary
   directly, avoiding later dynamic Node resolution. Node, Python, launcher and
   package sources are also pinned.

Preparation passed real local containment probes with no OAuth: writes to the new
home/tmp worked; reads/writes of the protected files and creation of the actual
attempt ledger were denied. Both synthetic timeout and interruption probes spawned
a child, killed and reaped their owned group, and ended with no group survivors.
The synthetic probes' unknown-outcome flags describe only those intentionally
interrupted local processes, not provider requests.

The r2 public receipts are:

* `prepared.public.json`: `1377d995d1feab5d77d5bdcd87c22f8226d009d4ee5c4270eef109c0978eb0f1`;
* `containment-probes.public.json`: `c9234e438c52ede6395123d0aa17ecaf77f1e3ecee8dcf4731542ee8318eee91`;
* `frozen-program-pins.public.json`: `0e37dfde07756e33acc939aaff2f94653c4357556c9ca335dc92fb32496a74a7`;
* `run-native-login.sh`: `4ad7f2b32788b9e0781ee160322a57a3fec3b64da9312607b9afe4cbe506cf66`.

Frozen main helper SHA256 is
`d1e7ba53c3bb36037c9f52bc8e46def05091e72f456c2e784fe7d7e0dd411a90`;
custody helper SHA256 is
`418f77d72235c6c34576ab7d18059841e49ca0af9253e3bc80fef15ec0385cdd`;
bootstrap SHA256 is
`2e2e6ba1d7e2239cfa50cb778128bd4b6d07be60373cadc09ae63e8c24572163`.
The original installed native binary at
`/opt/homebrew/lib/node_modules/@openai/codex/node_modules/@openai/codex-darwin-arm64/vendor/aarch64-apple-darwin/bin/codex`
has SHA256 `531957aaf16c742232ce6ea495ddc0208d959ea156b84a89cffad3f1b4d07efc`.
No login flow is started. The local wrapper is provided only after independent
review. It may show the original target email in the human's local TTY to reduce
wrong-account mistakes; no account identifier is written to public receipts.

## Remaining production migration and retirement gates

The reviewed production configuration shape remains `openclaw-authbus` with
address, CA, role-id file, secret-id file, hostId, leadership/publishing and order
policy. A production migration must create separately scoped host AppRoles at the
selected final HeptaBao TLS endpoint, retain host inbox boundaries, preserve all
existing account identity mappings and quota state, and snapshot the exact
previous configuration and every affected logical auth store before publication.
The same stopped gateway state and startup registration must be restorable.
The actual credential consumer, default runtime and restart/rollback must be
evaluated per host. ROG's `codex/gpt-6.1-sol` uses its independently bound user
native source; a generic provider-name alias would not qualify that path.
Provider business availability remains a separate recorded qualification. A
pre-existing quota limitation or retained rejected historical generation does
not by itself show that faithful credential-store migration failed. Conversely,
local token consumption does not claim provider availability. A private rollback
does not qualify the production recovery path.

All enumerated consumer configurations, startup jobs and backup paths must be
migrated or explicitly retired before old OpenBao/HeptaBao services, binaries or
recovery assets are deleted. Recent inventory found relay-internal bindings but
no direct current default-model binding to the old relay ports; that is not proof
that no legacy consumer exists. Legacy relay reconstruction is consequently not
an invented prerequisite for the independently configured native AuthBus path.

The finite four-host startup/client/backup planning scope is recorded at
`/home/qian/heptabao-cutover-cleanup-inventory-20261104-r1/finite-cutover-registration-scope-r2.public.json`,
SHA256 `f458db4ebda522c3054c48eca917b8d7aaafcef33c13892a846c53441b49aa64`.
It is a planning inventory, not proof of cutover or permission to ignore an
observed dependency. Newly observed active command/configuration or restore
bindings reopen that bounded scope. Hypothetical unregistered manual paths do
not add an unbounded search gate. Mac's four relay registrations, ROG's dormant
restart/accept helpers, Pocket's exact held startup markers, and X230's disabled
proxy/dev oracle remain individually tracked until their disposition is proved.
