# Mac T5 R10: current credentials, cold start, owned launchd and inverse

This is a concrete source plan for the next Mac qualification. It has not created the proposed T5 root, captured new private input, started a service, or altered the production gateway. The R10 normal product and both normal44 results are accepted; the five-agent Mac consumer, actual Mac manager lifecycle and current Mac off-host recovery remain separate unexecuted scopes.

## Fixed product and storage identity

| Item | Exact binding |
| --- | --- |
| Canonical source | `49503322c7f446e5eb41e7744f1fdbd7f1192ecc`, tree `1d4211f91e1b34a2ed087a3bbef2e2884bac88e9` |
| Source directory | `/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261104-native-http-r10/source` |
| Normal server | `/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261104-native-http-r10/normal-release-tests-r1/artifacts/heptabao-server`, 93,038,816 bytes, `bc1fc6b8ded5a43a60ab4c562cd5e092e63ae9df77afd654c9af8c096c128c98` |
| Native receipt | 798 bytes, `16fa488ed8d7a9a46541b5aea5007e27b538e5c37f9246c14de0e5fe24b05ad1`, Git blob `3daa9c7e0537b066502606430b9289b39a249712` |
| Normal build receipt | 3,326 bytes, `f5746eaf7fd79c8001ac927c9738922297d6e5e575cbd12bc092aafa2c13f544`, Git blob `5d0f6fd01dfd4415610e6f30afe4b2ea203a4297` |
| Actual normal44 result | 24,522 bytes, `28f47931ad644e610d45af00545b343a8d5867546ea8d00a44cae0a3de13c961`, Git blob `f1721688e97951506f728bc7ae639e8107641696` |
| Required mounted volume | `/Volumes/T5`, UUID `FB804D1B-24CB-4D6E-AEA7-A9E180807758` |
| Proposed fresh root | `/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-r10-current-consumer-r1` |
| Original current home | `/Users/qianqi`, UID 501, Darwin arm64 |

The product source is the accepted 495033 revision even though the branch later received independent test-only fixture changes. No later branch tip, Linux binary, historical normal360 binary or published QA commit is substituted for the above product.

Before any future private file creation and on every actual owned service start, the guard checks the real diskutil UUID/mount result within the original 30-second guard bound, the held parent/device identity and all frozen source/config/binary pins. A missing or replaced T5 is a refusal. It must not cause an empty store to be created at the mount pathname. The new tree's private directories are 0700 and private files 0600; nothing is written into the existing R10 build root or the production OpenClaw directories.

## Current Mac behavior to preserve

The retained source projection is config `/Users/qianqi/.openclaw/openclaw.json`, SHA `ca2dd7d7879fa901dfb24e00837b56a4e0fd230600d7ed1e3086eda194187d4d`. The finite collector must establish its current status before this becomes a new private-capture input.

Five configured agents remain `main`, `trnm`, `hepta-ui`, `hepta`, and `hepta-backend`. Main and the latter three retain complete profiles 1/2/3, original order, usage, last-good state and raw row metadata. Trnm's profile-free primary row remains distinct from its actual effective inheritance from main. The common managed policy remains candidates **2,1**, activeProfile null, non-enforced and without a new scheduler; the existing Mac order remains **1,2,3**. Identity 3 and its already rejected generation remain local fallback/recovery material; this run does not refresh, publish or relabel it as valid.

The original `hostId=mac`, `leader=false`, `publishNew=true`, `manageOrder=true`, omitted exclusion/scheduler settings, releaseGeneration 200, poll interval, refresh margins, model, runtime and home-scope resolution remain unchanged. Only the four AuthBus connection keys point at the private test TLS service and its owner-private CA/role/secret files. Explicitly enumerated filesystem remapping and non-started channel/cron isolation in the owned copy are a separate, reported harness change; they do not count as a production four-key edit.

No synthetic credential, forced selected identity, quota reset, arbitrary usage mark, model override or home-scope override is allowed. An ordinary actual selector may choose the currently eligible source. Its choice must be reported rather than changed to obtain a pass. Current credential freshness and a provider's willingness to accept that credential are different observations.

## Recovered Mac source and necessary changes

The exact previous Mac source is independently recovered from QA commit `8a31986957805df7e27bdd17e34b02bdf96219d4`:

| Source | Whole SHA256 | Git blob |
| --- | --- | --- |
| authbus_native_codex_live.py, 36,421 bytes | `c384de8d1ada71f5fc4461a1cb5c03faaa178d42d88bfe6a652aa77c0ca101d0` | `d547432ce6045b93cfc1639c8ff217870127787e` |
| authbus_native_codex_consumer.mjs, 33,710 bytes | `a0faff4f0da0f9afd505476715495bf2ae4af040693020cf46e56b707aa7a733` | `e07e5106c9a49b1f95f453a6c6dac03c719f7141` |
| authbus_native_process_observer.py, 11,897 bytes | `2a2d8e61ba33b41a6617e5c900d502ee73b3e4a96377f1f502a64822875bb2a9` | `acc80fe9dcae285c0c162447d1fdf89e758cfa7a` |
| Observer preflight, 6,082 bytes | `104a09d76c8c9924fe3cc82f1205d6856c0d5c788d5ce4ee2c91b0e176a3e906` | `6bd31b879a340b829257b0e28a03e84ffd0ca1cc` |

This prior driver materializes only main, uses `multisource-canary`, sets publishNew false and a different poll interval, and carries a separately observed source-quota state into the private fixture. Those facts were legitimate within its historical scope; they prevent treating a binary-only rebinding as a current five-agent qualification.

The new source therefore needs a reviewed functional delta:

1. Bind the R10 product and actual current five-agent capture; materialize all five stores without filling trnm's raw-empty local row from its effective store.
2. Derive the private plugin config from the full original Mac config, changing only its connection fields while preserving hostId and all original AuthBus flags.
3. Reuse current full usage/order as captured. Remove the historical fixture-only quota rewriting and two-profile-only local assumptions.
4. Add complete six-cache byte/absence/identity custody and strict once inverse, following the already reviewed Pocket ownership contract but using Mac paths and actual Mac SDK behavior. Linux hard-coded prefixes, unshare and namespaces are not ported as if they existed on Mac.
5. Use the exact installed registry row and real current Mac plugin/module/native paths. Replace the old unguarded registry read with the reviewed bounded sidecar-aware capture contract.
6. Keep the actual Mac inherited kernel sandbox and native process observer, adding protected child registration and explicit unknown accounting where necessary. No argument-only observer, mocked login result or extra process is accepted as the native proof.

These six changes and source pins must be frozen before a real fixture. The old normal360 source and result stay immutable.

## Private capture and source custody

The current exact references are:

- SDK `/opt/homebrew/lib/node_modules/openclaw`; Node `/opt/homebrew/bin/node`.
- AuthBus `/Users/qianqi/.openclaw/extensions/openclaw-authbus`.
- Registered Codex plugin `/Users/qianqi/.openclaw/npm/projects/openclaw-codex-8902d781d4__openclaw-generation__g-49fd4dbfde2c5057/node_modules/@openclaw/codex`.
- Registry `/Users/qianqi/.openclaw/state/openclaw.sqlite`, exact installed_plugin_index row only.
- Prior native pin receipt `/Volumes/T5/hepta-vnext-recovery-20261013/authbus-profile2-selector-c138-20261104-r1/runtime-contract-source-r1/native-pin.public.json`, SHA `fce8536b33a83b920accd7264991759a13011057cac3502b0ce14fffc075339e`.
- Independent user-native `/Users/qianqi/.codex/auth.json` and `config.toml`; actual agent-scope native inputs resolved from the pinned installed runtime, starting with known main `/Users/qianqi/.openclaw/agents/main/agent/codex-home`.

They are precise prior observations, not newly read facts. A changed pin is not silently replaced by another installed version.

The proposed capture obtains the five exact primary auth store/state rows including updated_at and original absence, actual SDK local/effective projections, original config, six cache byte/absence identities and relevant native input metadata/bytes under private custody. A direct read-only SQLite transaction is admitted only under the guarded existing-sidecar contract. A missing-sidecar permission fallback must use the explicitly reviewed stable FD copy route and exact schema/column names; it may not open production SQLite to create a missing SHM or guess another table.

This is a live readonly source capture and final source fence, not a stopped global atomic backup. If a writer changes a selected row/cache/generation, the fixture stops and retains that observation. It never restores over production. A later production transition would need its own actually stopped baseline.

The credential source for managed 1/2 must retain the already verified original source receipts and private same-provider/type/account/email identities. The source packet supplies actual generations; this task does not call a provider to manufacture a newer one or refresh the known failed generation. Credential literals, private identities and native diagnostic output remain private. Public evidence is count/digest/provenance based.

## Actual consumer and cold/inverse phases

The owned root has fixed `qa`, `private-inputs`, `initial`, `cold-new-process`, `server`, `launchd`, `credential-recovery` and `public` subdirectories. All initial absences and input pins are checked before creating them. Original sources remain unchanged.

The TLS server uses the recovered proven smoke helper's actual allocated loopback address and formal native V6 file storage. The resulting port/address and real leaf/CA are recorded and become the only sandbox network exception; a commit prefix such as “36076” is not a port binding. Init, mount, activation and narrowly scoped test roles are newly created **inside this private fixture**. They are not production cluster/key-custody decisions.

The installed AuthBus must read manifest, profiles, order-policy and scheduler-assignments under the actual host role. PublishNew remains true. Exact managed1/2 events may be observed; other local identities remain deferred without a grant. It must not publish identity 3 or change the common order by treating an inbox write as enrollment authority.

Each configured agent goes through its actual installed SDK local/effective and native selection path. The kernel sandbox is inherited through Node, the installed launcher and native process. The permitted native RPC sequence is initialize, actual ephemeral chatgptAuthTokens login, and account/read with refreshToken false, then actual close-and-wait. No model RPC or provider response is used as a substitute. A real kernel containment preflight precedes credential-bearing native launch. The native process may access only the fresh run and its exact Bao loopback exception; external egress and production auth/config/agent/state reads remain denied. Background attempts are not falsely counted as zero when they were only blocked.

The existing Mac native operation limits remain start 15,000 ms, account read 8,000 ms and close 3,000 ms. The legacy aggregate consumer phase bound is 120 seconds. A five-agent phase shares that one deadline; it does not allocate five new 120-second windows. If the original aggregate controller/manager wrapper cap is unavailable, the new finite cap must be explicitly proposed and reviewed rather than described as historical.

After initial consumption, token deny/renew/revoke behavior is recorded under the same real role. The actual owned server is stopped, observed terminated, restarted sealed and explicitly unsealed with its private fixture recovery material. A genuinely new consumer process performs the cold phase.

Each initial/cold inverse consumes a durable once marker before action. It compares the exact committed local/effective checkpoint, restores complete logical state under the installed transaction contract, restores raw primary rows/updated_at/original absence, then restores all six cache bytes or absence under exact file CAS. It verifies every agent again, including trnm inheritance. A changed generation is preserved as a conflict; it is not overwritten. Shared KV/inbox/manifest history is not rewound.

Every unsafe dispatch is marked before send. An unknown response or manager/native outcome, failed CAS, source drift or unreaped process stops further business/cold steps. Independent cleanup has its own once ledger and does not become a replay. Public output counts phase records separately from unique labels and gives the exact full path mapping for duplicate basenames.

## Actual launchd scope, separated from production

The proposed owned labels are:

- `org.heptabao.qa.mac-authbus-r10-r1.server`
- `org.heptabao.qa.mac-authbus-r10-r1.consumer`

Their two 0600 plists live under the new T5 `launchd` directory. The registry domain is exactly gui/501. A reviewed wrapper guards the volume and fixed inputs before launching the normal server or sandboxed consumer. The launchd fixture has RunAtLoad true and KeepAlive false so an unknown or failed operation does not silently launch again. This qualifies an actual manager start/stop/new-process/reverse contract; it does not assert equivalence to the production gateway's KeepAlive true policy.

The exact operations are bootstrap of one owned plist, print of its exact label, and one bootout of that exact label. Before any cleanup following an ambiguous bootstrap, print must reconcile actual plist path/program/arguments and process identity against the private ownership receipt. A PID or label prefix alone is not enough. The actual manager registration, PID/start identity, child/native observer and readiness are all checked. Detached launchd services are not claimed to be controlled by the Python caller's process group. A bootout error or unknown result is not retried under a new identity.

The existing production label `ai.openclaw.gateway`, its four relay labels, its plist, wrapper, environment file, logs and state remain unchanged. The known plist SHA is `e176c41f40b462b288177c20ced94c0e645b3a58f6bda024e53366f1592e8d08`, and its known environment path is `/Users/qianqi/.openclaw/service-env/ai.openclaw.gateway.env`. Full current program arguments and wrapper path must come from actual accepted registration custody; the historical argument count eight does not invent their values.

A future production service forward/inverse is a separate concrete intent: actual local HA endpoint/CA/AppRole/cluster bindings, real original supervisor drain behavior, stopped writer baseline, compare-and-replace four-field config, same registration startup, then a verified exact inverse. Restoring the old J3160 connection is a reversible-config observation, not proof that J3160 became healthy.

## Current Mac recovery and the historical chain

The current credential recovery bundle must cover the full original credential-relevant config and connection custody; five primary/effective auth-state and inheritance relationships; all six caches; independently owned native inputs; and the actual gateway/wrapper/environment/registered dependency files. A coordinator owner journal is included only if actual enrollment gives this Mac such an ownership role.

A private fsynced copy on the same T5 is local rollback custody, not off-host recovery. The next encrypted recovery action must bind its actual algorithm, new or existing owner-private key custody and exact selected producer/restore code. The intended independent destination is an isolated X230 root. Transport/hash/decrypt/restore and the restored logical/raw/native/cache/config state must be checked using the actual current Mac bundle. A technical owned-fixture key, if selected and reviewed, is reported as such; it is not silently promoted to the production custody policy.

The already proven nine-receipt chain remains valuable historical evidence: capture November 2, transport/restore November 3, Linux main UID1000 under /home/qian-qi, 23 files/7DB/6auth stores. Its logical coherence qualification coexists with raw/stamp stability false. Neither the name main nor the physical fleet table makes it a current Mac capture.

Only an actual current registered command/config or restore binding expands this scope. There is no nine-independent-backup requirement, provider quota recovery requirement, or speculative manual-file discovery gate.

## Immediate handoff

The root-reviewed product pins and recovered Mac QA are ready. The finite Mac collector source is frozen separately and undergoing review. Next authoring work is the smallest five-agent Mac capture/consumer/raw-cache inverse delta plus actual volume-guarded launchd wrapper. Those executable candidates need their own source/AST/component review before any private capture or startup.

This plan does not grant runtime permission or claim any unexecuted result. Its fixed paths, identity constraints, exact preserved behavior and explicit pending code changes make the next action reviewable without changing existing production state.
