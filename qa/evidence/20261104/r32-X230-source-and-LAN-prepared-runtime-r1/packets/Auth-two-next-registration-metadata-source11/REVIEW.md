# Actual source convergence and next two public metadata requests

## Result and current boundary

The complete three-source read is now closed and root-reviewed. It establishes why the old all-enabled npm-root predicate is not a general invariant of the installed SDK, and gives a concrete object-identity chain for a later selection observation. It does **not** identify the actual selected owner, qualify the Google code root, authorize an SDK import, or change the failed WAL caller.

This packet proposes only two new `file_info` operations, both derived from literal imports in the already whole-read loader. They have not been submitted. Line B has been released and reassigned; Runtime calls and native futures on this line are both zero.

The preceding completed windows remain 3 files / 3 chunks / 13,569 B plus 3 files / 4 chunks / 127,095 B, totalling **6 files / 7 chunks / 140,664 B**. The earlier 265,740-byte maximum is not reused or reset. These proposed metadata calls authorize zero body bytes. Purpose-built `file_info` hashes the whole file internally; it has no caller-supplied byte cap.

## What the current source resolves about the Google failure

The public catalog observed the Google code-root string `/opt/homebrew/lib/node_modules/openclaw/dist/extensions/google`; the original composite npm namespace predicate returned false, and actual selection remained null. That observation is retained.

The actual loader handles bundled candidates and built/dist runtime paths; its plugin record takes `source/rootDir` from the discovery candidate and its id from the manifest record. It has no universal rule requiring every enabled plugin to live beneath the client's npm projects namespace. In particular:

| Source evidence | Exact consequence |
| --- | --- |
| loader L1603–1620, L1640–1671 | Discovery candidates and a manifest registry are joined by root; the plugin id is `manifestRecord.id`. An enabled catalog row is not this actual load/registration event. |
| loader L1731–1753, L1780–1792 | The public record retains candidate source/root, while the runtime entry is separately realpathed and may prefer a built artifact. |
| loader L1909–1947 | Metadata-only mode skips registration. In executing mode the actual import uses `safeSource` after the root-file check, not merely the recorded root string. The checked FD is closed before module loading; this is not a lifetime-held-FD execution proof. |
| loader L2237–2276 | Registration receives schema-validated plugin config. With `activate:false`, the global harness table is restored afterward; this is not the original active registry selection path. |

These facts explain why a narrowly reviewed bundled-source admission may be needed. They do not justify deleting Google from the enabled set, widening a directory whitelist, or treating the observed directory string as a trusted executable source. The old guard remains byte-exact. A future successor must admit all code actually imported/registered/evaluated under the original scope from precise provenance and pins, then distinguish the selected credential owner. An unselected harness may still have executed registration or `supports`; selection is not permission to ignore that code.

The complete loader contains neither a Google manifest filename nor the implementation that binds a registration record to `ownerPluginId`. No `package.json` or `openclaw.plugin.json` path is inferred.

## Exact original selection chain

The latest failed caller's public worker is `3614c27cb06f311870ceeeda3f01e806306ae0d1`, 28,533 B, SHA256 `8c4a2cc09330cfda7a488e7e5caa811f4e190a10054a31f683b3466124210431`. Lines 335–343 already use:

1. Import runtime-registry-loader, selection, then harness registry in the same Node process.
2. `loader.t` with `scope:'all'`, the same `cfg` as both config and activationSourceConfig, original workspace, and complete `plan.harnessOwnerPluginIds`.
3. `selector.o` with only provider, modelId, config and agentId.
4. Preserve the original `selectedHarness.id === 'codex'` gate and `registry.r('codex').harness === selectedHarness` check.

No sessionKey, forced runtime override, extra channel scope, manifestRegistry override or disabled-activation mode is added.

The selector's L15231–15358 takes the actual harness objects from the registry; L15531–15538 returns the same selected object. The registry's L20–29 creates a stored harness copy and independently stores `ownerPluginId`; `harness.pluginId` is the harness-provided value or nullish fallback to the owner. They can differ. Therefore an identifier match alone does not establish ownership. The later diagnostic must compare the actual selected object with the actual record in that same registry, then bind both owner fields to the manifest/plugin record and admitted executed source.

`loader.t` can return early when an active wider registry satisfies its requested ids (runtime-loader L69–93); the scope is not a promise to remove extra registrations. In auto mode the real selector calls every registered candidate's `supports`, then sorts by descending priority and id tie-break. The forced branch also calls its actual candidate's `supports`. Both branches pass the real provider-ownership result. The separate effective-runtime helper in support source is not an equivalent selector replacement.

The original worker has prior SDK imports and auth-store operations at L311–334. This packet does not run that main or supply its private capsule to Node. A future credential-free diagnostic must explicitly account for original public import/cache/registry prestate; a fresh isolated selection observation will not be called a live-gateway instance observation.

## Specific configuration that cannot be casually removed

`CONFIG-AND-INSTANCE-CONTRACT.public.json` records the precise known read fields, original call shape and ordered future proof. These are a necessary lower bound, not a completed safe projection.

- Runtime policy depends on the actual agent/default model maps, provider/model `agentRuntime.id`, original array/key ordering, and exact presence/types. Direct provider keys precede normalized aliases; exact agent/model policy precedes wildcard/provider policy. Imported session/agent normalization still receives configuration, so this source does not prove an exhaustive projection.
- The default OpenAI routing branch also depends on provider `baseUrl`. Missing/blank values count as official; dropping a custom URL can change the chosen runtime. The predicate checks protocol/hostname/path but is not a general URL security validator. URLs and arbitrary request fields must not enter public output.
- Support context reads model/provider `api`, `baseUrl`, `params.azureApiVersion`, provider `request`, and provider ownership. The real selector imports the ownership resolver. Its implementation and every actual registered support callback/options remain necessary evidence; this packet does not guess ownership or substitute `unowned`.
- Loader configuration includes raw plugins normalization, explicit installs, normalized per-plugin config/hooks, original workspace/scope, environment/activation and manifest schema. Register receives cfg and plugin config. Neither an arbitrary plugin-config copy nor credentials stripped without a proven behavioral boundary is an equivalent credential-free input.
- QA force variables must not be introduced. The original five agents, models, declaration/default relationship and flags remain unchanged; all actual values are still unbound in this contract.

If preserving a required value would carry a credential, or an unreviewed callback can read omitted configuration, the credential-free proposal remains incomplete. It must not silently replace that value, execute the whole private configuration, or claim success from a handcrafted registry.

## Minimum next observation: two metadata files

| Sequence | Exact source import | Lexically derived metadata target |
| --- | --- | --- |
| 1 | loader L15: `./manifest-registry--UiRn6nq.js` | `/opt/homebrew/lib/node_modules/openclaw/dist/manifest-registry--UiRn6nq.js` |
| 2 | loader L40: `./registry-B8eQDFB4.js` | `/opt/homebrew/lib/node_modules/openclaw/dist/registry-B8eQDFB4.js` |

The first is the next implementation boundary for manifest-record/path derivation. The second is the next implementation boundary for plugin API registration-to-owner binding. Their contents may expose a remaining dependency; this packet makes no recursive-read commitment. Both are exact existing import literals; neither proves the target exists. Size, whole SHA, version, full9 and content are all null until separately authorized metadata actually returns. There is no fallback path, directory enumeration or body request in this proposal.

After actual metadata, any body request needs its own exact version/size/EOF budget and root GO. Other imported helpers are explicitly unresolved; no recursive readset is proposed. After source recovery, the independent diagnostic still requires a concrete allowed configuration projection, code/manifest/root admission, proven OS sandbox, original process isolation and deadlines, same-instance observation, and known terminal closure before it can affect the failed caller.

## Evidence and verification scope

`SOURCE-BASIS.public.json` gives ten complete immutable source pins already verified. `SOURCE-ANCHORS.public.json` gives exact 1-based line slices bound back to those whole bytes. The pure verifier checks those byte/source anchors, exact two request shapes, original worker call shape, and consumed-budget arithmetic. It only handles strings/data/hashes; it imports no SDK, executes no source function, opens no host resource and makes no Runtime call. Its result is a source-binding check, not a product case or an actual selection result.

All prior known failures and UNKNOWN records, original npm composite, WAL limits, expiry policy and fixture deadlines remain unchanged. No new runtime, credential use, production cutover, provider call or cleanup of old results is authorized here.
