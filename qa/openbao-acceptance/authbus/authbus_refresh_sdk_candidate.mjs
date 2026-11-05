/** Hash-bound, disposable SDK refresh hooks composed with the existing R4
 * admission/final-dispatch and the actually tested R5 SQLite commit bridge. */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import * as moduleApi from "node:module";
import { pathToFileURL } from "node:url";
import { DISPATCH_SDK_BINDINGS, patchDispatchSdkSource } from "./authbus_dispatch_sdk_candidate.mjs";
import { REFRESH_STORE_SDK_BINDINGS, patchRefreshStoreSdkSource } from "./authbus_refresh_store_sdk_candidate.mjs";

const sha256 = value => crypto.createHash("sha256").update(value).digest("hex");
const fail = code => { throw Object.assign(new Error(code), { diagnosticCode: code }); };
const once = (source, before, after) => {
  const at = source.indexOf(before);
  if (at < 0 || source.indexOf(before, at + before.length) >= 0) fail("trusted_refresh_sdk_source_boundary_changed");
  return source.slice(0, at) + after + source.slice(at + before.length);
};
const inside = (source, start, end, change) => {
  const at = source.indexOf(start), stop = source.indexOf(end, at + start.length);
  if (at < 0 || stop <= at || source.indexOf(start, at + start.length) >= 0) fail("trusted_refresh_sdk_function_boundary_changed");
  return source.slice(0, at) + change(source.slice(at, stop)) + source.slice(stop);
};
const helper = `function heptaBaoRefreshRegistry() {
  const registry = globalThis[Symbol.for("heptabao.authbus.admission.candidate.v1")];
  if (!registry || typeof registry.resolveManagedOAuthAccess !== "function" ||
      typeof registry.assertManagedRefreshEntry !== "function" ||
      typeof registry.dispatchManagedOAuthTransport !== "function" ||
      typeof registry.prepareGuardedOAuthTransport !== "function" ||
      typeof registry.enterGuardedOAuthRuntimeTransport !== "function" ||
      typeof registry.dispatchGuardedOAuthTransport !== "function") {
    throw Object.assign(new Error("AuthBus SDK refresh authority unavailable"), { diagnosticCode: "trusted_refresh_sdk_registry_unavailable" });
  }
  return registry;
}
`;

const refreshOnlyBindings = [
  { relative: "dist/credential-state-BY-oz-QV.js", originalSha256: "596a57e2ef09a3bc13a584781ddf749b66598b52a6b3f0817584bc6f401b4db4" },
  { relative: "dist/sqlite-B1ze-fre.js", originalSha256: "ed940f0ba0877eea0f00b2da30e727714993db60156fefc6fe80ac8564984c50" },
  { relative: "dist/runtime-snapshots-D6VA-VN8.js", originalSha256: "a1b70fb7664f40fd0a7e6a62f8d1215bca7d6aa465360a5762424100d0dafa4f" },
  { relative: "dist/bundled-dir-DKbeVv7V.js", originalSha256: "cf0976b5d6cf61faf8ceb10a43035a44dcd4f4c20557febc2428bde3fcb61b6d" },
  { relative: "dist/openclaw-root-_Kkan8Lf.js", originalSha256: "b38ffc9ed9d1de4b79213bf9aab474985ae62127ba5f148b14433d8cbb51b7b9" },
  { relative: "dist/oauth-BcZS_BvC.js", originalSha256: "2a3aef714168afd10ca2afc537744f5e44639eaad4113e443bcc371f457409b4" },
  { relative: "dist/chutes-oauth-YFvuN1-a.js", originalSha256: "f9e7bee3fbc4c311a960007f38e4057c70955c55e93caa7f0988a39aed940a55" },
  { relative: "dist/provider-runtime.runtime--yRUs3av.js", originalSha256: "93be7eb924cb45f84505f03696e5c6545a1e0e885b584b12c7357d98d729c9ab" },
  { relative: "dist/provider-runtime-CLQOjLJ6.js", originalSha256: "6daf266a90294162eb45ce8c9402ce15743df0ee1cc951e4e95602a3c6122338" },
  { relative: "dist/extensions/openai/api.js", originalSha256: "5490ab62c857124e421570502596f5189a228e44513d8ee18b11b6f3b47198f5" },
  { relative: "dist/openai-chatgpt-provider.runtime-DGoPIR1g.js", originalSha256: "c9248524ab3c9bf1226096ddd76d31a755518de1ff763e3c24245912b7aed92f" },
  { relative: "dist/openai-chatgpt-oauth-flow.runtime.js", originalSha256: "183d0ad3b17da4acae91ede7add0c3293eed186d0c0b29741fcab891c5743d3b" },
  { relative: "dist/openai-chatgpt-oauth-flow.runtime-DOVvnAqe.js", originalSha256: "e3852eb201e21b907beed38facea3b115f1058a80ba66436dc7202d36c6df07d" },
  { relative: "dist/openai-chatgpt-auth-identity-DrQLjrg2.js", originalSha256: "94d48f2fee6a6fc139438d53d1adbadb61dd9791febe11ea0ec1c960e30e3765" },
  { relative: "dist/fetch-guard-6VNcgVVc.js", originalSha256: "ef4befea09e2fbf0bece7bfc5cc46102843ee1070182fdab5b98f3c632a88bfc" },
  { relative: "dist/undici-global-dispatcher-DeobtFo9.js", originalSha256: "a8e81ea3c77cee197800a4ff9006dd0de56127e3103a85449685e928745b1e23" },
  { relative: "dist/runtime-fetch-k5Zth7kk.js", originalSha256: "9bf76247c5901725af5db78bbab2830a5e0fd7caf19953b095be74d4382db611" },
  { relative: "dist/facade-runtime-Dce8fe3v.js", originalSha256: "febd9b83ff5a398545f4ce350e49d2084b1704bdd01d467dbec889f4bfbe77f4" },
  { relative: "dist/facade-loader-ClPyIgA5.js", originalSha256: "5062ff2347de145c1f1253acd60c45c66cddb92825519c2dec277d93fe7d44d7" },
  { relative: "dist/facade-activation-check.runtime.js", originalSha256: "289f0f2efe2eaa482289692f8f58513ca0c1c9198ca4db11f32b95a6c107df9a" },
  { relative: "dist/plugin-module-loader-cache-uqaaAPup.js", originalSha256: "af5dc41aba74bb7eab264d1544d16a86906401bfe1c24a0ad53ae25bb8f1d2ac" },
  { relative: "dist/config-state-CtMlHVRM.js", originalSha256: "af2e3bc003048755d820284d3e01a777fae907aff3be8bc4e281dee663f409c5" },
  { relative: "dist/sdk-alias-BJSUcD8n.js", originalSha256: "a08f997f961d42aedf70699cfcb52b2785861412131cd718234aa31eca1dcb32" },
  { relative: "dist/undici-runtime-BL8ZN-Ey.js", originalSha256: "3528db33bb716a2e30fe895cd93c4027750c2da57379c8107d0b748cb0857978" },
  { relative: "dist/ssrf-BayeDjCv.js", originalSha256: "dd29e02505654eb7aac62519013fe9cdd883b56f78855806f6d643aadadc4295" },
  { relative: "dist/proxy-env-Bf6oQCTF.js", originalSha256: "5167b8055ce85f341e3df69a8d3c1e7877430fbcba63bcc052ad21abebb52bca" },
  { relative: "dist/managed-proxy-undici-RiF2s48t.js", originalSha256: "74b9478c30f20653068c1fc7f62b62ae805c1810d097150d5f8caeb08834a989" },
  { relative: "dist/active-proxy-state-DJLhrP_Z.js", originalSha256: "6723ab658f0df2dd3b833a1e8c9d35ee76001864ca93097f9919cf62ac3fa185" },
];
const bindings = new Map();
for (const binding of [...DISPATCH_SDK_BINDINGS, ...REFRESH_STORE_SDK_BINDINGS, ...refreshOnlyBindings]) {
  if (bindings.has(binding.relative) && bindings.get(binding.relative).originalSha256 !== binding.originalSha256)
    fail("trusted_refresh_sdk_overlapping_binding_conflict");
  bindings.set(binding.relative, Object.freeze({ ...binding }));
}
export const OAUTH_REFRESH_SDK_BINDINGS = Object.freeze([...bindings.values()]);
export const OAUTH_REFRESH_SDK_METADATA_BINDINGS = Object.freeze([
  Object.freeze({ relative: "dist/extensions/openai/openclaw.plugin.json",
    originalSha256: "0db880f0e5a77ad809ec4cf57767416364db021d617569c48fdb2703c8c9485f" }),
]);

export function patchOAuthRefreshSdkSource(relative, original) {
  const binding = bindings.get(relative);
  if (!binding || sha256(original) !== binding.originalSha256) fail("trusted_refresh_sdk_source_binding_changed");
  let candidate = DISPATCH_SDK_BINDINGS.some(item => item.relative === relative)
    ? patchDispatchSdkSource(relative, original)
    : REFRESH_STORE_SDK_BINDINGS.some(item => item.relative === relative)
      ? patchRefreshStoreSdkSource(relative, original) : original;
  if (relative === "dist/bundled-dir-DKbeVv7V.js") {
    // The owned adapter loads this exact SDK package. Its auxiliary source
    // checkout diagnostic must not probe an external QA entrypoint's parents.
    // Package discovery and all plugin activation checks remain SDK-owned.
    return once(candidate,
      'return uniqueStrings([resolveOpenClawPackageRootSync({ argv1: process.argv[1] }), resolveOpenClawPackageRootSync({ moduleUrl: import.meta.url })].filter((entry) => Boolean(entry)));',
      'return uniqueStrings([resolveOpenClawPackageRootSync({ moduleUrl: import.meta.url })].filter((entry) => Boolean(entry)));');
  }
  if (relative === "dist/oauth-B4aOCsid.js") {
    candidate = once(candidate, "\tasync function resolveOAuthAccess(params) {\n",
      `\tasync function resolveOAuthAccess(params) {
\t\tconst authbusManaged = await heptaBaoRefreshRegistry().resolveManagedOAuthAccess(params, {
\t\t\tneedsRefresh: Boolean(params.forceRefresh) || !hasUsableOAuthCredential(params.credential),
\t\t\trefreshCredential: credential => withRefreshCallTimeout(
\t\t\t\t\u0060refreshOAuthCredential(\u0024{credential.provider})\u0060, OAUTH_REFRESH_CALL_TIMEOUT_MS,
\t\t\t\t() => adapter.refreshCredential(credential)),
\t\t\tbuildApiKey: credential => adapter.buildApiKey(credential.provider, credential, { cfg: params.cfg, agentDir: params.agentDir })
\t\t});
\t\tif (authbusManaged.managed) return authbusManaged.value;
`);
    candidate = once(candidate, "async function refreshOAuthCredential(credential) {\n",
      "async function refreshOAuthCredential(credential) {\n\theptaBaoRefreshRegistry().assertManagedRefreshEntry({ provider: credential.provider, credential });\n");
    candidate = once(candidate, "async function refreshOAuthCredentialForRuntime(params) {\n",
      "async function refreshOAuthCredentialForRuntime(params) {\n\theptaBaoRefreshRegistry().assertManagedRefreshEntry({ provider: params.credential?.provider, credential: params.credential, cfg: params.cfg });\n");
    // R4 retains the old permit across resolution. Cross exactly this one
    // OAuth return through the already-private, freshly published successor.
    candidate = once(candidate,
      "\t\tif (!resolved) return null;\n\t\tif (leaseAdmission) admissionRegistry.assertCurrent(admissionParams, leaseAdmission, profileId);\n\t\treturn buildApiKeyProfileResult({\n\t\t\tapiKey: resolved.apiKey,",
      "\t\tif (!resolved) return null;\n\t\tif (leaseAdmission) admissionRegistry.advanceAfterRefresh(admissionParams, leaseAdmission, profileId, resolved.apiKey);\n\t\treturn buildApiKeyProfileResult({\n\t\t\tapiKey: resolved.apiKey,");
    return helper + candidate;
  }
  if (relative === "dist/oauth-BcZS_BvC.js") {
    candidate = once(candidate, "async function refreshAnthropicToken(refreshToken) {\n",
      "async function refreshAnthropicToken(refreshToken) {\n\theptaBaoRefreshRegistry().assertManagedRefreshEntry({ provider: \"anthropic\", refreshToken });\n");
    candidate = once(candidate, "async function refreshGitHubCopilotToken(refreshToken, enterpriseDomain, options = {}) {\n",
      "async function refreshGitHubCopilotToken(refreshToken, enterpriseDomain, options = {}) {\n\theptaBaoRefreshRegistry().assertManagedRefreshEntry({ provider: \"github-copilot\", refreshToken });\n");
    candidate = once(candidate, "async function refreshOpenAICodexToken(refreshToken) {\n",
      "async function refreshOpenAICodexToken(refreshToken) {\n\theptaBaoRefreshRegistry().assertManagedRefreshEntry({ provider: OPENAI_CODEX_PROVIDER_ID, refreshToken });\n");
    candidate = once(candidate, "\tif (!creds) return null;\n\tif (Date.now() >= creds.expires) try {",
      "\tif (!creds) return null;\n\tconst authbusManagedRefresh = heptaBaoRefreshRegistry().assertManagedRefreshEntry({ provider: providerId, credential: creds });\n\tif (authbusManagedRefresh || Date.now() >= creds.expires) try {");
    candidate = once(candidate, "\t\tcreds = await provider.refreshToken(creds);",
      "\t\theptaBaoRefreshRegistry().assertQualifiedRefreshFunction(providerId, provider.refreshToken);\n\t\tcreds = await provider.refreshToken(creds);");
    candidate = once(candidate, "\tif (!refreshed) return await loadOpenAICodexOAuthFacade().refreshOpenAICodexToken(refreshToken);",
      `\tif (!refreshed) {
\t\tconst facade = loadOpenAICodexOAuthFacade();
\t\theptaBaoRefreshRegistry().assertQualifiedRefreshFunction(OPENAI_CODEX_PROVIDER_ID, facade.refreshOpenAICodexToken);
\t\treturn await facade.refreshOpenAICodexToken(refreshToken);
\t}`);
    candidate = once(candidate, "function registerOAuthProvider(provider) {\n",
      "function registerOAuthProvider(provider) {\n\tif (heptaBaoRefreshRegistry().isManagedOAuthProvider(provider?.id)) throw Object.assign(new Error(\"AuthBus managed OAuth provider replacement denied\"), { diagnosticCode: \"trusted_refresh_provider_replacement_denied\" });\n");
    candidate = inside(candidate, "async function postJson(url, body, options = {}) {", "async function exchangeAuthorizationCode(", source => {
      let patched = once(source, "\tconst response = await fetch(url, {", "\tconst authbusSend = (target, init) => fetch(target, init);\n\tconst init = {");
      patched = once(patched, "\t});\n\tconst buffer = await readResponseWithLimit", `\t};
\tconst response = body.grant_type === "refresh_token"
\t\t? await heptaBaoRefreshRegistry().dispatchManagedOAuthTransport({ provider: "anthropic", operation: "anthropic-token-refresh", url, init }, authbusSend)
\t\t: await authbusSend(url, init);
\tconst buffer = await readResponseWithLimit`);
      return patched;
    });
    candidate = inside(candidate, "async function fetchResponse(url, init, operation, options = {}) {", "async function fetchJson(", source => {
      let patched = once(source, "\t\treturn await fetch(url, {", "\t\tconst authbusInit = {");
      patched = once(patched, "\t\t});\n\t} catch (error)", `\t\t};
\t\tconst authbusSend = (target, request) => fetch(target, request);
\t\treturn operation === "token refresh request"
\t\t\t? await heptaBaoRefreshRegistry().dispatchManagedOAuthTransport({ provider: "github-copilot", operation: "github-copilot-token-refresh", url, init: authbusInit }, authbusSend)
\t\t\t: await authbusSend(url, authbusInit);
\t} catch (error)`);
      return patched;
    });
    return helper + candidate;
  }
  if (relative === "dist/chutes-oauth-YFvuN1-a.js") {
    candidate = inside(candidate, "async function refreshChutesTokens(params) {", "//#endregion", source => {
      let patched = once(source, "async function refreshChutesTokens(params) {\n",
        "async function refreshChutesTokens(params) {\n\theptaBaoRefreshRegistry().assertManagedRefreshEntry({ provider: \"chutes\", credential: params.credential });\n");
      patched = once(patched, "\tconst response = await fetchFn(CHUTES_TOKEN_ENDPOINT, {", "\tconst authbusInit = {");
      patched = once(patched, "\t\tbody\n\t});\n\tif (!response.ok)", `\t\tbody
\t};
\tconst response = await heptaBaoRefreshRegistry().dispatchManagedOAuthTransport({
\t\tprovider: "chutes", operation: "chutes-token-refresh", url: CHUTES_TOKEN_ENDPOINT, init: authbusInit
\t}, (target, request) => fetchFn(target, request));
\tif (!response.ok)`);
      return patched;
    });
    return helper + candidate;
  }
  if (relative === "dist/provider-runtime.runtime--yRUs3av.js") {
    candidate = once(candidate, "async function refreshProviderOAuthCredentialWithPlugin(...args) {\n",
      "async function refreshProviderOAuthCredentialWithPlugin(...args) {\n\tif (heptaBaoRefreshRegistry().assertManagedRefreshEntry({ provider: args[0]?.provider, credential: args[0]?.context, cfg: args[0]?.config })) return null;\n");
    return helper + candidate;
  }
  if (relative === "dist/provider-runtime-CLQOjLJ6.js") {
    candidate = once(candidate, "async function refreshProviderOAuthCredentialWithPlugin(params) {\n",
      "async function refreshProviderOAuthCredentialWithPlugin(params) {\n\tif (heptaBaoRefreshRegistry().assertManagedRefreshEntry({ provider: params.provider, credential: params.context, cfg: params.config })) return null;\n");
    return helper + candidate;
  }
  if (relative === "dist/openai-chatgpt-provider.runtime-DGoPIR1g.js") {
    candidate = once(candidate, "function createOpenAICodexProviderRuntime(deps) {\n",
      `function createOpenAICodexProviderRuntime(deps) {
\tconst authbusOwnedDependencies = deps.ensureGlobalUndiciEnvProxyDispatcher === ensureGlobalUndiciEnvProxyDispatcher &&
\t\tdeps.getOAuthApiKey === getOpenAICodexOAuthApiKey && deps.refreshOpenAICodexToken === refreshOpenAICodexToken$1;
`);
    candidate = once(candidate, "\t\tasync getOAuthApiKey(...args) {\n",
      `\t\tasync getOAuthApiKey(...args) {
\t\t\tif (heptaBaoRefreshRegistry().assertManagedRefreshEntry({ provider: args[0], credential: args[1]?.[args[0]] }) && !authbusOwnedDependencies)
\t\t\t\tthrow Object.assign(new Error("AuthBus OpenAI runtime dependencies unqualified"), { diagnosticCode: "trusted_refresh_openai_runtime_dependencies_unqualified" });
`);
    candidate = once(candidate, "\t\tasync refreshOpenAICodexToken(...args) {\n",
      `\t\tasync refreshOpenAICodexToken(...args) {
\t\t\tif (heptaBaoRefreshRegistry().assertManagedRefreshEntry({ provider: "openai", refreshToken: args[0] }) && !authbusOwnedDependencies)
\t\t\t\tthrow Object.assign(new Error("AuthBus OpenAI runtime dependencies unqualified"), { diagnosticCode: "trusted_refresh_openai_runtime_dependencies_unqualified" });
`);
    return helper + candidate;
  }
  if (relative === "dist/openai-chatgpt-oauth-flow.runtime-DOVvnAqe.js") {
    candidate = once(candidate, "async function refreshAccessToken(refreshToken, options = {}) {\n",
      "async function refreshAccessToken(refreshToken, options = {}) {\n\theptaBaoRefreshRegistry().assertManagedRefreshEntry({ provider: \"openai\", refreshToken });\n");
    candidate = once(candidate, "async function refreshOpenAICodexToken(refreshToken) {\n",
      "async function refreshOpenAICodexToken(refreshToken) {\n\theptaBaoRefreshRegistry().assertManagedRefreshEntry({ provider: \"openai\", refreshToken });\n");
    return helper + candidate;
  }
  if (relative === "dist/fetch-guard-6VNcgVVc.js") {
    candidate = once(candidate, "async function fetchWithSsrFGuardInternal(params) {\n",
      "async function fetchWithSsrFGuardInternal(params) {\n\tconst authbusRefreshTicket = heptaBaoRefreshRegistry().prepareGuardedOAuthTransport(params);\n");
    candidate = once(candidate,
      "\t\t\tconst response = shouldUseRuntimeFetch ? await fetchWithRuntimeDispatcher(parsedUrl.toString(), init) : await defaultFetch(parsedUrl.toString(), init);",
      `\t\t\tconst response = shouldUseRuntimeFetch
\t\t\t\t? await fetchWithRuntimeDispatcher(parsedUrl.toString(), init, authbusRefreshTicket)
\t\t\t\t: authbusRefreshTicket
\t\t\t\t\t? await heptaBaoRefreshRegistry().dispatchGuardedOAuthTransport(authbusRefreshTicket, { url: parsedUrl.toString(), init }, defaultFetch)
\t\t\t\t\t: await defaultFetch(parsedUrl.toString(), init);`);
    candidate = once(candidate, "\t\t\tawait captureGuardedFetchExchange({",
      "\t\t\tif (!authbusRefreshTicket) await captureGuardedFetchExchange({");
    candidate = once(candidate, "\t\t\tif (isRedirectStatus(response.status)) {\n",
      `\t\t\tif (isRedirectStatus(response.status)) {
\t\t\t\tif (authbusRefreshTicket) {
\t\t\t\t\tawait response.body?.cancel().catch(() => void 0);
\t\t\t\t\tawait release(dispatcher);
\t\t\t\t\tthrow Object.assign(new Error("AuthBus OAuth refresh redirect denied"), { diagnosticCode: "trusted_refresh_redirect_denied" });
\t\t\t\t}
`);
    return helper + candidate;
  }
  if (relative === "dist/runtime-fetch-k5Zth7kk.js") {
    candidate = once(candidate, "async function fetchWithRuntimeDispatcher(input, init) {\n",
      `async function fetchWithRuntimeDispatcher(input, init, authbusRefreshTicket) {
\tconst authbusTicket = heptaBaoRefreshRegistry().enterGuardedOAuthRuntimeTransport(authbusRefreshTicket, { url: input, init });
`);
    candidate = once(candidate, "\treturn await runtimeFetch(input, normalizeRuntimeRequestInit(init, runtimeDeps.FormData));",
      `\tconst authbusInit = normalizeRuntimeRequestInit(init, runtimeDeps.FormData);
\treturn authbusTicket
\t\t? await heptaBaoRefreshRegistry().dispatchGuardedOAuthTransport(authbusTicket, { url: input, init: authbusInit }, runtimeFetch)
\t\t: await runtimeFetch(input, authbusInit);`);
    candidate = once(candidate,
      `async function fetchWithRuntimeDispatcherOrMockedGlobal(input, init) {
\tif (isMockedFetch(globalThis.fetch)) return await globalThis.fetch(input, init);
\treturn await fetchWithRuntimeDispatcher(input, init);
}`,
      `async function fetchWithRuntimeDispatcherOrMockedGlobal(input, init, authbusRefreshTicket) {
\tif (isMockedFetch(globalThis.fetch)) {
\t\tconst authbusTicket = heptaBaoRefreshRegistry().enterGuardedOAuthRuntimeTransport(authbusRefreshTicket, { url: input, init });
\t\treturn authbusTicket
\t\t\t? await heptaBaoRefreshRegistry().dispatchGuardedOAuthTransport(authbusTicket, { url: input, init }, (target, request) => globalThis.fetch(target, request))
\t\t\t: await globalThis.fetch(input, init);
\t}
\treturn await fetchWithRuntimeDispatcher(input, init, authbusRefreshTicket);
}`);
    return helper + candidate;
  }
  return candidate;
}

export function installOAuthRefreshSdkCandidate(openclawRoot, report) {
  if (typeof moduleApi.registerHooks !== "function") fail("node_sync_module_hooks_unavailable");
  const root = fs.realpathSync(openclawRoot), sources = new Map();
  report.oauthRefreshSdkModules = [];
  report.oauthRefreshSdkMetadata = [];
  for (const binding of OAUTH_REFRESH_SDK_METADATA_BINDINGS) {
    const file = path.join(root, binding.relative), stat = fs.lstatSync(file);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 65536) fail("trusted_refresh_sdk_metadata_custody_invalid");
    const bytes = fs.readFileSync(file);
    if (sha256(bytes) !== binding.originalSha256) fail("trusted_refresh_sdk_metadata_binding_changed");
    const value = JSON.parse(bytes.toString("utf8"));
    if (value.id !== "openai" || value.enabledByDefault !== true) fail("trusted_refresh_sdk_openai_manifest_changed");
    report.oauthRefreshSdkMetadata.push({ ...binding, bytes: bytes.length, usedAsCodeOverlay: false });
  }
  for (const binding of OAUTH_REFRESH_SDK_BINDINGS) {
    const file = path.join(root, binding.relative), stat = fs.lstatSync(file);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 262144) fail("trusted_refresh_sdk_source_custody_invalid");
    const original = fs.readFileSync(file, "utf8"), source = patchOAuthRefreshSdkSource(binding.relative, original);
    const receipt = { ...binding, candidateSha256: sha256(source), loaded: false };
    report.oauthRefreshSdkModules.push(receipt);
    sources.set(pathToFileURL(file).href, { source, receipt });
  }
  const hook = moduleApi.registerHooks({ load(url, context, nextLoad) {
    const candidate = sources.get(url);
    if (!candidate) return nextLoad(url, context);
    candidate.receipt.loaded = true;
    return { format: "module", source: candidate.source, shortCircuit: true };
  } });
  const qualified = new WeakMap();
  const supported = [];
  let qualifiedLoaded = false;
  let persistedSource;
  const readOwnedStore = agentDir => {
    if (!qualifiedLoaded || typeof persistedSource?.c !== "function") fail("trusted_refresh_sdk_owner_reader_unavailable");
    if (typeof agentDir !== "string" || !path.isAbsolute(agentDir)) fail("trusted_refresh_sdk_owner_path_required");
    // This exact SDK export reads only the requested persisted owner. Its
    // effective-store API also merges main profiles and is not an owner read.
    return persistedSource.c(agentDir, { allowKeychainPrompt: false }) ?? { version: 1, profiles: {} };
  };
  return Object.freeze({
    deregister: () => hook.deregister(),
    qualification: Object.freeze({
      providerOf: callback => typeof callback === "function" ? qualified.get(callback) ?? null : null,
      supportedProviders: () => Object.freeze([...supported]),
      readOwnedStore,
    }),
    async loadOwnedRefreshFunctions() {
      if (qualifiedLoaded) fail("trusted_refresh_sdk_qualification_already_loaded");
      persistedSource = await import(pathToFileURL(path.join(root, "dist/source-check-ZSz5NzGW.js")).href);
      if (typeof persistedSource.c !== "function") fail("trusted_refresh_sdk_persisted_reader_binding_changed");
      const oauth = await import(pathToFileURL(path.join(root, "dist/oauth-BcZS_BvC.js")).href);
      for (const providerId of ["anthropic", "github-copilot", "openai"]) {
        const provider = oauth.n(providerId);
        if (provider?.id !== providerId || typeof provider.refreshToken !== "function") fail("trusted_refresh_sdk_builtin_binding_changed");
        qualified.set(provider.refreshToken, providerId);
      }
      const chutes = await import(pathToFileURL(path.join(root, "dist/chutes-oauth-YFvuN1-a.js")).href);
      if (typeof chutes.a !== "function") fail("trusted_refresh_sdk_chutes_binding_changed");
      qualified.set(chutes.a, "chutes");
      const openaiRuntime = await import(pathToFileURL(path.join(root, "dist/openai-chatgpt-provider.runtime-DGoPIR1g.js")).href);
      const openaiFlow = await import(pathToFileURL(path.join(root, "dist/openai-chatgpt-oauth-flow.runtime-DOVvnAqe.js")).href);
      if (typeof openaiRuntime.r !== "function" || typeof openaiFlow.r !== "function" ||
          openaiFlow.n?.id !== "openai" || typeof openaiFlow.n.refreshToken !== "function")
        fail("trusted_refresh_sdk_openai_binding_changed");
      qualified.set(openaiRuntime.r, "openai");
      qualified.set(openaiFlow.r, "openai");
      qualified.set(openaiFlow.n.refreshToken, "openai");
      supported.push("anthropic", "github-copilot", "chutes", "openai");
      qualifiedLoaded = true;
      return Object.freeze({ builtinProviderFunctions: 3, openaiRefreshFunctionBindings: 3,
        openaiFacadeQualified: false, openaiTransportQualified: false, actualExecutionQualifiedByRunnerOnly: true });
    },
  });
}
export function verifyOAuthRefreshSdkUnchanged(root) {
  return [...OAUTH_REFRESH_SDK_BINDINGS, ...OAUTH_REFRESH_SDK_METADATA_BINDINGS]
    .every(binding => sha256(fs.readFileSync(path.join(root, binding.relative))) === binding.originalSha256);
}
