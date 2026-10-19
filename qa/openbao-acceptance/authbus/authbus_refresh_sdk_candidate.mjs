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
      typeof registry.dispatchManagedOAuthTransport !== "function") {
    throw Object.assign(new Error("AuthBus SDK refresh authority unavailable"), { diagnosticCode: "trusted_refresh_sdk_registry_unavailable" });
  }
  return registry;
}
`;

const refreshOnlyBindings = [
  { relative: "dist/credential-state-BY-oz-QV.js", originalSha256: "596a57e2ef09a3bc13a584781ddf749b66598b52a6b3f0817584bc6f401b4db4" },
  { relative: "dist/oauth-BcZS_BvC.js", originalSha256: "2a3aef714168afd10ca2afc537744f5e44639eaad4113e443bcc371f457409b4" },
  { relative: "dist/chutes-oauth-YFvuN1-a.js", originalSha256: "f9e7bee3fbc4c311a960007f38e4057c70955c55e93caa7f0988a39aed940a55" },
  { relative: "dist/provider-runtime.runtime--yRUs3av.js", originalSha256: "93be7eb924cb45f84505f03696e5c6545a1e0e885b584b12c7357d98d729c9ab" },
  { relative: "dist/provider-runtime-CLQOjLJ6.js", originalSha256: "6daf266a90294162eb45ce8c9402ce15743df0ee1cc951e4e95602a3c6122338" },
];
const bindings = new Map();
for (const binding of [...DISPATCH_SDK_BINDINGS, ...REFRESH_STORE_SDK_BINDINGS, ...refreshOnlyBindings]) {
  if (bindings.has(binding.relative) && bindings.get(binding.relative).originalSha256 !== binding.originalSha256)
    fail("trusted_refresh_sdk_overlapping_binding_conflict");
  bindings.set(binding.relative, Object.freeze({ ...binding }));
}
export const OAUTH_REFRESH_SDK_BINDINGS = Object.freeze([...bindings.values()]);

export function patchOAuthRefreshSdkSource(relative, original) {
  const binding = bindings.get(relative);
  if (!binding || sha256(original) !== binding.originalSha256) fail("trusted_refresh_sdk_source_binding_changed");
  let candidate = DISPATCH_SDK_BINDINGS.some(item => item.relative === relative)
    ? patchDispatchSdkSource(relative, original)
    : REFRESH_STORE_SDK_BINDINGS.some(item => item.relative === relative)
      ? patchRefreshStoreSdkSource(relative, original) : original;
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
  return candidate;
}

export function installOAuthRefreshSdkCandidate(openclawRoot, report) {
  if (typeof moduleApi.registerHooks !== "function") fail("node_sync_module_hooks_unavailable");
  const root = fs.realpathSync(openclawRoot), sources = new Map();
  report.oauthRefreshSdkModules = [];
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
    // Exact persisted owner read. The SDK's effective-store API also merges
    // main profiles and must not be used as a managed owner observation.
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
      supported.push("anthropic", "github-copilot", "chutes");
      qualifiedLoaded = true;
      return Object.freeze({ builtinProviderFunctions: 3, openaiFacadeQualified: false });
    },
  });
}
export function verifyOAuthRefreshSdkUnchanged(root) {
  return OAUTH_REFRESH_SDK_BINDINGS.every(binding => sha256(fs.readFileSync(path.join(root, binding.relative))) === binding.originalSha256);
}
