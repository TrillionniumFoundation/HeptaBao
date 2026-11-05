/**
 * Exact-source SDK admission candidate. Installed files are never changed.
 * This first adapter guards the actual SDK order and eligibility implementations.
 * Provider credential/dispatch entry points require their separate bound patches.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import * as moduleApi from "node:module";
import { pathToFileURL } from "node:url";
const sha256 = source => crypto.createHash("sha256").update(source).digest("hex");
const fail = code => { throw Object.assign(new Error(code), { diagnosticCode: code }); };
const once = (source, before, after) => {
  const i = source.indexOf(before);
  if (i < 0 || source.indexOf(before, i + before.length) >= 0) fail("admission_source_boundary_changed");
  return source.slice(0, i) + after + source.slice(i + before.length);
};
const helper = `function requireAuthbusLeaseAdmission(params) {
  const admission = globalThis[Symbol.for("heptabao.authbus.admission.candidate.v1")];
  if (!admission || typeof admission.decision !== "function") throw new Error("AuthBus admission authority unavailable");
  return admission.decision(params);
}
`;
export const ADMISSION_SDK_BINDINGS = [{
  relative: "dist/order-CeBlX0NH.js",
  originalSha256: "4674b1d9ccf77f2b3ef7dd87c394ad99404ba34e6b2a0efed661c4546ac5c732",
}, {
  relative: "dist/model-auth-CJEm9SNp.js",
  originalSha256: "2b5e700c9f7a7b012f8e7d7b0b56b06267e58861b3ebf8ca3a092bd74dd90aa7",
}, {
  relative: "dist/oauth-B4aOCsid.js",
  originalSha256: "505d561b6fe271c95d29d7b93b44cd0780ac5859342a98e46f20b4e08487234e",
}];
export function patchAdmissionSdkSource(relative, source) {
  const binding = ADMISSION_SDK_BINDINGS.find(item => item.relative === relative);
  if (!binding || sha256(source) !== binding.originalSha256) fail("admission_sdk_source_binding_changed");
  if (relative === "dist/model-auth-CJEm9SNp.js") return patchModelCredentialSource(source);
  if (relative === "dist/oauth-B4aOCsid.js") return patchProfileCredentialSource(source);
  let candidate = source;
  candidate = once(candidate, "//#region src/agents/auth-profiles/order.ts\n",
    helper + "//#region src/agents/auth-profiles/order.ts\n");
  candidate = once(candidate,
    `function resolveAuthProfileEligibility(params) {
\tconst providerAuthKey = resolveProviderIdForAuth(params.provider, { config: params.cfg });
\tconst cred = params.store.profiles[params.profileId];`,
    `function resolveAuthProfileEligibility(params) {
\tconst providerAuthKey = resolveProviderIdForAuth(params.provider, { config: params.cfg });
\tconst leaseAdmission = requireAuthbusLeaseAdmission({ ...params, providerAuthKey });
\tif (leaseAdmission && (!leaseAdmission.allowed || leaseAdmission.profileId !== params.profileId)) return {
\t\teligible: false, reasonCode: "authbus_lease_denied"
\t};
\tconst cred = params.store.profiles[params.profileId];`);
  candidate = once(candidate,
    `\tconst providerAuthKey = resolveProviderIdForAuth(provider, { config: cfg });
\tconst now = Date.now();`,
    `\tconst providerAuthKey = resolveProviderIdForAuth(provider, { config: cfg });
\tconst leaseAdmission = requireAuthbusLeaseAdmission({ ...params, providerAuthKey });
\tif (leaseAdmission && !leaseAdmission.allowed) return [];
\tconst now = Date.now();`);
  candidate = once(candidate,
    "\tconst isValidProfile = (profileId) => resolveAuthProfileEligibility({",
    "\tconst isValidProfile = (profileId) => (!leaseAdmission || profileId === leaseAdmission.profileId) && resolveAuthProfileEligibility({");
  candidate = once(candidate,
    `\t\tprovider,
\t\tprofileId,
\t\tnow
\t}).eligible;`,
    `\t\tprovider,
\t\tprofileId,
\t\tnow,
\t\tagentDir: params.agentDir
\t}).eligible;`);
  return candidate;
}
function patchModelCredentialSource(source) {
  let candidate = once(source,
    "async function resolveApiKeyForProvider(params) {\n\tconst { provider, cfg, profileId, preferredProfile } = params;\n\tconst agentDir = params.agentDir?.trim() || (cfg ? resolveDefaultAgentDir(cfg) : void 0);\n\tlet scopedStore = params.store;",
    [
      "async function resolveApiKeyForProvider(params) {",
      "\tlet { provider, cfg, profileId, preferredProfile } = params;",
      "\tlet agentDir = params.agentDir?.trim() || (cfg ? resolveDefaultAgentDir(cfg) : void 0);",
      "\tlet scopedStore = params.store;",
      "\tconst admissionRegistry = globalThis[Symbol.for(\"heptabao.authbus.admission.candidate.v1\")];",
      "\tif (!admissionRegistry) throw new Error(\"AuthBus admission authority unavailable\");",
      "\tconst admissionOwner = admissionRegistry.owner({ cfg, provider, agentDir });",
      "\tlet leaseAdmission = null;",
      "\tif (admissionOwner) {",
      "\t\tagentDir = admissionOwner.scope.agentDir;",
      "\t\tscopedStore = admissionRegistry.readStore(agentDir);",
      "\t\tleaseAdmission = admissionRegistry.decision({ cfg, provider, agentDir, store: scopedStore });",
      "\t\tif (!leaseAdmission?.allowed || profileId && profileId !== leaseAdmission.profileId) throw Object.assign(new Error(\"AuthBus request admission denied\"), { diagnosticCode: \"authbus_request_admission_denied\" });",
      "\t\tprofileId = leaseAdmission.profileId;",
      "\t\tparams = { ...params, store: scopedStore, lockedProfile: true };",
      "\t}",
    ].join("\n"));
  candidate = once(candidate,
    "\t\t\tprofileId\n\t\t});\n\t\tif (awsSdkProfileAuth) return awsSdkProfileAuth;",
    "\t\t\tprofileId\n\t\t});\n\t\tif (awsSdkProfileAuth && leaseAdmission) throw Object.assign(new Error(\"AuthBus lease cannot authorize ambient AWS credentials\"), { diagnosticCode: \"authbus_ambient_auth_denied\" });\n\t\tif (awsSdkProfileAuth) return awsSdkProfileAuth;");
  candidate = once(candidate,
    "\t\treturn result;\n\t}\n\tif (cfg?.auth?.profiles || cfg?.auth?.order) {",
    "\t\tif (leaseAdmission) admissionRegistry.assertCurrent({ cfg, provider, agentDir }, leaseAdmission, resolvedProfileId);\n\t\treturn result;\n\t}\n\tif (cfg?.auth?.profiles || cfg?.auth?.order) {");
  return candidate;
}
function patchProfileCredentialSource(source) {
  let candidate = once(source,
    "async function resolveApiKeyForProfile(params) {\n\tconst { cfg, store, profileId } = params;\n\tconst cred = store.profiles[profileId];\n\tif (!cred) return null;",
    [
      "async function resolveApiKeyForProfile(params) {",
      "\tconst { cfg, store, profileId } = params;",
      "\tconst cred = store.profiles[profileId];",
      "\tif (!cred) return null;",
      "\tconst admissionRegistry = globalThis[Symbol.for(\"heptabao.authbus.admission.candidate.v1\")];",
      "\tif (!admissionRegistry) throw new Error(\"AuthBus admission authority unavailable\");",
      "\tconst admissionParams = { cfg, store, provider: cred.provider, agentDir: params.agentDir };",
      "\tconst leaseAdmission = admissionRegistry.decision(admissionParams);",
      "\tif (leaseAdmission && (!leaseAdmission.allowed || leaseAdmission.profileId !== profileId)) throw Object.assign(new Error(\"AuthBus profile admission denied\"), { diagnosticCode: \"authbus_profile_admission_denied\" });",
      "\tif (leaseAdmission) admissionRegistry.assertCurrent(admissionParams, leaseAdmission, profileId);",
    ].join("\n"));
  candidate = once(candidate,
    "\t\tif (!key) return null;\n\t\treturn buildApiKeyProfileResult({",
    "\t\tif (!key) return null;\n\t\tif (leaseAdmission) admissionRegistry.assertCurrent(admissionParams, leaseAdmission, profileId);\n\t\treturn buildApiKeyProfileResult({");
  candidate = once(candidate,
    "\t\tif (!token) return null;\n\t\treturn buildApiKeyProfileResult({",
    "\t\tif (!token) return null;\n\t\tif (leaseAdmission) admissionRegistry.assertCurrent(admissionParams, leaseAdmission, profileId);\n\t\treturn buildApiKeyProfileResult({");
  candidate = once(candidate,
    "\t\tif (!resolved) return null;\n\t\treturn buildApiKeyProfileResult({\n\t\t\tapiKey: resolved.apiKey,",
    "\t\tif (!resolved) return null;\n\t\tif (leaseAdmission) admissionRegistry.assertCurrent(admissionParams, leaseAdmission, profileId);\n\t\treturn buildApiKeyProfileResult({\n\t\t\tapiKey: resolved.apiKey,");
  candidate = once(candidate,
    "\t} catch (error) {\n\t\tlet refreshedStore = error instanceof OAuthManagerRefreshError",
    "\t} catch (error) {\n\t\tif (leaseAdmission) throw Object.assign(new Error(\"AuthBus managed OAuth resolution failed\"), { diagnosticCode: \"authbus_managed_oauth_resolution_failed\" });\n\t\tlet refreshedStore = error instanceof OAuthManagerRefreshError");
  return candidate;
}
export const ATOMIC_PLUGIN_SHA256 = "6b3258940a325cdbb15edf705f951b8ad0ee8723e666935872cbb359c1e3ce41";
export function patchAdmissionPluginSource(source) {
  if (sha256(source) !== ATOMIC_PLUGIN_SHA256) fail("admission_plugin_source_binding_changed");
  let candidate = once(source,
    "    result.expiredKeys.add(epochKey);\n    const store = loadAuthProfileStoreWithoutExternalProfiles(agentDir, { allowKeychainPrompt: false });",
    [
      "    result.expiredKeys.add(epochKey);",
      "    const admissionRegistry = globalThis[Symbol.for(\"heptabao.authbus.admission.candidate.v1\")];",
      "    if (!admissionRegistry) throw new Error(\"AuthBus admission authority unavailable\");",
      "    admissionRegistry.closeExpired({ agentDir, provider });",
      "    const store = loadAuthProfileStoreWithoutExternalProfiles(agentDir, { allowKeychainPrompt: false });",
    ].join("\n"));
  candidate = once(candidate,
    "      const saved = await saveStrictLeaseOrder(agentDir, scope.provider, store, profileId);",
    [
      "      const admissionRegistry = globalThis[Symbol.for(\"heptabao.authbus.admission.candidate.v1\")];",
      "      if (!admissionRegistry) throw new Error(\"AuthBus admission authority unavailable\");",
      "      const saved = await admissionRegistry.saveAssignment({ agentDir, provider: scope.provider, grant, profileId },",
      "        async () => {",
      "          const saved = await saveStrictLeaseOrder(agentDir, scope.provider, store, profileId);",
      "          if (!saved) throw new Error(\u0060AuthBus strict lease transaction failed for agent \u0024{agentId}\u0060);",
      "          return saved;",
      "        },",
      "        () => {",
      "          const current = loadAuthProfileStoreWithoutExternalProfiles(agentDir, { allowKeychainPrompt: false });",
      "          const key = findProviderKey(current.order, scope.provider);",
      "          return Boolean(key) && sameOrder(current.order[key], profileId ? [profileId] : []) &&",
      "            (profileId ? findProviderLastGood(current, scope.provider) === profileId &&",
      "              credentialDigest(current.profiles?.[profileId]) === grant.digest : !findProviderLastGood(current, scope.provider));",
      "        });",
    ].join("\n"));
  return candidate;
}
export function installAdmissionSdkCandidate(openclawRoot, report) {
  if (typeof moduleApi.registerHooks !== "function") fail("node_sync_module_hooks_unavailable");
  const root = fs.realpathSync(openclawRoot), sources = new Map();
  report.admissionSdkModules = [];
  for (const binding of ADMISSION_SDK_BINDINGS) {
    const filename = path.join(root, binding.relative), stat = fs.lstatSync(filename);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 262144) fail("admission_sdk_custody_invalid");
    const source = patchAdmissionSdkSource(binding.relative, fs.readFileSync(filename, "utf8"));
    const receipt = { ...binding, candidateSha256: sha256(source), loaded: false };
    report.admissionSdkModules.push(receipt);
    sources.set(pathToFileURL(filename).href, { source, receipt });
  }
  return moduleApi.registerHooks({ load(url, context, nextLoad) {
    const candidate = sources.get(url);
    if (!candidate) return nextLoad(url, context);
    candidate.receipt.loaded = true;
    return { format: "module", source: candidate.source, shortCircuit: true };
  } });
}
export function verifyAdmissionSdkUnchanged(openclawRoot) {
  return ADMISSION_SDK_BINDINGS.every(item => sha256(fs.readFileSync(path.join(openclawRoot, item.relative))) === item.originalSha256);
}


