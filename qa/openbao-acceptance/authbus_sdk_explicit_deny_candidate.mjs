/** Review-only, hash-bound SDK candidate. Never writes the installed SDK.
 * The existing resolver already treats a present empty order as a deny.
 * Preserve that value across SQLite save/load and expose an explicit, locked
 * operation without changing the legacy setAuthProfileOrder([]) clear API.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import * as moduleApi from "node:module";
import path from "node:path";
import { pathToFileURL } from "node:url";

export const sha256 = value => crypto.createHash("sha256").update(value).digest("hex");
export const ORIGINAL_PLUGIN_SHA = "b19b6a9e7c1d57ccef8d67994ed3421891788ac30a82ff6bad2eef2ef7e30f9b";
export const DEADLINE_PLUGIN_SHA = "b59c461e710d12f1c2f85ed7f3a32f14c05818a491b55bdee8f597e7bf4588fc";

const oldPrune = '\tstore.order = store.order ? Object.fromEntries(Object.entries(store.order).map(([provider, profileIds]) => [provider, profileIds.filter((profileId) => keptOrderProfileIds.has(profileId))]).filter(([, profileIds]) => profileIds.length > 0)) : void 0;';
const newPrune = `\t// Preserve only an explicit empty input. Removing the last invalid profile
\t// reference must retain the existing clear/fallback behavior.
\tconst explicitDenies = new Set(Object.entries(store.order ?? {}).filter(([, profileIds]) => Array.isArray(profileIds) && profileIds.length === 0).map(([provider]) => provider));
\tstore.order = store.order ? Object.fromEntries(Object.entries(store.order).map(([provider, profileIds]) => [provider, profileIds.filter((profileId) => keptOrderProfileIds.has(profileId))]).filter(([provider, profileIds]) => profileIds.length > 0 || explicitDenies.has(provider))) : void 0;`;

const oldSetter = `async function setAuthProfileOrder(params) {
\tconst providerKey = normalizeProviderId(params.provider);
\tconst deduped = dedupeProfileIds(params.order && Array.isArray(params.order) ? normalizeStringEntries(params.order) : []);
\treturn await updateAuthProfileStoreWithLock({
\t\tagentDir: params.agentDir,
\t\tupdater: (store) => {
\t\t\tstore.order = store.order ?? {};
\t\t\tif (deduped.length === 0) {
\t\t\t\tif (!store.order[providerKey]) return false;
\t\t\t\tdelete store.order[providerKey];
\t\t\t\tif (Object.keys(store.order).length === 0) store.order = void 0;
\t\t\t\treturn true;
\t\t\t}
\t\t\tstore.order[providerKey] = deduped;
\t\t\treturn true;
\t\t}
\t});
}`;
const newSetter = `async function setAuthProfileOrder(params) {
\tconst explicitDeny = params.explicitDeny === true;
\tif (explicitDeny && (!Array.isArray(params.order) || params.order.length !== 0)) throw new Error("Explicit auth deny requires an original empty array");
\tconst providerKey = explicitDeny ? resolveProviderIdForAuth(params.provider) : normalizeProviderId(params.provider);
\tif (explicitDeny && !providerKey) throw new Error("Explicit auth deny requires a provider");
\tconst deduped = dedupeProfileIds(params.order && Array.isArray(params.order) ? normalizeStringEntries(params.order) : []);
\treturn await updateAuthProfileStoreWithLock({
\t\tagentDir: params.agentDir,
\t\t...(explicitDeny ? { saveOptions: { filterExternalAuthProfiles: false, syncExternalCli: false } } : {}),
\t\tupdater: (store) => {
\t\t\tstore.order = store.order ?? {};
\t\t\tif (explicitDeny) {
\t\t\t\t// Touch only this provider's selection metadata in the existing
\t\t\t\t// SQLite transaction. Never rewrite from a caller's stale store.
\t\t\t\tfor (const key of Object.keys(store.order)) if (resolveProviderIdForAuth(key) === providerKey) delete store.order[key];
\t\t\t\tstore.order[providerKey] = [];
\t\t\t\tif (store.lastGood) {
\t\t\t\t\tfor (const key of Object.keys(store.lastGood)) if (resolveProviderIdForAuth(key) === providerKey) delete store.lastGood[key];
\t\t\t\t\tif (Object.keys(store.lastGood).length === 0) store.lastGood = void 0;
\t\t\t\t}
\t\t\t\treturn true;
\t\t\t}
\t\t\tif (deduped.length === 0) {
\t\t\t\tif (!store.order[providerKey]) return false;
\t\t\t\tdelete store.order[providerKey];
\t\t\t\tif (Object.keys(store.order).length === 0) store.order = void 0;
\t\t\t\treturn true;
\t\t\t}
\t\t\tstore.order[providerKey] = deduped;
\t\t\treturn true;
\t\t}
\t});
}`;

export const SDK_PATCHES = [
  { relative: "dist/store-DH33UrUj.js", originalSha256: "25a5c7075e13b8fb32f498a90e5ee91d93b7e15972b3b74796f1325b5ba98ebf", changes: [[oldPrune, newPrune]] },
  { relative: "dist/source-check-ZSz5NzGW.js", originalSha256: "9c02bbf2df3cf123efe8c34c423ae4ea044371aab91d727f38986351695ce1c9",
    changes: [["\t\tif (list.length > 0) acc[providerKey] = list;", "\t\tif (list.length > 0 || value.length === 0) acc[providerKey] = list;"]] },
  { relative: "dist/profiles-DyU-YCq2.js", originalSha256: "075f9d6ecd43103c32a6908816bf42720076fd0aaedb2b5e7e96481d64a29ba5", changes: [[oldSetter, newSetter]] },
];

function fail(code) { throw Object.assign(new Error(code), { diagnosticCode: code }); }
function replaceExactly(source, before, after) {
  const start = source.indexOf(before);
  if (start < 0 || source.indexOf(before, start + before.length) >= 0) fail("candidate_source_boundary_changed");
  return source.slice(0, start) + after + source.slice(start + before.length);
}

export function patchSdkSource(relative, original) {
  const binding = SDK_PATCHES.find(item => item.relative === relative);
  if (!binding || sha256(original) !== binding.originalSha256) fail("installed_sdk_source_binding_changed");
  return binding.changes.reduce((source, [before, after]) => replaceExactly(source, before, after), original);
}

export function patchDeadlinePlugin(original) {
  if (sha256(original) !== DEADLINE_PLUGIN_SHA) fail("deadline_plugin_source_binding_changed");
  const first = "async function saveStrictLeaseOrder(";
  const next = "/** Clear only locally remembered grants";
  const start = original.indexOf(first), end = original.indexOf(next, start);
  if (start < 0 || end <= start) fail("plugin_clear_boundary_changed");
  const replacement = `async function saveStrictLeaseOrder(agentDir, provider, store, profileId) {
  if (profileId) return await saveManagedOrder(agentDir, provider, store, [profileId], profileId);
  // The candidate SDK owns an explicit deny in its existing SQLite write
  // transaction. Legacy SDKs ignore this option, so verify the persisted key
  // and never accept their clear/fallback behavior as a successful deny.
  const saved = await setAuthProfileOrder({
    agentDir, provider: resolveProviderIdForAuth(provider), order: [], explicitDeny: true,
  });
  if (!saved) return false;
  const verified = loadAuthProfileStoreWithoutExternalProfiles(agentDir, { allowKeychainPrompt: false });
  const verifiedOrderKey = findProviderKey(verified.order, provider);
  return Boolean(verifiedOrderKey) && sameOrder(verified.order[verifiedOrderKey], []) &&
    !findProviderLastGood(verified, provider);
}

`;
  return original.slice(0, start) + replacement + original.slice(end);
}

/** Load exactly three candidate modules in this disposable process. */
export function installSdkCandidate(openclawRoot, report) {
  if (typeof moduleApi.registerHooks !== "function") fail("node_sync_module_hooks_unavailable");
  const root = fs.realpathSync(openclawRoot);
  const modules = new Map();
  report.sdkCandidateModules = [];
  for (const binding of SDK_PATCHES) {
    const filename = path.join(root, binding.relative);
    const stat = fs.lstatSync(filename);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 262144) fail("sdk_candidate_source_custody_invalid");
    const source = patchSdkSource(binding.relative, fs.readFileSync(filename, "utf8"));
    const receipt = { relative: binding.relative, originalSha256: binding.originalSha256, candidateSha256: sha256(source), loaded: false };
    modules.set(pathToFileURL(filename).href, { source, receipt });
    report.sdkCandidateModules.push(receipt);
  }
  return moduleApi.registerHooks({
    load(url, context, nextLoad) {
      const candidate = modules.get(url);
      if (!candidate) return nextLoad(url, context);
      candidate.receipt.loaded = true;
      return { format: "module", source: candidate.source, shortCircuit: true };
    },
  });
}

export function verifyInstalledSdkUnchanged(openclawRoot) {
  return SDK_PATCHES.every(item => sha256(fs.readFileSync(path.join(openclawRoot, item.relative))) === item.originalSha256);
}
