/** Hash-bound R5 credential commit on the actual SDK's existing transaction.
 * Installs only disposable module hooks. External CLI synchronization is
 * explicitly disabled, and a stale credential digest cannot overwrite a newer
 * SQLite credential. The caller cannot submit a whole stale profile store. */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import * as moduleApi from "node:module";
import { pathToFileURL } from "node:url";
import { SDK_PATCHES, patchSdkSource } from "./authbus_sdk_explicit_deny_candidate.mjs";
const sha256 = value => crypto.createHash("sha256").update(value).digest("hex");
const fail = code => { throw Object.assign(new Error(code), { diagnosticCode: code }); };
export const REFRESH_STORE_SDK_BINDINGS = SDK_PATCHES.map(({ relative, originalSha256 }) => ({ relative, originalSha256 }));
const managedCommit = `
const heptaBaoRefreshStable = value => Array.isArray(value) ? value.map(heptaBaoRefreshStable) : value && typeof value === "object"
  ? Object.fromEntries(Object.keys(value).sort().map(key => [key, heptaBaoRefreshStable(value[key])])) : value;
const heptaBaoRefreshDigest = value => heptaBaoRefreshCreateHash("sha256").update(JSON.stringify(heptaBaoRefreshStable(value))).digest("hex");
async function heptaBaoCommitManagedOAuthCredential(params) {
  if (!params || typeof params.agentDir !== "string" || !heptaBaoRefreshIsAbsolute(params.agentDir) || typeof params.profileId !== "string" || !params.profileId ||
      !/^[a-f0-9]{64}$/.test(params.expectedCredentialDigest ?? "") || params.credential?.type !== "oauth" ||
      typeof params.credential.provider !== "string" || !params.credential.provider ||
      typeof params.credential.access !== "string" || !params.credential.access ||
      typeof params.credential.refresh !== "string" || !params.credential.refresh ||
      !Number.isSafeInteger(params.credential.expires)) {
    throw Object.assign(new Error("AuthBus managed OAuth commit binding invalid"), { diagnosticCode: "trusted_refresh_sdk_commit_binding_invalid" });
  }
  const credential = structuredClone(params.credential), agentDir = params.agentDir, profileId = params.profileId, expectedDigest = params.expectedCredentialDigest;
  let updaterApplied = false;
  const saved = await updateAuthProfileStoreWithLock({
    agentDir,
    saveOptions: { filterExternalAuthProfiles: false, syncExternalCli: false },
    updater: store => {
      const previous = store.profiles[profileId];
      if (!previous || previous.type !== "oauth" || previous.provider !== credential.provider ||
          heptaBaoRefreshDigest(previous) !== expectedDigest) return false;
      store.profiles[profileId] = credential;
      updaterApplied = true;
      return true;
    },
  });
  // The frozen SDK returns a store for a no-op and null for a transaction
  // failure. A truthy return alone does not prove that this credential won.
  return updaterApplied && Boolean(saved?.profiles?.[profileId]) &&
    heptaBaoRefreshDigest(saved.profiles[profileId]) === heptaBaoRefreshDigest(credential);
}
export { heptaBaoCommitManagedOAuthCredential };
`;
export function patchRefreshStoreSdkSource(relative, original) {
  let candidate = patchSdkSource(relative, original);
  if (relative !== "dist/profiles-DyU-YCq2.js") return candidate;
  if (candidate.includes("heptaBaoCommitManagedOAuthCredential") || !candidate.includes("updateAuthProfileStoreWithLock")) fail("trusted_refresh_store_boundary_changed");
  return 'import { createHash as heptaBaoRefreshCreateHash } from "node:crypto";\nimport { isAbsolute as heptaBaoRefreshIsAbsolute } from "node:path";\n' + candidate + managedCommit;
}
export function installRefreshStoreSdkCandidate(openclawRoot, report) {
  if (typeof moduleApi.registerHooks !== "function") fail("node_sync_module_hooks_unavailable");
  const root = fs.realpathSync(openclawRoot), candidates = new Map();
  report.refreshStoreSdkModules = [];
  for (const binding of REFRESH_STORE_SDK_BINDINGS) {
    const file = path.join(root, binding.relative), stat = fs.lstatSync(file);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 262144) fail("trusted_refresh_sdk_source_custody_invalid");
    const original = fs.readFileSync(file, "utf8"), source = patchRefreshStoreSdkSource(binding.relative, original);
    const receipt = { ...binding, candidateSha256: sha256(source), loaded: false };
    report.refreshStoreSdkModules.push(receipt);
    candidates.set(pathToFileURL(file).href, { source, receipt });
  }
  return moduleApi.registerHooks({ load(url, context, nextLoad) {
    const candidate = candidates.get(url);
    if (!candidate) return nextLoad(url, context);
    candidate.receipt.loaded = true;
    return { format: "module", source: candidate.source, shortCircuit: true };
  } });
}
export function verifyRefreshStoreSdkUnchanged(root) {
  return REFRESH_STORE_SDK_BINDINGS.every(item => sha256(fs.readFileSync(path.join(root, item.relative))) === item.originalSha256);
}
