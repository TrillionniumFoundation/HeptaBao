/** Exact-source overlay: disposable module hooks; installed SDK files stay intact. */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import * as moduleApi from "node:module";
import { pathToFileURL } from "node:url";
import { ADMISSION_SDK_BINDINGS, patchAdmissionSdkSource } from "./authbus_sdk_admission_candidate.mjs";

const sha256 = value => crypto.createHash("sha256").update(value).digest("hex");
const fail = code => { throw Object.assign(new Error(code), { diagnosticCode: code }); };
const once = (source, before, after) => {
  const position = source.indexOf(before);
  if (position < 0 || source.indexOf(before, position + before.length) >= 0) fail("dispatch_sdk_source_boundary_changed");
  return source.slice(0, position) + after + source.slice(position + before.length);
};
const helper = `function requireAuthbusDispatchRegistry() {
  const registry = globalThis[Symbol.for("heptabao.authbus.admission.candidate.v1")];
  if (!registry || typeof registry.assertTransportDispatch !== "function") throw new Error("AuthBus final dispatch authority unavailable");
  return registry;
}
`;
export const DISPATCH_SDK_BINDINGS = [
  ...ADMISSION_SDK_BINDINGS,
  { relative: "dist/stream-BcRkg2P0.js", originalSha256: "0224b5cf2a5338c423fa48417c74f0df36ec432111dc0f59c5e701ff7b2c781e" },
  { relative: "dist/fetch-guard-6VNcgVVc.js", originalSha256: "ef4befea09e2fbf0bece7bfc5cc46102843ee1070182fdab5b98f3c632a88bfc" },
];

export function patchDispatchSdkSource(relative, original) {
  const binding = DISPATCH_SDK_BINDINGS.find(item => item.relative === relative);
  if (!binding || sha256(original) !== binding.originalSha256) fail("dispatch_sdk_source_binding_changed");
  let candidate = ADMISSION_SDK_BINDINGS.some(item => item.relative === relative)
    ? patchAdmissionSdkSource(relative, original) : original;
  if (relative === "dist/model-auth-CJEm9SNp.js") {
    candidate = once(candidate,
      "\t\tif (leaseAdmission) admissionRegistry.assertCurrent({ cfg, provider, agentDir }, leaseAdmission, resolvedProfileId);\n\t\treturn result;",
      "\t\tif (leaseAdmission) return admissionRegistry.bindCredentialResult({ cfg, provider, agentDir }, leaseAdmission, resolvedProfileId, result, resolved.apiKey);\n\t\treturn result;");
    candidate = once(candidate,
      "function applyLocalNoAuthHeaderOverride(model, auth) {\n",
      "function applyLocalNoAuthHeaderOverride(model, auth) {\n\tmodel = requireAuthbusDispatchRegistry().bindModelForDispatch(model, auth);\n");
    candidate = once(candidate,
      "function applyAuthHeaderOverride(model, auth, cfg) {\n",
      "function applyAuthHeaderOverride(model, auth, cfg) {\n\tmodel = requireAuthbusDispatchRegistry().bindModelForDispatch(model, auth);\n");
    return helper + candidate;
  }
  if (relative === "dist/stream-BcRkg2P0.js") {
    candidate = once(candidate,
      "function buildGuardedModelFetch(model, timeoutMs, options) {\n",
      "function buildGuardedModelFetch(model, timeoutMs, options) {\n\tconst authbusDispatchCapability = requireAuthbusDispatchRegistry().captureModelDispatch(model);\n");
    candidate = once(candidate,
      "\t\tconst guardedFetchOptions = {\n\t\t\turl,",
      "\t\tconst guardedFetchOptions = {\n\t\t\t[Symbol.for(\"heptabao.authbus.request-capability.candidate.v1\")]: authbusDispatchCapability,\n\t\t\turl,");
    return helper + candidate;
  }
  if (relative === "dist/fetch-guard-6VNcgVVc.js") {
    candidate = once(candidate,
      "\t\t\tconst response = shouldUseRuntimeFetch ? await fetchWithRuntimeDispatcher(parsedUrl.toString(), init) : await defaultFetch(parsedUrl.toString(), init);",
      [
        "\t\t\trequireAuthbusDispatchRegistry().assertTransportDispatch(",
        "\t\t\t\tparams[Symbol.for(\"heptabao.authbus.request-capability.candidate.v1\")],",
        "\t\t\t\t{ provider: params.capture?.meta?.provider, model: params.capture?.meta?.model, url: parsedUrl.toString(), init });",
        "\t\t\tconst response = shouldUseRuntimeFetch ? await fetchWithRuntimeDispatcher(parsedUrl.toString(), init) : await defaultFetch(parsedUrl.toString(), init);",
      ].join("\n"));
    return helper + candidate;
  }
  return candidate;
}

export function installDispatchSdkCandidate(openclawRoot, report) {
  if (typeof moduleApi.registerHooks !== "function") fail("node_sync_module_hooks_unavailable");
  const root = fs.realpathSync(openclawRoot), sources = new Map();
  report.dispatchSdkModules = [];
  for (const binding of DISPATCH_SDK_BINDINGS) {
    const filename = path.join(root, binding.relative), stat = fs.lstatSync(filename);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 262144) fail("dispatch_sdk_custody_invalid");
    const original = fs.readFileSync(filename);
    const source = patchDispatchSdkSource(binding.relative, original.toString("utf8"));
    const receipt = { ...binding, candidateSha256: sha256(source), loaded: false };
    report.dispatchSdkModules.push(receipt);
    sources.set(pathToFileURL(filename).href, { source, receipt });
  }
  return moduleApi.registerHooks({ load(url, context, nextLoad) {
    const candidate = sources.get(url);
    if (!candidate) return nextLoad(url, context);
    candidate.receipt.loaded = true;
    return { format: "module", source: candidate.source, shortCircuit: true };
  } });
}

export function verifyDispatchSdkUnchanged(openclawRoot) {
  return DISPATCH_SDK_BINDINGS.every(item => sha256(fs.readFileSync(path.join(openclawRoot, item.relative))) === item.originalSha256);
}
