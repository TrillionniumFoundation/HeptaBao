#!/usr/bin/env node
/** Review-only lease regression with the real installed OpenClaw SDK.
 * The production plugin is read as source, never imported or changed. Only its
 * exact lease/store functions run, against new private SQLite databases.
 * All network entrypoints are disabled. Credential material is synthetic.
 * Exit 3 is an honest SDK/lease qualification failure, not a skipped test.
 */
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import vm from "node:vm";

const ORIGINAL_SHA = "b19b6a9e7c1d57ccef8d67994ed3421891788ac30a82ff6bad2eef2ef7e30f9b";
const hash = value => crypto.createHash("sha256").update(value).digest("hex");
const stable = value => Array.isArray(value) ? value.map(stable) : value && typeof value === "object"
  ? Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])])) : value;
const PROFILE = "google:authbus-lease-sdk-regression";
const CREDENTIAL = { provider: "google", type: "api_key", key: "synthetic-lease-regression-only-not-a-real-key" };
const DIGEST = hash(JSON.stringify(stable(CREDENTIAL)));
const FENCE_KEY = "google\u0000main";

function fail(message) { throw Object.assign(new Error(message), { diagnosticCode: message }); }
function ownedDirectory(directory) {
  const stat = fs.lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid() || (stat.mode & 0o077)) fail("private_directory_custody_invalid");
}
function writePrivate(filename, value) {
  const fd = fs.openSync(filename, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_TRUNC | fs.constants.O_NOFOLLOW, 0o600);
  try { fs.writeFileSync(fd, typeof value === "string" ? value : JSON.stringify(value) + "\n"); fs.fsyncSync(fd); }
  finally { fs.closeSync(fd); }
  const dir = fs.openSync(path.dirname(filename), fs.constants.O_RDONLY | fs.constants.O_DIRECTORY);
  try { fs.fsyncSync(dir); } finally { fs.closeSync(dir); }
}
function section(source, first, next) {
  const start = source.indexOf(first), end = source.indexOf(next, start + first.length);
  if (start < 0 || end <= start) fail("exact_source_function_boundaries_changed");
  return source.slice(start, end);
}
function grantDocument(epoch, expiresAt, overrides = {}) {
  return {
    schemaVersion: 1, generation: epoch,
    scopes: [{ hostId: "isolated-main", provider: "google", model: "synthetic-model", agentIds: ["main"], strict: true }],
    assignments: [{ hostId: "isolated-main", provider: "google", model: "synthetic-model", agentId: "main", status: "ASSIGNED", mode: "enforce", epoch, expiresAt, leaseId: "synthetic-lease-" + epoch, profileId: PROFILE, digest: DIGEST, ...overrides }],
    refreshLeases: [],
  };
}

async function worker(config, phase) {
  const report = { phase, checks: [], networkAllowed: false, actualSdk: true, credentialSource: "synthetic", productionMutation: false, qualified: false };
  function check(name, condition) {
    report.checks.push({ case: name, passed: Boolean(condition) });
    if (!condition) fail(name);
  }
  try {
    ownedDirectory(config.root);
    const state = path.join(config.root, phase === "original" ? "original-state" : "patched-state");
    const agent = path.join(state, "agents/main/agent");
    for (const directory of [state, path.join(state, "agents"), path.join(state, "agents/main"), agent, path.join(state, "credentials"), path.join(state, "home")]) {
      if (!fs.existsSync(directory)) fs.mkdirSync(directory, { mode: 0o700 });
      ownedDirectory(directory);
    }
    const configPath = path.join(state, "openclaw.json");
    if (!fs.existsSync(configPath)) writePrivate(configPath, { agents: { list: [{ id: "main", default: true, agentDir: agent }] } });
    process.env.OPENCLAW_STATE_DIR = state;
    process.env.OPENCLAW_CONFIG_PATH = configPath;
    process.env.OPENCLAW_HOME = path.join(state, "home");
    process.env.OPENCLAW_OAUTH_DIR = path.join(state, "credentials");
    for (const key of ["GOOGLE_API_KEY", "GEMINI_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "OPENCLAW_GATEWAY_TOKEN"]) delete process.env[key];
    const denyNetwork = () => fail("unexpected_network_attempt");
    http.request = http.get = https.request = https.get = denyNetwork;
    net.Socket.prototype.connect = denyNetwork;
    globalThis.fetch = denyNetwork;
    const sdk = await import(pathToFileURL(path.join(config.openclawRoot, "dist/plugin-sdk/agent-runtime.js")).href);
    check("default_main_agent_scoped", path.resolve(sdk.resolveDefaultAgentDir({})) === path.resolve(agent));
    check("sqlite_path_scoped", path.resolve(sdk.resolveAuthStorePathForDisplay(agent)) === path.join(agent, "openclaw-agent.sqlite"));
    report.sdkVersion = JSON.parse(fs.readFileSync(path.join(config.openclawRoot, "package.json"), "utf8")).version;
    report.resolverSourceSha256 = hash(String(sdk.resolveAuthProfileOrder));
    const rawSource = fs.readFileSync(phase === "original" ? config.originalSource : config.candidateSource, "utf8");
    report.executedSourceSha256 = hash(rawSource);
    const helper = await import("data:text/javascript;base64," + fs.readFileSync(config.leaseHelper).toString("base64"));
    const functions = [
      section(rawSource, "function isRecord(", "function profileLogId("),
      section(rawSource, "function findProviderKey(", "function uniqueProfileIds("),
      section(rawSource, "async function saveManagedOrder(", "function resolveScheduledProviderState("),
    ].join("\n");
    const globals = { crypto, path, ...helper, sameOrder: (a, b) => JSON.stringify(a) === JSON.stringify(b) };
    for (const name of ["resolveProviderIdForAuth", "loadAuthProfileStoreWithoutExternalProfiles", "saveAuthProfileStore", "setAuthProfileOrder"]) {
      check("actual_sdk_function_" + name, typeof sdk[name] === "function");
      globals[name] = sdk[name];
    }
    const context = vm.createContext(globals);
    vm.runInContext(functions + "\nglobalThis.apply = applyLeaseAssignments; globalThis.clear = saveStrictLeaseOrder; globalThis.expire = typeof expireKnownLeaseOrders === 'function' ? expireKnownLeaseOrders : null;", context, { timeout: 1000 });
    const read = () => { sdk.clearRuntimeAuthProfileStoreSnapshots(); return sdk.loadAuthProfileStoreWithoutExternalProfiles(agent, { allowKeychainPrompt: false }); };
    const resolve = store => sdk.resolveAuthProfileOrder({ cfg: {}, store, provider: "google" });
    const order = () => {
      const store = read(), explicit = Object.hasOwn(store.order ?? {}, "google");
      const resolved = resolve(store);
      check("actual_resolver_returns_array", Array.isArray(resolved));
      return { explicit, stored: store.order?.google ?? null, lastGood: store.lastGood?.google ?? null, resolved };
    };
    const denied = () => { const value = order(); return value.explicit && value.stored.length === 0 && value.lastGood === null && value.resolved.length === 0; };
    const granted = () => { const value = order(); return value.explicit && value.stored.length === 1 && value.stored[0] === PROFILE && value.lastGood === PROFILE && value.resolved.includes(PROFILE); };
    const fencePath = path.join(state, "fences.json");
    let epochs = fs.existsSync(fencePath) ? new Map(Object.entries(JSON.parse(fs.readFileSync(fencePath, "utf8")))) : new Map();
    const control = { hostId: "isolated-main", schedulerMode: "enforce" };
    const apply = (document, now) => context.apply([agent], document, control, epochs, { providers: {} }, now);
    const persistFences = () => writePrivate(fencePath, Object.fromEntries(epochs));
    const tick = config.tick;
    if (phase === "original" || phase === "seed") {
      sdk.saveAuthProfileStore({ version: 1, profiles: {} }, agent, { filterExternalAuthProfiles: false, syncExternalCli: false });
      check("new_sqlite_initially_empty", Object.keys(read().profiles ?? {}).length === 0);
      await sdk.upsertAuthProfileWithLock({ agentDir: agent, profileId: PROFILE, credential: CREDENTIAL });
      check("synthetic_credential_exact_sdk_readback", hash(JSON.stringify(stable(read().profiles[PROFILE]))) === DIGEST);
      const withEmptyOrder = { ...read(), order: { google: [] }, lastGood: undefined };
      report.inMemoryEmptyOrderDenies = resolve(withEmptyOrder).length === 0;
      sdk.saveAuthProfileStore(withEmptyOrder, agent, { filterExternalAuthProfiles: false, syncExternalCli: false, preserveOrderProfileIds: [] });
      const afterEmpty = order();
      report.sdkEmptyOrder = { explicitAfterSave: afterEmpty.explicit, resolvedCountAfterSave: afterEmpty.resolved.length };
      await apply(grantDocument(7, tick + 1000), tick);
      check("valid_grant_applied_through_actual_sdk", granted());
      if (phase === "original") {
        const result = await apply(grantDocument(7, tick + 1000), tick + 1001);
        report.originalExpiryBugObserved = result.staleAssignments === 1 && granted();
        const clearResult = await context.clear(agent, "google", read(), null);
        const afterClear = order();
        report.originalClearContract = { returnedSuccess: clearResult, explicitAfterSave: afterClear.explicit, resolvedCountAfterSave: afterClear.resolved.length };
        report.originalFalseDenyObserved = clearResult && !afterClear.explicit && afterClear.resolved.includes(PROFILE);
        report.observationComplete = true;
        return report;
      }
      check("deadline_persisted_with_original_grant", epochs.get(FENCE_KEY)?.grant?.expiresAt === tick + 1000);
      persistFences();
      report.seedComplete = true;
      return report;
    }
    check("cold_reopen_exact_synthetic_profile", hash(JSON.stringify(stable(read().profiles[PROFILE]))) === DIGEST);
    if (phase === "final-reopen") {
      check("cold_reopen_expired_tombstone", epochs.get(FENCE_KEY)?.status === "EXPIRED");
      await apply(grantDocument(10, tick + 10000), tick);
      check("clock_rollback_and_replay_do_not_resurrect", denied());
      report.qualified = true;
      return report;
    }
    check("cold_reopen_deadline_preserved", epochs.get(FENCE_KEY)?.grant?.expiresAt === tick + 1000);
    try { await apply(grantDocument(7, tick + 1000), tick + 1001); }
    catch (error) {
      const after = order();
      report.sdkDenyBlock = { guardErrorSha256: hash(String(error.message)), explicitOrder: after.explicit, resolvedCandidates: after.resolved.length, unsafeSuccessClaimPrevented: String(error.message) === "AuthBus expired lease order could not be cleared" };
      fail("installed_sdk_cannot_persist_explicit_deny");
    }
    check("same_epoch_expiration_clears_and_denies", denied());
    await apply(grantDocument(7, tick + 1000), tick);
    check("clock_rollback_cannot_resurrect_expired_epoch", denied());
    await apply(grantDocument(8, tick + 5000), tick + 2000);
    check("new_epoch_can_authorize", granted());
    const changed = await apply(grantDocument(8, tick + 9000), tick + 2001);
    check("same_epoch_extension_rejected", changed.staleAssignments === 1 && epochs.get(FENCE_KEY)?.grant?.expiresAt === tick + 5000 && granted());
    const lower = await apply(grantDocument(7, tick + 1000), tick + 2002);
    check("lower_epoch_expired_message_cannot_revoke_current_grant", lower.staleAssignments === 1 && granted());
    await context.expire([agent], control, epochs, tick + 5001);
    check("local_preflight_expires_without_network_or_control_document", denied());
    await apply(grantDocument(9, tick + 9000), tick + 6000);
    check("new_epoch_recovers_after_local_expiration", granted());
    const legacy = { ...epochs.get(FENCE_KEY) }; delete legacy.grant; epochs.set(FENCE_KEY, legacy);
    await context.expire([agent], control, epochs, tick + 6001);
    check("legacy_epoch_without_deadline_fails_closed", denied());
    await apply(grantDocument(9, tick + 9000), tick + 6002);
    check("same_epoch_cannot_upgrade_unknown_legacy_deadline", denied());
    await apply(grantDocument(10, tick + 10000), tick + 6003);
    check("higher_epoch_can_upgrade_legacy_state", granted());
    await apply(null, tick + 10001);
    check("missing_all_scopes_does_not_bypass_remembered_expiration", denied());
    persistFences();
    report.qualified = true;
  } catch (error) {
    report.errorCode = error.diagnosticCode ?? "unexpected_regression_failure";
    report.errorSha256 = hash(String(error.message));
  }
  return report;
}

async function main() {
  if (process.argv[2] === "--worker") {
    const result = await worker(JSON.parse(fs.readFileSync(process.argv[3], "utf8")), process.argv[4]);
    process.stdout.write(JSON.stringify(result) + "\n");
    return;
  }
  const names = { "--work-dir": "root", "--openclaw-root": "openclawRoot", "--original-source": "originalSource", "--candidate-source": "candidateSource", "--lease-helper": "leaseHelper" };
  const config = { tick: Date.now() };
  for (let i = 2; i < process.argv.length; i += 2) {
    if (!names[process.argv[i]] || !process.argv[i + 1]) fail("invalid_cli_arguments");
    config[names[process.argv[i]]] = path.resolve(process.argv[i + 1]);
  }
  if (Object.values(names).some(name => !config[name])) fail("missing_cli_arguments");
  if (hash(fs.readFileSync(config.originalSource)) !== ORIGINAL_SHA) fail("installed_plugin_source_binding_changed");
  const candidateHash = hash(fs.readFileSync(config.candidateSource));
  fs.mkdirSync(config.root, { mode: 0o700 }); // Must be a new directory.
  ownedDirectory(config.root);
  const configPath = path.join(config.root, "driver.private.json");
  writePrivate(configPath, config);
  const report = { schema: "authbus-lease-deadline-actual-sdk-v1", productionMutation: false, realCredentials: false, networkAllowed: false, hardPerRequestDeadlineQualified: false, originalSourceSha256: ORIGINAL_SHA, candidateSourceSha256: candidateHash, phases: [], ok: false };
  for (const phase of ["original", "seed", "reopen", "final-reopen"]) {
    const child = spawnSync(process.execPath, [process.argv[1], "--worker", configPath, phase], { encoding: "utf8", timeout: 45000, maxBuffer: 1024 * 1024 });
    writePrivate(path.join(config.root, phase + ".stdout.log"), child.stdout ?? "");
    writePrivate(path.join(config.root, phase + ".stderr.log"), child.stderr ?? "");
    if (child.status !== 0) { report.phases.push({ phase, processExit: child.status, errorCode: child.error?.code ?? null }); break; }
    let value;
    try { value = JSON.parse(child.stdout); }
    catch { report.phases.push({ phase, errorCode: "worker_output_not_json" }); break; }
    report.phases.push(value);
    if (value.errorCode) break;
  }
  report.originalSourceUnchanged = hash(fs.readFileSync(config.originalSource)) === ORIGINAL_SHA;
  report.candidateSourceUnchanged = hash(fs.readFileSync(config.candidateSource)) === candidateHash;
  report.ok = report.phases.length === 4 && report.phases.at(-1).qualified === true && report.originalSourceUnchanged && report.candidateSourceUnchanged;
  writePrivate(path.join(config.root, "public.json"), report);
  process.stdout.write(JSON.stringify(report) + "\n");
  if (!report.ok) process.exitCode = 3;
}

try { await main(); }
catch (error) {
  process.stdout.write(JSON.stringify({ ok: false, errorCode: error.diagnosticCode ?? "harness_setup_failure", errorSha256: hash(String(error.message)) }) + "\n");
  process.exitCode = 2;
}
