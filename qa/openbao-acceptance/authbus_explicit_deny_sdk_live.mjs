#!/usr/bin/env node
/** Isolated real-SDK regression for explicit deny persistence and lease expiry.
 * Three SDK source candidates load only in disposable processes; the installed
 * package and production plugin are read/hash checked and never changed.
 * A real SQLite abort also tests the remaining revocation/admission boundary.
 * Exit 3 is a qualification failure, including an honestly observed fail-open.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import vm from "node:vm";
import { DEADLINE_PLUGIN_SHA, ORIGINAL_PLUGIN_SHA, SDK_PATCHES, installSdkCandidate,
  patchDeadlinePlugin, sha256, verifyInstalledSdkUnchanged } from "./authbus_sdk_explicit_deny_candidate.mjs";

const PROFILE = "google:authbus-deny-owned";
const UNMANAGED = "google:authbus-deny-unmanaged";
const NEW_UNMANAGED = "google:authbus-deny-unmanaged-new";
const OTHER = "anthropic:authbus-deny-other";
const CREDENTIALS = Object.fromEntries([PROFILE, UNMANAGED, NEW_UNMANAGED, OTHER].map((profile, index) => [profile,
  { type: "api_key", provider: profile.split(":")[0], key: "synthetic-authbus-explicit-deny-credential-" + index }]));
const stable = value => Array.isArray(value) ? value.map(stable) : value && typeof value === "object"
  ? Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])])) : value;
const digest = value => sha256(JSON.stringify(stable(value)));
const DIGEST = digest(CREDENTIALS[PROFILE]);
const FENCE = "google\u0000main";
const fail = code => { throw Object.assign(new Error(code), { diagnosticCode: code }); };

function ownedDirectory(directory) {
  const stat = fs.lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid() || (stat.mode & 0o077)) fail("private_directory_custody_invalid");
}
function writePrivate(filename, value) {
  const temporary = filename + ".new";
  const fd = fs.openSync(temporary, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
  try { fs.writeFileSync(fd, typeof value === "string" ? value : JSON.stringify(value) + "\n"); fs.fsyncSync(fd); }
  finally { fs.closeSync(fd); }
  fs.renameSync(temporary, filename);
  const parent = fs.openSync(path.dirname(filename), fs.constants.O_RDONLY | fs.constants.O_DIRECTORY);
  try { fs.fsyncSync(parent); } finally { fs.closeSync(parent); }
}
function section(source, first, next) {
  const start = source.indexOf(first), end = source.indexOf(next, start + first.length);
  if (start < 0 || end <= start) fail("exact_plugin_function_boundaries_changed");
  return source.slice(start, end);
}
function control(epoch, expiresAt, revoke = false) {
  return { schemaVersion: 1, generation: epoch, refreshLeases: [],
    scopes: [{ hostId: "isolated-main", provider: "google", model: "synthetic-model", agentIds: ["main"], strict: true }],
    assignments: [{ hostId: "isolated-main", provider: "google", model: "synthetic-model", agentId: "main", epoch,
      status: revoke ? "UNASSIGNED" : "ASSIGNED", mode: "enforce", expiresAt,
      profileId: revoke ? null : PROFILE, digest: revoke ? null : DIGEST, leaseId: revoke ? null : "synthetic-lease-" + epoch }] };
}

async function worker(config, phase) {
  const report = { phase, checks: [], actualSdk: true, sdkCandidate: phase !== "original", networkAllowed: false,
    realCredentials: false, productionMutation: false, hardPerRequestDeadlineQualified: false };
  const check = (name, condition) => { report.checks.push({ case: name, passed: Boolean(condition) }); if (!condition) fail(name); };
  let hook;
  try {
    process.umask(0o077); // Only this disposable worker creates SDK databases.
    ownedDirectory(config.root);
    const stateName = phase === "original" ? "original-state" : phase.startsWith("write-failure") ? "failure-state" : "candidate-state";
    const state = path.join(config.root, stateName), agent = path.join(state, "agents/main/agent");
    for (const directory of [state, path.join(state, "agents"), path.join(state, "agents/main"), agent, path.join(state, "credentials"), path.join(state, "home")]) {
      if (!fs.existsSync(directory)) fs.mkdirSync(directory, { mode: 0o700 });
      ownedDirectory(directory);
    }
    const cfgPath = path.join(state, "openclaw.json");
    if (!fs.existsSync(cfgPath)) writePrivate(cfgPath, { agents: { list: [{ id: "main", default: true, agentDir: agent }] } });
    process.env.OPENCLAW_STATE_DIR = state;
    process.env.OPENCLAW_CONFIG_PATH = cfgPath;
    process.env.OPENCLAW_HOME = path.join(state, "home");
    process.env.OPENCLAW_OAUTH_DIR = path.join(state, "credentials");
    for (const name of ["GOOGLE_API_KEY", "GEMINI_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "OPENCLAW_GATEWAY_TOKEN"]) delete process.env[name];
    if (process.env.OPENCLAW_AUTH_STORE_READONLY === "1") fail("inherited_readonly_auth_store");
    const denyNetwork = () => fail("unexpected_network_attempt");
    http.request = http.get = https.request = https.get = denyNetwork;
    net.Socket.prototype.connect = denyNetwork;
    globalThis.fetch = denyNetwork;
    if (report.sdkCandidate) hook = installSdkCandidate(config.openclawRoot, report);
    const sdk = await import(pathToFileURL(path.join(config.openclawRoot, "dist/plugin-sdk/agent-runtime.js")).href);
    check("default_main_agent_scoped", path.resolve(sdk.resolveDefaultAgentDir({})) === path.resolve(agent));
    const databasePath = path.join(agent, "openclaw-agent.sqlite");
    check("database_scoped", path.resolve(sdk.resolveAuthStorePathForDisplay(agent)) === databasePath);
    report.sdkVersion = JSON.parse(fs.readFileSync(path.join(config.openclawRoot, "package.json"), "utf8")).version;
    if (report.sdkCandidate) check("exact_three_candidate_modules_loaded", report.sdkCandidateModules.length === 3 && report.sdkCandidateModules.every(item => item.loaded));
    const source = phase === "original" ? fs.readFileSync(config.originalSource, "utf8") : fs.readFileSync(config.generatedPlugin, "utf8");
    check("executed_plugin_source_bound", sha256(source) === (phase === "original" ? ORIGINAL_PLUGIN_SHA : config.generatedPluginSha256));
    report.executedPluginSha256 = sha256(source);
    const helper = await import("data:text/javascript;base64," + fs.readFileSync(config.leaseHelper).toString("base64"));
    const functions = [section(source, "function isRecord(", "function profileLogId("),
      section(source, "function findProviderKey(", "function uniqueProfileIds("),
      section(source, "async function saveManagedOrder(", "function resolveScheduledProviderState(")].join("\n");
    const globals = { crypto, path, ...helper, sameOrder: (a, b) => JSON.stringify(a) === JSON.stringify(b) };
    for (const name of ["resolveProviderIdForAuth", "loadAuthProfileStoreWithoutExternalProfiles", "saveAuthProfileStore", "setAuthProfileOrder"]) {
      check("actual_sdk_" + name, typeof sdk[name] === "function"); globals[name] = sdk[name];
    }
    const context = vm.createContext(globals);
    vm.runInContext(functions + "\nglobalThis.apply = applyLeaseAssignments; globalThis.clear = saveStrictLeaseOrder; globalThis.expire = typeof expireKnownLeaseOrders === 'function' ? expireKnownLeaseOrders : null;", context, { timeout: 1000 });
    const read = () => { sdk.clearRuntimeAuthProfileStoreSnapshots(); return sdk.loadAuthProfileStoreWithoutExternalProfiles(agent, { allowKeychainPrompt: false }); };
    const resolve = (store = read(), extra = {}) => sdk.resolveAuthProfileOrder({ cfg: {}, store, provider: "google", ...extra });
    const fingerprints = () => Object.fromEntries(Object.entries(read().profiles ?? {}).map(([id, credential]) => [id, digest(credential)]));
    const expectedProfiles = includeNew => Object.fromEntries([PROFILE, UNMANAGED, OTHER, ...(includeNew ? [NEW_UNMANAGED] : [])].map(id => [id, digest(CREDENTIALS[id])]));
    const profilesUnchanged = includeNew => digest(fingerprints()) === digest(expectedProfiles(includeNew));
    const { DatabaseSync } = await import("node:sqlite");
    const withDatabase = callback => {
      const stat = fs.lstatSync(databasePath);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== process.getuid() || (stat.mode & 0o077)) fail("sqlite_custody_invalid");
      const database = new DatabaseSync(databasePath);
      try { return callback(database); } finally { database.close(); }
    };
    const rawState = () => withDatabase(database => {
      const row = database.prepare("SELECT state_json FROM auth_profile_state WHERE state_key = 'primary'").get();
      return row ? JSON.parse(row.state_json) : {};
    });
    const denied = () => {
      const store = read(), raw = rawState();
      return Object.hasOwn(store.order ?? {}, "google") && Array.isArray(store.order.google) && store.order.google.length === 0
        && Object.hasOwn(raw.order ?? {}, "google") && Array.isArray(raw.order.google) && raw.order.google.length === 0
        && !store.lastGood?.google && !raw.lastGood?.google && resolve(store).length === 0;
    };
    const granted = () => {
      const store = read();
      return digest(store.order?.google) === digest([PROFILE]) && store.lastGood?.google === PROFILE && digest(resolve(store)) === digest([PROFILE]);
    };
    const otherUntouched = () => {
      const store = read();
      return digest(store.order?.anthropic) === digest([OTHER]) && store.lastGood?.anthropic === OTHER
        && digest(sdk.resolveAuthProfileOrder({ cfg: {}, store, provider: "anthropic" })) === digest([OTHER]);
    };
    const fencePath = path.join(state, "fences.private.json");
    const epochs = fs.existsSync(fencePath) ? new Map(Object.entries(JSON.parse(fs.readFileSync(fencePath, "utf8")))) : new Map();
    const configMode = { hostId: "isolated-main", schedulerMode: "enforce" };
    const apply = (document, now) => context.apply([agent], document, configMode, epochs, { providers: {} }, now);
    const persist = () => writePrivate(fencePath, Object.fromEntries(epochs));
    const seed = async () => {
      check("new_database_absent", !fs.existsSync(databasePath));
      sdk.saveAuthProfileStore({ version: 1, profiles: {} }, agent, { filterExternalAuthProfiles: false, syncExternalCli: false });
      for (const id of [PROFILE, UNMANAGED, OTHER]) check("upsert_" + id, await sdk.upsertAuthProfileWithLock({ agentDir: agent, profileId: id, credential: CREDENTIALS[id] }));
      const store = read();
      store.order = { google: [PROFILE, UNMANAGED], anthropic: [OTHER] };
      store.lastGood = { google: PROFILE, anthropic: OTHER };
      sdk.saveAuthProfileStore(store, agent, { filterExternalAuthProfiles: false, syncExternalCli: false });
      check("seed_all_credentials_exact", profilesUnchanged(false));
    };
    const tick = config.tick;

    if (phase === "original") {
      await seed();
      const empty = { ...read(), order: { ...read().order, google: [] } };
      check("original_resolver_in_memory_empty_order_denies", resolve(empty).length === 0);
      sdk.saveAuthProfileStore(empty, agent, { filterExternalAuthProfiles: false, syncExternalCli: false });
      report.originalEmptyOrderLost = !Object.hasOwn(read().order ?? {}, "google") && resolve().length === 2;
      check("original_persistence_bug_reproduced", report.originalEmptyOrderLost);
      await apply(control(7, tick + 1000), tick);
      check("original_real_sdk_grant_applied", granted());
      const expired = await apply(control(7, tick + 1000), tick + 1001);
      report.originalSameEpochExpiryBug = expired.staleAssignments === 1 && granted();
      check("original_same_epoch_bug_reproduced", report.originalSameEpochExpiryBug);
      check("original_unmanaged_credentials_unchanged", profilesUnchanged(false));
      report.observationComplete = true;
    } else if (phase === "seed") {
      await seed();
      check("legacy_empty_setter_still_clears_override", Boolean(await sdk.setAuthProfileOrder({ agentDir: agent, provider: "google", order: [] })) && !Object.hasOwn(read().order ?? {}, "google") && resolve().length === 2);
      const beforeInvalid = digest(rawState());
      for (const invalid of [undefined, [""], ["missing-profile"], [PROFILE], ""]) {
        let rejected = false;
        try { await sdk.setAuthProfileOrder({ agentDir: agent, provider: "google", order: invalid, explicitDeny: true }); }
        catch (error) { rejected = error.message === "Explicit auth deny requires an original empty array"; }
        check("explicit_deny_rejects_nonempty_or_nonarray_" + (invalid === undefined ? "undefined" : digest(invalid)), rejected && digest(rawState()) === beforeInvalid);
      }
      check("locked_explicit_deny_succeeded", Boolean(await sdk.setAuthProfileOrder({ agentDir: agent, provider: "google", order: [], explicitDeny: true })));
      check("sqlite_and_actual_resolver_deny", denied());
      check("deny_overrides_configured_and_preferred_fallback", resolve(read(), { cfg: { auth: { order: { google: [UNMANAGED] }, profiles: { [UNMANAGED]: { provider: "google", mode: "api_key" } } } }, preferredProfile: PROFILE }).length === 0);
      check("unmanaged_and_other_provider_untouched", profilesUnchanged(false) && otherUntouched());
      const withInvalid = read();
      withInvalid.order.invalid = ["nonexistent-profile"];
      withInvalid.order.invalidValues = [" "];
      sdk.saveAuthProfileStore(withInvalid, agent, { filterExternalAuthProfiles: false, syncExternalCli: false });
      check("pruned_invalid_lists_not_promoted_to_deny", !Object.hasOwn(read().order ?? {}, "invalid") && !Object.hasOwn(read().order ?? {}, "invalidvalues") && denied());
      await apply(control(7, tick + 1000), tick);
      check("valid_grant_uses_real_sdk", granted());
      check("original_grant_deadline_recorded", epochs.get(FENCE)?.grant?.expiresAt === tick + 1000);
      persist();
      report.seedComplete = true;
    } else if (phase === "reopen") {
      check("cold_deadline_and_grant_exact", epochs.get(FENCE)?.grant?.expiresAt === tick + 1000 && granted() && profilesUnchanged(false));
      await apply(control(7, tick + 1000), tick + 1001);
      check("same_epoch_expired_really_denies", denied() && epochs.get(FENCE)?.status === "EXPIRED");
      const staleStore = read();
      check("new_unmanaged_profile_added_with_real_sdk", await sdk.upsertAuthProfileWithLock({ agentDir: agent, profileId: NEW_UNMANAGED, credential: CREDENTIALS[NEW_UNMANAGED] }));
      check("unrelated_sdk_write_preserves_deny", denied() && profilesUnchanged(true));
      check("deny_from_stale_caller_preserves_new_unmanaged_profile", await context.clear(agent, "google", staleStore, null) && denied() && profilesUnchanged(true));
      await apply(control(7, tick + 1000), tick);
      check("clock_rollback_does_not_resurrect", denied());
      await apply(control(8, tick + 5000), tick + 2000);
      check("higher_epoch_restores_managed_grant", granted() && profilesUnchanged(true));
      const changed = await apply(control(8, tick + 9000), tick + 2001);
      check("same_epoch_deadline_extension_rejected", changed.staleAssignments === 1 && epochs.get(FENCE).grant.expiresAt === tick + 5000 && granted());
      const lower = await apply(control(7, tick + 1000), tick + 2002);
      check("lower_epoch_expired_message_cannot_revoke_current", lower.staleAssignments === 1 && granted());
      await context.expire([agent], configMode, epochs, tick + 5001);
      check("local_preflight_without_network_denies", denied());
      await apply(control(9, tick + 9000), tick + 6000);
      const legacy = { ...epochs.get(FENCE) }; delete legacy.grant; epochs.set(FENCE, legacy);
      await context.expire([agent], configMode, epochs, tick + 6001);
      check("legacy_grant_without_deadline_denies", denied());
      await apply(control(9, tick + 9000), tick + 6002);
      check("legacy_same_epoch_cannot_upgrade_authority", denied());
      await apply(control(10, tick + 10000), tick + 6003);
      check("new_epoch_after_legacy_can_authorize", granted());
      await apply(null, tick + 10001);
      check("missing_scope_cannot_hide_known_expiration", denied());
      check("all_unmanaged_credentials_and_other_order_unchanged", profilesUnchanged(true) && otherUntouched());
      persist();
      report.repairChecksPassed = true;
    } else if (phase === "final-reopen") {
      check("cold_tombstone_preserved", epochs.get(FENCE)?.status === "EXPIRED" && epochs.get(FENCE)?.grant?.expiresAt === tick + 10000);
      check("cold_sqlite_still_explicitly_denies", denied());
      await apply(control(10, tick + 10000), tick);
      check("cold_clock_rollback_and_replay_denied", denied());
      check("cold_all_unmanaged_credentials_unchanged", profilesUnchanged(true) && otherUntouched());
      report.coldRepairChecksPassed = true;
    } else if (phase === "write-failure") {
      await seed();
      await apply(control(11, tick + 60000), tick);
      check("failure_fixture_has_real_grant", granted());
      persist();
      const before = digest(rawState());
      withDatabase(database => database.exec("CREATE TRIGGER authbus_fixture_reject_state_insert BEFORE INSERT ON auth_profile_state BEGIN SELECT RAISE(ABORT, 'authbus_fixture_state_write_rejected'); END;"));
      let failure = null;
      try { await apply(control(12, 0, true), tick + 1); }
      catch (error) { failure = error; }
      check("real_sqlite_revocation_failure_propagated", failure?.message === "AuthBus strict lease transaction failed for agent main");
      check("failed_transaction_did_not_half_clear_last_good", digest(rawState()) === before);
      check("failed_revoke_not_acknowledged_or_accepted", epochs.get(FENCE)?.epoch === 11 && epochs.get(FENCE)?.status === "ASSIGNED");
      check("failed_revoke_does_not_delete_unmanaged", profilesUnchanged(false) && otherUntouched());
      report.revocationFailureResolverDenied = denied();
      report.revocationFailureResolvedCount = resolve().length;
      report.revocationFailureSelectedOldGrant = resolve().includes(PROFILE);
      report.fixtureAbortTriggerPersisted = true;
    } else if (phase === "write-failure-reopen") {
      check("failed_revoke_cold_fence_remains_uncommitted", epochs.get(FENCE)?.epoch === 11 && profilesUnchanged(false));
      report.coldFailedRevocationResolverDenied = denied();
      report.coldFailedRevocationSelectedOldGrant = resolve().includes(PROFILE);
      withDatabase(database => database.exec("DROP TRIGGER authbus_fixture_reject_state_insert;"));
      await apply(control(12, 0, true), tick + 2);
      check("fault_removed_actual_revocation_denies", denied() && epochs.get(FENCE)?.epoch === 12);
      check("recovery_keeps_unmanaged_credentials", profilesUnchanged(false) && otherUntouched());
      persist();
      report.faultRemovedAndRecovered = true;
    } else fail("unknown_worker_phase");
    check("installed_sdk_still_unchanged", verifyInstalledSdkUnchanged(config.openclawRoot));
    check("production_plugin_still_unchanged", sha256(fs.readFileSync(config.originalSource)) === ORIGINAL_PLUGIN_SHA);
  } catch (error) {
    report.errorCode = error.diagnosticCode ?? "unexpected_regression_failure";
    report.errorSha256 = sha256(String(error.message));
  } finally { hook?.deregister(); }
  return report;
}

async function main() {
  if (process.argv[2] === "--worker") {
    process.stdout.write(JSON.stringify(await worker(JSON.parse(fs.readFileSync(process.argv[3], "utf8")), process.argv[4])) + "\n");
    return;
  }
  const names = { "--work-dir": "root", "--openclaw-root": "openclawRoot", "--original-source": "originalSource", "--deadline-candidate": "deadlineCandidate", "--lease-helper": "leaseHelper" };
  const config = { tick: Date.now() };
  for (let index = 2; index < process.argv.length; index += 2) {
    if (!names[process.argv[index]] || !process.argv[index + 1] || !path.isAbsolute(process.argv[index + 1])) fail("absolute_cli_arguments_required");
    config[names[process.argv[index]]] = path.resolve(process.argv[index + 1]);
  }
  if (Object.values(names).some(name => !config[name])) fail("missing_cli_arguments");
  if (sha256(fs.readFileSync(config.originalSource)) !== ORIGINAL_PLUGIN_SHA || sha256(fs.readFileSync(config.deadlineCandidate)) !== DEADLINE_PLUGIN_SHA) fail("plugin_source_binding_changed");
  if (sha256(fs.readFileSync(config.leaseHelper)) !== "24192dc82ddd682e836ea2df717b065b76773c0a1f4b0905f6764e4d498d77e7") fail("lease_helper_source_binding_changed");
  if (!verifyInstalledSdkUnchanged(config.openclawRoot)) fail("installed_sdk_source_binding_changed");
  fs.mkdirSync(config.root, { mode: 0o700 }); // New fixture; never overwrite a prior run.
  ownedDirectory(config.root);
  config.generatedPlugin = path.join(config.root, "plugin-atomic-deny-candidate.private.js");
  const candidate = patchDeadlinePlugin(fs.readFileSync(config.deadlineCandidate, "utf8"));
  config.generatedPluginSha256 = sha256(candidate);
  writePrivate(config.generatedPlugin, candidate);
  const configPath = path.join(config.root, "driver.private.json");
  writePrivate(configPath, config);
  const report = { schema: "authbus-explicit-deny-actual-sdk-v1", ok: false, productionMutation: false,
    realCredentials: false, providerNetworkAllowed: false, productionCoordinatorReplacement: false,
    hardPerRequestDeadlineQualified: false, sourcePluginSha256: ORIGINAL_PLUGIN_SHA,
    pluginCandidateSha256: config.generatedPluginSha256, sdkSourceBindings: SDK_PATCHES.map(({ relative, originalSha256 }) => ({ relative, originalSha256 })), phases: [] };
  for (const phase of ["original", "seed", "reopen", "final-reopen", "write-failure", "write-failure-reopen"]) {
    const child = spawnSync(process.execPath, [process.argv[1], "--worker", configPath, phase], { encoding: "utf8", timeout: 45000, maxBuffer: 1024 * 1024 });
    writePrivate(path.join(config.root, phase + ".stdout.log"), child.stdout ?? "");
    writePrivate(path.join(config.root, phase + ".stderr.log"), child.stderr ?? "");
    if (child.status !== 0) { report.phases.push({ phase, processExit: child.status, errorCode: child.error?.code ?? "worker_failed" }); break; }
    let result;
    try { result = JSON.parse(child.stdout); } catch { report.phases.push({ phase, errorCode: "worker_output_not_json" }); break; }
    report.phases.push(result);
    if (result.errorCode) break;
  }
  const get = phase => report.phases.find(item => item.phase === phase);
  report.installedSdkUnchanged = verifyInstalledSdkUnchanged(config.openclawRoot);
  report.productionPluginUnchanged = sha256(fs.readFileSync(config.originalSource)) === ORIGINAL_PLUGIN_SHA;
  report.explicitDenyAndLeaseRepairPassed = get("reopen")?.repairChecksPassed === true && get("final-reopen")?.coldRepairChecksPassed === true;
  report.revocationFailureClosed = get("write-failure")?.revocationFailureResolverDenied === true && get("write-failure-reopen")?.coldFailedRevocationResolverDenied === true;
  report.qualificationChecks = [
    { case: "explicit_deny_and_lease_repair", passed: report.explicitDenyAndLeaseRepairPassed },
    { case: "revocation_write_failure_closes_actual_resolver", passed: report.revocationFailureClosed },
  ];
  report.ok = report.phases.length === 6 && !report.phases.some(item => item.errorCode) && report.installedSdkUnchanged
    && report.productionPluginUnchanged && report.explicitDenyAndLeaseRepairPassed && report.revocationFailureClosed;
  if (report.explicitDenyAndLeaseRepairPassed && get("write-failure-reopen")?.faultRemovedAndRecovered === true && !report.revocationFailureClosed) {
    report.remainingBlocker = "failed_revocation_does_not_close_gateway_admission";
  }
  const evidence = JSON.stringify(report);
  const syntheticSecrets = Object.values(CREDENTIALS).map(item => item.key);
  const diagnostics = report.phases.map(item => fs.readFileSync(path.join(config.root, item.phase + ".stdout.log"), "utf8") + fs.readFileSync(path.join(config.root, item.phase + ".stderr.log"), "utf8")).join("\n");
  report.diagnosticsRedacted = syntheticSecrets.every(value => !evidence.includes(value) && !diagnostics.includes(value));
  if (!report.diagnosticsRedacted) { report.ok = false; report.remainingBlocker = "diagnostics_redaction_failed"; }
  writePrivate(path.join(config.root, "public.json"), report);
  process.stdout.write(JSON.stringify(report) + "\n");
  if (!report.ok) process.exitCode = 3;
}

try { await main(); }
catch (error) {
  process.stdout.write(JSON.stringify({ ok: false, errorCode: error.diagnosticCode ?? "harness_setup_failure", errorSha256: sha256(String(error.message)) }) + "\n");
  process.exitCode = 2;
}
