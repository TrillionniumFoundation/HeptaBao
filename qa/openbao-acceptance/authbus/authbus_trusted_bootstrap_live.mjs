#!/usr/bin/env node
/**
 * Run on main only with a newly provisioned isolated native HeptaBao TLS/KV2
 * fixture and fresh issuer/reader AppRoles. No actual provider credential is
 * used. Node child processes import the exact SDK baseline through the frozen
 * dispatch overlays and perform actual SQLite transactions.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import net from "node:net";
import childProcess from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";
import { performance } from "node:perf_hooks";
import { digest } from "./authbus_admission_authority_candidate.mjs";
import { TrustedAdmissionAuthority, applyFromTrustedControl } from "./authbus_trusted_admission_candidate.mjs";
import { TrustedBaoControlSource, TrustedBaoCoordinator, readCustodiedFile } from "./authbus_trusted_control_candidate.mjs";
import { DispatchAdmissionRegistry } from "./authbus_dispatch_registry_candidate.mjs";
import { installSdkCandidate, verifyInstalledSdkUnchanged } from "./authbus_sdk_explicit_deny_candidate.mjs";
import { installDispatchSdkCandidate, verifyDispatchSdkUnchanged } from "./authbus_dispatch_sdk_candidate.mjs";

const fail = code => { throw Object.assign(new Error(code), { diagnosticCode: code }); };
const sha256 = value => crypto.createHash("sha256").update(value).digest("hex");
const CREDENTIAL = { type: "api_key", provider: "openai", key: "synthetic-trusted-bootstrap-r4-only" };
const here = path.dirname(fileURLToPath(import.meta.url));
let emergencyChildCleanup = null;
const SOURCE_FILES = ["authbus_admission_authority_candidate.mjs", "authbus_admission_registry_candidate.mjs",
  "authbus_sdk_admission_candidate.mjs", "authbus_sdk_explicit_deny_candidate.mjs", "authbus_dispatch_registry_candidate.mjs",
  "authbus_dispatch_sdk_candidate.mjs", "authbus_trusted_control_candidate.mjs", "authbus_trusted_admission_candidate.mjs", "authbus_trusted_bootstrap_live.mjs"];
const args = {};
for (let i = 2; i < process.argv.length; i += 2) {
  if (!["--fixture-config", "--work-dir", "--openclaw-root", "--child-input"].includes(process.argv[i]) || !path.isAbsolute(process.argv[i + 1] ?? "")) fail("trusted_bootstrap_absolute_cli_required");
  args[process.argv[i]] = path.resolve(process.argv[i + 1]);
}
process.umask(0o077);
const delay = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));
const safeError = error => ({ errorCode: error.diagnosticCode ?? "trusted_bootstrap_unclassified_failure", errorSha256: sha256(String(error.message)) });
const denied = async (callback, prefix) => {
  try { await callback(); } catch (error) { if (String(error.diagnosticCode ?? "").startsWith(prefix)) return true; throw error; }
  return false;
};
function childConfig(input) {
  const config = JSON.parse(readCustodiedFile(input.fixtureConfig).toString("utf8"));
  if (config.provider !== "openai") fail("trusted_bootstrap_fixture_provider_must_be_openai");
  const scope = { hostId: config.hostId, agentId: config.agentId, agentDir: path.join(input.workDir, "state/agents/main/agent"), provider: config.provider };
  return { config, scope, binding: { scope, model: config.model, profileId: config.profileId, credentialDigest: digest(CREDENTIAL) } };
}

async function runChild(inputFile) {
  if (!process.send) fail("trusted_bootstrap_child_ipc_required");
  const input = JSON.parse(readCustodiedFile(inputFile).toString("utf8"));
  const { config, scope, binding } = childConfig(input);
  const state = path.join(input.workDir, "state"), agent = scope.agentDir, cfgPath = path.join(state, "openclaw.json");
  const checks = [], check = (name, passed) => { checks.push({ case: name, passed: Boolean(passed) }); if (!passed) fail(name); };
  const rawWall = Date.now, wallOffsetMs = input.wallOffsetMs ?? 0;
  Date.now = () => rawWall() + wallOffsetMs;
  process.env.OPENCLAW_STATE_DIR = state;
  process.env.OPENCLAW_CONFIG_PATH = cfgPath;
  process.env.OPENCLAW_HOME = path.join(state, "home");
  process.env.OPENCLAW_OAUTH_DIR = path.join(state, "credentials");
  for (const name of ["GOOGLE_API_KEY", "GEMINI_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "OPENCLAW_GATEWAY_TOKEN"]) delete process.env[name];
  if (process.env.OPENCLAW_AUTH_STORE_READONLY === "1") fail("trusted_bootstrap_inherited_readonly_store");
  const endpoint = new URL(config.address), originalConnect = net.Socket.prototype.connect;
  let forbiddenNetwork = 0;
  net.Socket.prototype.connect = function (...values) {
    const first = Array.isArray(values[0]) ? values[0][0] : values[0];
    const options = typeof first === "object" && first !== null ? first : { port: first, host: values[1] };
    const host = options.host ?? options.hostname ?? "localhost";
    if (Number(options.port) !== Number(endpoint.port || 443) || ![endpoint.hostname, "127.0.0.1", "::1", "localhost"].includes(host)) {
      forbiddenNetwork += 1; fail("trusted_bootstrap_external_network_forbidden");
    }
    return originalConnect.apply(this, values);
  };
  for (const method of ["spawn", "spawnSync", "exec", "execSync", "execFile", "execFileSync", "fork"]) childProcess[method] = () => fail("trusted_bootstrap_child_process_forbidden");
  syncBuiltinESMExports();
  const source = new TrustedBaoControlSource(config);
  let cleanupPromise = null;
  emergencyChildCleanup = () => cleanupPromise ??= (async () => {
    try { return { ...(await source.close()), sourceCounts: source.publicCounts() }; }
    catch (error) { return { revoked: false, coldDenied: false, ...safeError(error), sourceCounts: source.publicCounts() }; }
  })();
  const authority = new TrustedAdmissionAuthority({ directory: path.join(state, "admission"), scope, controlSource: source });
  const cfg = JSON.parse(readCustodiedFile(cfgPath).toString("utf8"));
  let sdk;
  const read = () => { sdk.clearRuntimeAuthProfileStoreSnapshots(); return sdk.loadAuthProfileStoreWithoutExternalProfiles(agent, { allowKeychainPrompt: false }); };
  const registry = new DispatchAdmissionRegistry({ authorities: [authority], resolveDefaultAgentDir: value => sdk.resolveDefaultAgentDir(value),
    resolveProviderIdForAuth: (value, options) => sdk.resolveProviderIdForAuth(value, options), readStore: directory => {
      if (path.resolve(directory) !== agent) fail("trusted_bootstrap_store_scope_escape"); return read();
    } });
  const uninstall = registry.install(), overlayReport = {};
  const baseHook = installSdkCandidate(input.openclawRoot, overlayReport), dispatchHook = installDispatchSdkCandidate(input.openclawRoot, overlayReport);
  sdk = await import(pathToFileURL(path.join(input.openclawRoot, "dist/plugin-sdk/agent-runtime.js")).href);
  await import(pathToFileURL(path.join(input.openclawRoot, "dist/stream-BcRkg2P0.js")).href);
  const databasePath = path.join(agent, "openclaw-agent.sqlite");
  const faultProfileId = config.profileId + ":fault-target";
  if (!fs.existsSync(databasePath)) {
    sdk.saveAuthProfileStore({ version: 1, profiles: {} }, agent, { filterExternalAuthProfiles: false, syncExternalCli: false });
    check("actual_sdk_fixture_credential_seeded", Boolean(await sdk.upsertAuthProfileWithLock({ agentDir: agent, profileId: config.profileId, credential: CREDENTIAL })));
    check("actual_sdk_distinct_fault_target_seeded", Boolean(await sdk.upsertAuthProfileWithLock({ agentDir: agent, profileId: faultProfileId, credential: CREDENTIAL })));
  }
  check("actual_sqlite_credential_digest_matches", digest(read().profiles[config.profileId]) === binding.credentialDigest);
  check("actual_sqlite_fault_target_digest_matches", digest(read().profiles[faultProfileId]) === binding.credentialDigest);
  check("cold_instance_initially_closed", !authority.inspect().allowed);
  const record = fs.existsSync(authority.filename) ? JSON.parse(fs.readFileSync(authority.filename, "utf8")) : null;
  let storeTouches = 0;
  const callbacks = {
    updateStore: () => { storeTouches += 1; const store = read(); store.order = { openai: [config.profileId] }; store.lastGood = { openai: config.profileId };
      sdk.saveAuthProfileStore(store, agent, { filterExternalAuthProfiles: false, syncExternalCli: false }); return true; },
    verifyStore: grant => read().order?.openai?.[0] === config.profileId && digest(read().profiles[config.profileId]) === grant.digest,
  };
  if (record?.grant) {
    const before = storeTouches;
    check("old_epoch_verify_true_cannot_cold_reconcile", await denied(() => authority.reconcileCommitted(record.grant, { verifyStore: () => true }), "trusted_control_cold_higher_epoch_required"));
    check("old_epoch_forged_proof_cannot_cold_apply", await denied(() => authority.apply(record.grant, { ...callbacks, verifyStore: () => true, controlProof: {} }), "trusted_control_fresh_proof_required"));
    check("old_epoch_cold_attempts_never_touch_store", storeTouches === before);
    check("old_bootstrap_id_fails_actual_fresh_tls_read", await denied(() => source.readGrant(scope), "trusted_control_bootstrap_assignment_mismatch"));
    if (wallOffsetMs < 0) check("raw_wall_is_behind_persisted_observation", Date.now() < record.observedAt);
  }
  const bootstrap = source.bootstrapRequest(scope, binding);
  process.send({ type: "ready", request: bootstrap, epochFloor: record?.grant?.epoch ?? -1, pid: process.pid, rawWallOffsetMs: wallOffsetMs });
  let running = false;
  let faultDiagnostics = null;
  const onMessage = async message => {
    if (running || !Number.isSafeInteger(message.id)) fail("trusted_bootstrap_child_command_overlap");
    running = true;
    try {
      let result;
      if (message.command === "apply") {
        const fresh = await applyFromTrustedControl({ authority, controlSource: source, ...callbacks });
        check("authenticated_higher_epoch_actual_store_committed_" + fresh.grant.epoch, authority.inspect().allowed);
        const model = { id: config.model, provider: config.provider, api: "openai-completions" };
        const auth = await sdk.getApiKeyForModel({ model, cfg, agentDir: agent, profileId: config.profileId });
        check("actual_sdk_resolver_accepts_trusted_scope_" + fresh.grant.epoch, auth.profileId === config.profileId && auth.apiKey === CREDENTIAL.key);
        check("all_exact_sdk_overlays_loaded_" + fresh.grant.epoch, overlayReport.sdkCandidateModules.every(item => item.loaded) && overlayReport.dispatchSdkModules.every(item => item.loaded));
        const cold = new TrustedAdmissionAuthority({ directory: path.join(state, "admission"), scope, controlSource: source });
        const same = await source.readGrant(scope), before = storeTouches;
        check("even_authenticated_same_epoch_is_denied_to_cold_authority_" + fresh.grant.epoch,
          await denied(() => cold.apply(same.grant, { ...callbacks, controlProof: same.proof }), "trusted_control_cold_higher_epoch_required"));
        check("same_epoch_cold_proof_never_touches_store_" + fresh.grant.epoch, storeTouches === before && !cold.inspect().allowed && authority.inspect().allowed);
        const otherScope = { ...scope, agentId: "unconfigured-other-agent" }, foreign = new TrustedAdmissionAuthority({ directory: path.join(state, "admission"), scope: otherScope, controlSource: source });
        const wrongScope = await source.readGrant(scope);
        check("proof_cannot_authorize_other_scope_" + fresh.grant.epoch,
          await denied(() => foreign.apply(wrongScope.grant, { ...callbacks, controlProof: wrongScope.proof }), "trusted_control_proof_binding_mismatch"));
        check("reader_role_is_read_only_" + fresh.grant.epoch, await source.probeWriteDenial());
        check("reader_approle_token_renewed_" + fresh.grant.epoch, await source.renew());
        const persisted = JSON.parse(fs.readFileSync(authority.filename, "utf8"));
        check("trusted_provenance_durably_bound_" + fresh.grant.epoch, persisted.trustedControl?.bootId === bootstrap.bootId && persisted.trustedControl?.refreshOwnerBound === true);
        result = { grant: fresh.grant, public: fresh.public, rawWallBehindLease: Date.now() < fresh.grant.expiresAt, phase: persisted.phase };
      } else if (message.command === "fail-store") {
        const { DatabaseSync } = await import("node:sqlite");
        const database = new DatabaseSync(databasePath), before = digest(read());
        faultDiagnostics = { beforeStoreDigest: before, afterStoreDigest: null, transactionThrew: false,
          updateCalls: 0, verifyCalls: 0, sdkSaved: null, errorCode: null, errorSha256: null, targetWasPreviouslySelected: null };
        database.exec("CREATE TRIGGER trusted_bootstrap_abort BEFORE INSERT ON auth_profile_state BEGIN SELECT RAISE(ABORT,'synthetic_trusted_bootstrap_abort'); END");
        let failed = false;
        try {
          const fresh = await source.readGrant(scope);
          faultDiagnostics.targetWasPreviouslySelected = read().order?.openai?.[0] === fresh.grant.profileId;
          check("fault_grant_requires_a_real_different_sdk_order", fresh.grant.profileId === faultProfileId && !faultDiagnostics.targetWasPreviouslySelected);
          await authority.apply(fresh.grant, {
            updateStore: async () => {
              storeTouches += 1; faultDiagnostics.updateCalls += 1;
              const saved = await sdk.setAuthProfileOrder({ agentDir: agent, provider: "openai", order: [fresh.grant.profileId] });
              faultDiagnostics.sdkSaved = Boolean(saved);
              if (!saved) fail("trusted_bootstrap_injected_sdk_transaction_failed");
              return saved;
            },
            verifyStore: grant => { faultDiagnostics.verifyCalls += 1; return read().order?.openai?.[0] === grant.profileId && digest(read().profiles[grant.profileId]) === grant.digest; },
            controlProof: fresh.proof,
          });
        } catch (error) {
          failed = true; faultDiagnostics.transactionThrew = true;
          faultDiagnostics.errorCode = error.diagnosticCode ?? error.code ?? "sdk_transaction_exception";
          faultDiagnostics.errorSha256 = sha256(String(error.message));
        }
        finally { database.exec("DROP TRIGGER trusted_bootstrap_abort"); database.close(); }
        const persisted = JSON.parse(fs.readFileSync(authority.filename, "utf8"));
        faultDiagnostics.afterStoreDigest = digest(read());
        faultDiagnostics.persistedPhase = persisted.phase; faultDiagnostics.persistedEpoch = persisted.grant.epoch;
        check("actual_sdk_transaction_failure_was_observed", failed && faultDiagnostics.updateCalls === 1);
        check("actual_sqlite_failure_preserves_previous_store", faultDiagnostics.afterStoreDigest === before);
        check("trusted_higher_epoch_failure_is_durable_pending", persisted.phase === "pending" && !authority.inspect().allowed);
        result = { epoch: persisted.grant.epoch, phase: persisted.phase, faultDiagnostics };
      } else if (message.command === "expire") {
        const fresh = await source.readGrant(scope);
        const beforeDeadline = authority.activation?.deadlineMono;
        await authority.reconcileCommitted(fresh.grant, { verifyStore: callbacks.verifyStore, controlProof: fresh.proof });
        check("warm_fresh_get_does_not_extend_monotonic_deadline", authority.activation.deadlineMono <= beforeDeadline);
        await delay(Math.max(0, authority.activation.deadlineMono - performance.now()) + 25);
        check("server_bound_monotonic_lease_naturally_expires_despite_raw_wall_rollback", !authority.inspect().allowed);
        check("natural_expiry_is_durably_closed", JSON.parse(fs.readFileSync(authority.filename, "utf8")).phase === "expired");
        check("expired_control_proof_is_not_minted", await denied(() => source.readGrant(scope), "trusted_control_lease_expired"));
        result = { expired: true };
      } else if (message.command === "shutdown") {
        const cleanup = await emergencyChildCleanup();
        check("reader_token_revoked_and_cold_denied", cleanup.revoked && cleanup.coldDenied);
        check("provider_egress_attempts_zero", forbiddenNetwork === 0);
        check("all_actual_sdk_source_unchanged", verifyInstalledSdkUnchanged(input.openclawRoot) && verifyDispatchSdkUnchanged(input.openclawRoot));
        baseHook.deregister(); dispatchHook.deregister(); uninstall();
        result = { checks, sourceCounts: source.publicCounts(), cleanup, actualSdk: true, actualSqlite: true, actualProviderRefresh: false,
          originalSdkSourceUnchanged: true, actualOverlayBindings: { sdk: overlayReport.sdkCandidateModules, dispatch: overlayReport.dispatchSdkModules } };
        process.send({ type: "result", id: message.id, result }, () => { process.disconnect(); process.exit(0); });
        return;
      } else fail("trusted_bootstrap_unknown_child_command");
      process.send({ type: "result", id: message.id, result });
    } catch (error) {
      const cleanup = await emergencyChildCleanup();
      process.send({ type: "failed", id: message.id, ...safeError(error), checks, faultDiagnostics, cleanup }, () => {
        process.disconnect(); process.exit(1);
      });
    } finally { running = false; }
  };
  process.on("message", message => { onMessage(message).catch(error => { process.send({ type: "fatal", ...safeError(error) }); process.exitCode = 1; }); });
}

async function runParent() {
  if (!args["--fixture-config"] || !args["--work-dir"] || !args["--openclaw-root"]) fail("trusted_bootstrap_missing_cli_argument");
  const input = { fixtureConfig: args["--fixture-config"], workDir: args["--work-dir"], openclawRoot: args["--openclaw-root"] };
  const { config, scope, binding } = childConfig(input), root = input.workDir;
  fs.mkdirSync(root, { mode: 0o700 });
  const state = path.join(root, "state");
  for (const relative of ["state", "state/agents", "state/agents/main", "state/agents/main/agent", "state/admission", "state/home", "state/credentials", "private"]) fs.mkdirSync(path.join(root, relative), { mode: 0o700 });
  fs.writeFileSync(path.join(state, "openclaw.json"), JSON.stringify({ agents: { list: [{ id: "main", default: true, agentDir: scope.agentDir }] } }) + "\n", { mode: 0o600 });
  const report = { schema: "authbus-trusted-bootstrap-actual-sdk-r4", ok: false, checks: [], processes: [],
    actualTlsAppRoleKv2: false, actualCoordinatorCasIssuance: false, actualColdProcess: false, actualSdk: false, actualSqlite: false,
    coldSameEpochDenied: false, strictlyHigherTrustedBootstrapQualified: false, refreshLeaseControlOwnershipQualified: false,
    actualOAuthProviderRefreshQualified: false, productionGatewayBootstrapQualified: false, allProductDispatchCoverageQualified: false,
    productionCutover: false, productionMutation: false, j3160Contacted: false, syntheticCredentials: true,
    frozenR3AuthoritySha256: sha256(fs.readFileSync(path.join(here, "authbus_admission_authority_candidate.mjs"))),
    candidateSourceBindings: SOURCE_FILES.map(relative => ({ relative, sha256: sha256(fs.readFileSync(path.join(here, relative))) })) };
  const check = (name, passed) => { report.checks.push({ case: name, passed: Boolean(passed) }); if (!passed) fail(name); };
  const coordinator = new TrustedBaoCoordinator(config, { bindings: [binding, { ...binding, profileId: config.profileId + ":fault-target" }] });
  const children = [], results = [];
  const emergencyCleanups = [];
  let commandId = 0;
  const launch = async (label, wallOffsetMs = 0) => {
    const inputFile = path.join(root, "private", label + ".json");
    fs.writeFileSync(inputFile, JSON.stringify({ ...input, wallOffsetMs }) + "\n", { mode: 0o600 });
    const child = childProcess.fork(fileURLToPath(import.meta.url), ["--child-input", inputFile], { stdio: ["ignore", "pipe", "pipe", "ipc"], env: { ...process.env } });
    children.push(child);
    let outputBytes = 0;
    const outputHash = crypto.createHash("sha256");
    for (const stream of [child.stdout, child.stderr]) stream.on("data", chunk => { outputBytes += chunk.length; outputHash.update(chunk); if (outputBytes > 65536) child.kill("SIGKILL"); });
    const pending = new Map(); let readyResolve, readyReject;
    const ready = new Promise((resolve, reject) => { readyResolve = resolve; readyReject = reject; });
    const timer = setTimeout(() => { readyReject(Object.assign(new Error("trusted_bootstrap_child_start_timeout"), { diagnosticCode: "trusted_bootstrap_child_start_timeout" })); child.kill("SIGKILL"); }, 30000);
    const exit = new Promise(resolve => child.once("exit", (code, signal) => {
      clearTimeout(timer);
      const error = Object.assign(new Error("trusted_bootstrap_child_exited"), { diagnosticCode: "trusted_bootstrap_child_exited" });
      readyReject(error); for (const waiter of pending.values()) waiter.reject(error);
      resolve({ code, signal, outputBytes, outputSha256: outputHash.digest("hex") });
    }));
    child.on("message", message => {
      if (message.type === "ready") { clearTimeout(timer); readyResolve(message); return; }
      if (message.type === "fatal") {
        report.failedChild = { label, ...message }; if (message.cleanup) emergencyCleanups.push(message.cleanup);
        readyReject(Object.assign(new Error(message.errorCode), { diagnosticCode: message.errorCode })); return;
      }
      const waiter = pending.get(message.id); if (!waiter) return; pending.delete(message.id);
      if (message.type === "result") waiter.resolve(message.result);
      else {
        report.failedChild = { label, ...message }; if (message.cleanup) emergencyCleanups.push(message.cleanup);
        waiter.reject(Object.assign(new Error(message.errorCode), { diagnosticCode: message.errorCode }));
      }
    });
    const boot = await ready;
    const send = async command => {
      const id = ++commandId;
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => { pending.delete(id); reject(Object.assign(new Error("trusted_bootstrap_child_command_timeout"), { diagnosticCode: "trusted_bootstrap_child_command_timeout" })); }, 35000);
        pending.set(id, { resolve: value => { clearTimeout(timer); resolve(value); }, reject: error => { clearTimeout(timer); reject(error); } });
        child.send({ id, command });
      });
    };
    return { label, child, boot, send, exit };
  };
  const stop = async worker => {
    const result = await worker.send("shutdown"), exit = await worker.exit;
    check(worker.label + "_independent_process_exited_cleanly", exit.code === 0 && exit.signal === null);
    report.processes.push({ label: worker.label, pid: worker.boot.pid, bootId: worker.boot.request.bootId, rawWallOffsetMs: worker.boot.rawWallOffsetMs,
      epochFloor: worker.boot.epochFloor, result, exit });
    results.push(result);
  };
  const waitOwnerExpiry = async grant => {
    const duration = Math.max(0, grant.expiresAt - Date.now() + 1100);
    if (duration > (config.maxLeaseMs ?? 30000) + 3000) fail("trusted_bootstrap_fixture_server_clock_skew");
    await delay(duration);
  };
  try {
    check("exact_frozen_r3_authority_included", report.frozenR3AuthoritySha256 === "a22974a765e47a9c350b2f2e46bea1f06401118cdecdb757ed1521260b9ac85b");
    const first = await launch("first");
    check("new_isolated_authority_has_no_persisted_epoch", first.boot.epochFloor === -1);
    const firstIssued = await coordinator.issue(first.boot.request, { leaseMs: config.leaseMs ?? 5000, epochFloor: first.boot.epochFloor });
    const firstApplied = await first.send("apply");
    check("actual_first_issuance_and_sdk_grant_match", digest(firstIssued.grant) === digest(firstApplied.grant));
    check("active_refresh_owner_cannot_be_preempted", await denied(() => coordinator.issue({ ...first.boot.request, bootId: crypto.randomUUID() }, { leaseMs: config.leaseMs ?? 5000, epochFloor: firstIssued.grant.epoch }), "trusted_control_refresh_owner_busy"));
    check("coordinator_cannot_issue_outside_pinned_scope", await denied(() => coordinator.issue({ ...first.boot.request, scope: { ...scope, hostId: "unauthorized-host" } }), "trusted_control_issuer_scope_not_authorized"));
    await stop(first);
    const cold = await launch("cold-wall-rollback", -60000);
    check("actual_second_process_has_distinct_bootstrap_id", cold.boot.pid !== first.boot.pid && cold.boot.request.bootId !== first.boot.request.bootId);
    check("actual_cold_floor_matches_old_grant", cold.boot.epochFloor === firstIssued.grant.epoch);
    await waitOwnerExpiry(firstIssued.grant);
    const coldIssued = await coordinator.issue(cold.boot.request, { leaseMs: config.leaseMs ?? 5000, epochFloor: cold.boot.epochFloor });
    const coldApplied = await cold.send("apply");
    check("only_actual_strictly_higher_cas_issuance_reopens_cold_process", coldIssued.grant.epoch > firstIssued.grant.epoch && digest(coldIssued.grant) === digest(coldApplied.grant));
    const failedIssued = await coordinator.issue({ ...cold.boot.request, profileId: config.profileId + ":fault-target" }, { leaseMs: config.leaseMs ?? 5000, epochFloor: coldIssued.grant.epoch });
    const failed = await cold.send("fail-store");
    report.actualSqliteFault = failed.faultDiagnostics;
    check("actual_failed_store_new_epoch_persisted_closed", failed.epoch === failedIssued.grant.epoch && failed.phase === "pending");
    await stop(cold);
    const recovery = await launch("pending-recovery", -60000);
    check("actual_third_process_reads_pending_epoch_floor", recovery.boot.pid !== cold.boot.pid && recovery.boot.epochFloor === failedIssued.grant.epoch);
    await waitOwnerExpiry(failedIssued.grant);
    const recoveryIssued = await coordinator.issue(recovery.boot.request, { leaseMs: config.leaseMs ?? 5000, epochFloor: recovery.boot.epochFloor });
    const recovered = await recovery.send("apply");
    check("actual_newer_trusted_issuance_recovers_pending_store", recovered.grant.epoch > failedIssued.grant.epoch && digest(recoveryIssued.grant) === digest(recovered.grant));
    await recovery.send("expire");
    await stop(recovery);
    check("issuer_approle_token_renewed", await coordinator.renew());
    report.actualTlsAppRoleKv2 = true; report.actualCoordinatorCasIssuance = true; report.actualColdProcess = true;
    report.actualSdk = results.every(item => item.actualSdk); report.actualSqlite = results.every(item => item.actualSqlite);
    report.coldSameEpochDenied = true; report.strictlyHigherTrustedBootstrapQualified = true; report.refreshLeaseControlOwnershipQualified = true;
    report.remainingBlockers = ["actual_gateway_service_bootstrap_not_installed", "actual_sdk_oauth_refresh_io_not_guarded_by_refresh_owner",
      "multi_host_coordinator_cas_races_not_executed_here", "actual_provider_credentials_not_used_in_this_r4_fixture",
      "non_llm_and_derived_credential_dispatch_not_qualified", "production_cutover_not_performed"];
    report.ok = true;
  } catch (error) { report.ok = false; Object.assign(report, safeError(error)); }
  finally {
    for (const child of children) if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
    try { report.issuerCleanup = await coordinator.close(); } catch (error) { report.ok = false; report.cleanupError = safeError(error); }
    report.issuerCounts = coordinator.publicCounts();
    report.allGracefulReaderTokensRevoked = results.length === 3 && results.every(item => item.cleanup.revoked && item.cleanup.coldDenied);
    report.emergencyReaderCleanups = emergencyCleanups;
    report.allSpawnedReaderTokensRevoked = results.length + emergencyCleanups.length === children.length &&
      results.every(item => item.cleanup.revoked && item.cleanup.coldDenied) && emergencyCleanups.every(item => item.revoked && item.coldDenied || item.sourceCounts?.logins === 0);
    report.allIssuedFixtureBindingsDestroyed = false;
    report.fixtureCleanupOwnedByOuterController = true;
    report.candidateSourceUnchanged = SOURCE_FILES.every((relative, index) => sha256(fs.readFileSync(path.join(here, relative))) === report.candidateSourceBindings[index].sha256);
    if (!report.candidateSourceUnchanged) report.ok = false;
    const text = JSON.stringify(report, null, 2) + "\n";
    if (text.includes(CREDENTIAL.key)) fail("trusted_bootstrap_diagnostic_secret_leak");
    fs.writeFileSync(path.join(root, "public.json"), text, { mode: 0o600 });
    process.stdout.write(JSON.stringify({ ok: report.ok, checks: report.checks.length, processCount: report.processes.length,
      coldProcessQualified: report.actualColdProcess, strictlyHigherTrustedBootstrapQualified: report.strictlyHigherTrustedBootstrapQualified,
      actualOAuthProviderRefreshQualified: false, publicReceipt: path.join(root, "public.json"), errorCode: report.errorCode }) + "\n");
    if (!report.ok) process.exitCode = 1;
  }
}

if (args["--child-input"]) {
  runChild(args["--child-input"]).catch(async error => {
    const cleanup = await emergencyChildCleanup?.();
    if (process.send) process.send({ type: "fatal", ...safeError(error), cleanup }, () => process.exit(1));
    else process.exit(1);
  });
} else await runParent();
