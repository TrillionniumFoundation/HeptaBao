#!/usr/bin/env node
/** Exact preserved owner credential -> unchanged plugin -> isolated actual SDK.
 * This adapter has its own exact source guard. The older synthetic-only
 * coordinator consumer remains unchanged. No provider or OAuth refresh is
 * allowed, and raw production profile/identity strings never enter a receipt.
 */
import assert from "node:assert/strict";
import childProcess from "node:child_process";
import crypto from "node:crypto";
import dns from "node:dns";
import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import path from "node:path";
import { syncBuiltinESMExports } from "node:module";
import { pathToFileURL } from "node:url";

const LIMIT = 2 * 1024 * 1024;
const ORIGINAL_SHA = "b19b6a9e7c1d57ccef8d67994ed3421891788ac30a82ff6bad2eef2ef7e30f9b";
const hash = value => crypto.createHash("sha256").update(value).digest("hex");
const stable = value => Array.isArray(value) ? value.map(stable) : value && typeof value === "object"
  ? Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])])) : value;
const digest = value => hash(JSON.stringify(stable(value)));
const identity = credential => digest(Object.fromEntries(
  ["provider", "type", "email", "accountId", "projectId"].map(key => [key, credential[key] ?? null])));
const SDK_FILES = {
  "dist/store-DH33UrUj.js": "25a5c7075e13b8fb32f498a90e5ee91d93b7e15972b3b74796f1325b5ba98ebf",
  "dist/source-check-ZSz5NzGW.js": "9c02bbf2df3cf123efe8c34c423ae4ea044371aab91d727f38986351695ce1c9",
  "dist/sqlite-B1ze-fre.js": "ed940f0ba0877eea0f00b2da30e727714993db60156fefc6fe80ac8564984c50",
  "dist/plugin-sdk/agent-runtime.js": "7831532d17eeaddd62889b2e8bb7b65ea7a7851901f69ceec23607a8c579dd95",
  "dist/agent-scope-config-BxAUeF6t.js": "83ef65476ae41bfcf040b1503f468074f36d602e9fa46551822cb7768bef3a1f",
};
const MAIN_BINDING = {
  hostId: "desktop", stateDir: "/home/qian-qi/.openclaw",
  ownerAgentDir: "/home/qian-qi/.openclaw/agents/main/agent",
  configSha256: "791d2d5e7166d02b871a8aa21b0194ca65456c0019757451bfe46d0fe8127d55",
  inspectReceiptSha256: "e058878b389fe28c9d32c046eeb37557d1838343a8bf0922cab50a2cd77e538b",
  profileIdSha256: "7b0b24e17c166c04c73864d9d276562e30c15bd5bf9f719ea3abd1a9687b0c0d",
  credentialDigest: "71c3e21e28368490383dc3628f561e42fef261b0f4ef78263e4dcf3873dc381b",
  identityDigest: "c84e09f9ec9749c94545ddf65091f448ff795b318fde24a3780b6f000ff4ee9d",
  candidateSha256: "f2c164581d5afb0c9f95b9a71aedaa3f2a889817dabe1201169f7b5ce6f5dbe6",
  exportReceiptSha256: "41197f8d23229f9103b51505b319cc09eef0a48192631821caf7da2172d74907",
};
function fail(code) { throw Object.assign(new Error(code), { canaryCode: code }); }
function requireValue(value, code) { if (!value) fail(code); }
function privateFile(filename) {
  const fd = fs.openSync(filename, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const before = fs.fstatSync(fd);
    requireValue(before.isFile() && before.uid === process.getuid()
      && (before.mode & 0o777) === 0o600 && before.size <= LIMIT, "private_file_custody_invalid");
    const value = fs.readFileSync(fd), after = fs.fstatSync(fd);
    requireValue(value.length <= LIMIT && before.dev === after.dev && before.ino === after.ino
      && before.size === after.size && before.mtimeMs === after.mtimeMs && before.ctimeMs === after.ctimeMs,
      "private_file_changed_during_read");
    return value;
  } finally { fs.closeSync(fd); }
}
function ownedDirectory(directory) {
  requireValue(path.isAbsolute(directory) && fs.realpathSync(directory) === path.resolve(directory),
    "private_directory_alias_invalid");
  const s = fs.lstatSync(directory);
  requireValue(s.isDirectory() && !s.isSymbolicLink() && s.uid === process.getuid()
    && (s.mode & 0o777) === 0o700, "private_directory_custody_invalid");
}
function inside(root, target) {
  if (!path.isAbsolute(target)) return false;
  const relative = path.relative(root, target);
  return relative !== "" && relative !== ".." && !relative.startsWith(".." + path.sep) && !path.isAbsolute(relative);
}
function writeExclusive(filename, value, raw = false) {
  const data = raw ? value : Buffer.from(JSON.stringify(value) + "\n");
  const fd = fs.openSync(filename, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
  try { fs.writeFileSync(fd, data); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  const parent = fs.openSync(path.dirname(filename), fs.constants.O_RDONLY | fs.constants.O_DIRECTORY);
  try { fs.fsyncSync(parent); } finally { fs.closeSync(parent); }
}
function rememberPrivate(record, secrets) {
  secrets.add(record.profileId);
  for (const [key, value] of Object.entries(record.credential)) {
    if (!["provider", "type", "chatgptPlanType"].includes(key) && typeof value === "string" && value.length) secrets.add(value);
  }
}
function redacted(value, secrets) {
  const text = typeof value === "string" ? value : JSON.stringify(value);
  return [...secrets].every(secret => !text.includes(secret)
    && !text.includes(JSON.stringify(secret).slice(1, -1)));
}

/** Python time.monotonic_ns and Node hrtime use the same monotonic clock on
 * this Linux-only main fixture. Retain the parent's exact absolute deadline;
 * importing the SDK, starting a second cycle, or issuing another request must
 * never create a new operation budget. The caller checks the clock domain. */
export function originalDeadline(value, clock = () => process.hrtime.bigint()) {
  requireValue(typeof value === "string" && /^[1-9][0-9]{1,24}$/.test(value), "original_deadline_shape_invalid");
  const deadline = BigInt(value);
  function left() {
    const remaining = deadline - clock();
    requireValue(remaining > 0n, "original_operation_deadline_elapsed");
    return remaining;
  }
  requireValue(left() <= 360000000000n, "original_deadline_clock_or_budget_mismatch");
  return {
    check: left,
    milliseconds(maximum = 15000) {
      requireValue(Number.isFinite(maximum) && maximum > 0 && maximum <= 75000, "request_deadline_bound_invalid");
      return Math.max(1, Math.min(maximum, Number((left() + 999999n) / 1000000n)));
    },
  };
}

/** Same validation executes before SDK import and in the local pure tests. */
export function validateOwnedCandidate(candidate, expected) {
  requireValue(candidate?.schema === "authbus-owned-sdk-source-snapshot-v1"
    && candidate.hostId === expected.hostId && candidate.stateDir === expected.stateDir
    && candidate.configSha256 === expected.configSha256
    && candidate.inspectReceiptSha256 === expected.inspectReceiptSha256, "owned_candidate_provenance_mismatch");
  requireValue(candidate.sdkContract?.version === "2026.7.1-2"
    && digest(candidate.sdkContract.files) === digest(SDK_FILES), "owned_candidate_sdk_contract_mismatch");
  const constraints = candidate.constraints;
  requireValue(constraints?.providerLivenessVerified === false && constraints.oauthRefreshed === false
    && constraints.productionCutover === false && constraints.snapshotRequiresRecheckBeforePublication === true
    && constraints.coordinatorOwnershipQualified === false, "owned_candidate_authority_inflated");
  requireValue(Array.isArray(candidate.profiles) && candidate.profiles.length === 1, "one_exact_owned_profile_required");
  const record = candidate.profiles[0], credential = record?.credential;
  requireValue(typeof record.profileId === "string" && record.profileId.length > 0
    && hash(record.profileId) === expected.profileIdSha256
    && record.digest === expected.credentialDigest && record.identity === expected.identityDigest
    && credential?.provider === "openai" && credential.type === "oauth"
    && typeof credential.access === "string" && credential.access.length >= 8
    && typeof credential.refresh === "string" && credential.refresh.length >= 8
    && Number.isSafeInteger(credential.expires)
    && !["keyRef", "tokenRef", "accessRef", "refreshRef"].some(key => Object.hasOwn(credential, key))
    && digest(credential) === expected.credentialDigest && identity(credential) === expected.identityDigest,
    "owned_candidate_exact_credential_mismatch");
  requireValue(record.source?.scopeAgentDir === expected.ownerAgentDir
    && record.source.ownerAgentDir === expected.ownerAgentDir
    && record.source.databasePath === path.join(expected.ownerAgentDir, "openclaw-agent.sqlite")
    && record.source.method === "actual_sdk_readonly_persisted_owner", "owned_candidate_owner_path_mismatch");
  return record;
}

async function cli() {
  const report = { schema: "actual-authbus-owned-source-client-v1", ok: false,
    production_coordinator_replacement: false, production_mutation: false, production_cutover: false,
    real_provider_credentials: true, provider_network_allowed: false, provider_called: false,
    oauth_refreshed: false, observations: [], cycles: [], outsideNetworkAttempts: 0, childProcessAttempts: 0 };
  const publicWrite = process.stdout.write.bind(process.stdout);
  const diagnostics = { bytes: 0, stdout: [], stderr: [] }, sensitive = new Set(), captured = [];
  // Hold SDK diagnostics for the entire Node lifetime. Only publicWrite emits
  // a constructed receipt; queued SDK warnings cannot bypass this sink.
  for (const name of ["stdout", "stderr"]) process[name].write = function (chunk, encoding, callback) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), typeof encoding === "string" ? encoding : "utf8");
    diagnostics.bytes += bytes.length;
    if (diagnostics.bytes <= LIMIT) diagnostics[name].push(bytes);
    if (typeof encoding === "function") encoding(); else if (typeof callback === "function") callback();
    return true;
  };
  let config, service, baoAgent, operation, privateOutputsTrusted = false, code = 2;
  const socketIds = new WeakMap(); let nextSocketId = 1;
  function socketId(socket) {
    if (!socketIds.has(socket)) socketIds.set(socket, nextSocketId++);
    return socketIds.get(socket);
  }
  try {
    report.phase = "scope";
    requireValue(process.argv.length === 3, "private_config_required");
    config = JSON.parse(privateFile(process.argv[2]));
    requireValue(config.schema === "authbus-owned-source-client-driver-v1"
      && Array.isArray(config.steps) && config.steps.length >= 1 && config.steps.length <= 2, "config_shape_invalid");
    requireValue(process.platform === "linux", "original_monotonic_clock_requires_main_linux");
    operation = originalDeadline(config.absoluteDeadlineMonotonicNs);
    report.originalOperationDeadlineReused = true;
    const root = config.workRoot; ownedDirectory(root);
    for (const name of ["stateDir", "agentDir", "runDir", "homeDir", "oauthDir", "configPath", "pluginEntry",
      "capturePath", "receiptPath", "sourceCandidatePath", "diagnosticsPath"]) {
      requireValue(inside(root, config[name]), "mutable_path_outside_fixture");
    }
    for (const name of ["stateDir", "agentDir", "runDir", "homeDir", "oauthDir"]) ownedDirectory(config[name]);
    for (const [name, filename] of [["capturePath", "tokens.private.json"], ["receiptPath", "receipt.json"],
      ["diagnosticsPath", "sdk-diagnostics.private.log"]]) {
      requireValue(config[name] === path.join(config.runDir, filename)
        && !fs.existsSync(config[name]), "new_private_output_required");
    }
    privateOutputsTrusted = true;
    process.umask(0o077);
    for (const name of ["roleIdFile", "secretIdFile", "caFile"])
      requireValue(inside(root, config.pluginConfig[name]), "binding_outside_fixture");
    const raw = config.pluginConfig;
    requireValue([true, false].includes(raw.leader) && raw.publishNew === true && raw.manageOrder === true
      && raw.releaseGeneration === 201 && raw.pollIntervalMs === 15000 && raw.maxRefreshesPerCycle === 1
      && raw.refreshMarginMs === 900000 && !Object.hasOwn(raw, "schedulerMode")
      && !Object.hasOwn(raw, "enforceRefreshLeases"), "actual_default_contract_changed");
    const target = new URL(raw.address);
    requireValue(target.protocol === "https:" && target.hostname === "127.0.0.1" && target.port
      && !target.username && !target.password && target.pathname === "/", "loopback_https_required");
    requireValue(hash(privateFile(config.pluginEntry)) === ORIGINAL_SHA, "production_plugin_source_changed");
    requireValue(config.sourceCandidateSha256 === MAIN_BINDING.candidateSha256
      && config.sourceReceiptSha256 === MAIN_BINDING.exportReceiptSha256, "owned_source_receipt_binding_changed");
    const candidateBytes = privateFile(config.sourceCandidatePath);
    requireValue(hash(candidateBytes) === MAIN_BINDING.candidateSha256, "owned_source_candidate_bytes_changed");
    const record = validateOwnedCandidate(JSON.parse(candidateBytes), MAIN_BINDING);
    rememberPrivate(record, sensitive);
    requireValue(record.credential.expires > Date.now() + raw.refreshMarginMs, "owned_source_expiry_margin_elapsed");
    report.source = { profileIdSha256: MAIN_BINDING.profileIdSha256, credentialDigest: record.digest,
      identityDigest: record.identity, exportReceiptSha256: MAIN_BINDING.exportReceiptSha256,
      candidateSha256: MAIN_BINDING.candidateSha256, providerLivenessVerified: false, snapshotNotARefreshLease: true };
    process.env.OPENCLAW_STATE_DIR = config.stateDir;
    process.env.OPENCLAW_CONFIG_PATH = config.configPath;
    process.env.OPENCLAW_HOME = config.homeDir;
    process.env.OPENCLAW_OAUTH_DIR = config.oauthDir;
    requireValue(process.env.OPENCLAW_AUTH_STORE_READONLY !== "1", "inherited_readonly_auth_store");
    for (const key of ["GOOGLE_API_KEY", "GEMINI_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "OPENCLAW_GATEWAY_TOKEN"])
      delete process.env[key];
    const denyNetwork = () => { report.outsideNetworkAttempts += 1; fail("network_outside_isolated_bao"); };
    http.request = http.get = https.get = denyNetwork; globalThis.fetch = denyNetwork;
    for (const key of ["lookup", "lookupService", "resolve", "resolve4", "resolve6", "resolveAny", "resolveCname",
      "resolveMx", "resolveTxt", "reverse"]) {
      if (typeof dns[key] === "function") dns[key] = denyNetwork;
      if (typeof dns.promises[key] === "function") dns.promises[key] = denyNetwork;
    }
    for (const key of ["exec", "execFile", "execSync", "execFileSync", "spawn", "spawnSync", "fork"]) {
      childProcess[key] = () => { report.childProcessAttempts += 1; fail("external_cli_or_child_not_allowed"); };
    }
    const connect = net.Socket.prototype.connect;
    net.Socket.prototype.connect = function (...args) {
      const first = Array.isArray(args[0]) ? args[0][0] : args[0];
      const host = first && typeof first === "object" ? first.host ?? first.hostname : args[1];
      const port = first && typeof first === "object" ? first.port : first;
      if (host !== "127.0.0.1" || String(port) !== target.port) return denyNetwork();
      return connect.apply(this, args);
    };
    baoAgent = new https.Agent({ keepAlive: false, maxCachedSessions: 0 });
    report.harnessTransport = { isolatedBaoAgent: "fresh_full_tls_handshake_per_request",
      keepAlive: false, maxCachedSessions: 0, productionPluginModified: false };
    const request = https.request;
    https.request = function (options, callback) {
      operation.check();
      if (!options || typeof options !== "object" || options instanceof URL
        || (options.hostname ?? options.host) !== target.hostname || String(options.port ?? 443) !== target.port
        || options.rejectUnauthorized !== true || !["GET", "POST"].includes(options.method)) return denyNetwork();
      const route = options.path === "/v1/auth/approle/login" && options.method === "POST" ? "login"
        : options.path?.startsWith("/v1/openclaw-auth/data/inbox/" + raw.hostId + "/") && options.method === "POST" ? "own_inbox"
        : options.path?.startsWith("/v1/openclaw-auth/data/") && options.method === "GET" ? "canonical_read" : null;
      requireValue(route !== null, "plugin_attempted_noncontract_route");
      const observation = { method: options.method, route, pathSha256: hash(options.path) };
      report.observations.push(observation);
      const timeout = operation.milliseconds(Math.min(options.timeout ?? 15000, 15000));
      const outgoing = request.call(https, { ...options, timeout, agent: baoAgent }, response => {
        try { operation.check(); } catch (error) {
          response.on("error", () => {}); outgoing.destroy(error); response.destroy(); return;
        }
        const socket = response.socket;
        observation.status = response.statusCode; observation.tlsAuthorized = socket.authorized === true;
        observation.tlsVersion = socket.getProtocol?.() ?? null; observation.socketId = socketId(socket);
        observation.isSessionReused = socket.isSessionReused?.() ?? null;
        const certificate = socket.getPeerCertificate();
        observation.peerCertificateSha256 = certificate.raw ? hash(certificate.raw) : null;
        if (!observation.tlsAuthorized || observation.peerCertificateSha256 !== config.serverCertificateSha256) {
          response.on("error", () => {});
          outgoing.destroy(Object.assign(new Error("isolated_peer_pin_changed"), { canaryCode: "isolated_peer_pin_changed" }));
          response.destroy(); return;
        }
        if (route === "login") {
          const chunks = []; let length = 0;
          response.on("data", chunk => { length += chunk.length; if (length <= LIMIT) chunks.push(chunk); });
          response.on("end", () => {
            if (length > LIMIT) return;
            try {
              const auth = JSON.parse(Buffer.concat(chunks))?.auth;
              if (response.statusCode === 200 && typeof auth?.client_token === "string") {
                captured.push({ token: auth.client_token, accessor: auth.accessor }); sensitive.add(auth.client_token);
                if (typeof auth.accessor === "string") sensitive.add(auth.accessor);
              }
            } catch { /* The unchanged plugin owns body parsing. */ }
          });
        }
        callback(response);
      });
      // The original plugin's socket timeout is an inactivity bound. This
      // timer also stops a response that continues streaming past the fixed
      // parent deadline; it does not restart when data arrives.
      const absoluteTimer = setTimeout(() => {
        outgoing.destroy(Object.assign(new Error("original_operation_or_request_deadline_elapsed"),
          { canaryCode: "original_operation_or_request_deadline_elapsed" }));
      }, timeout);
      outgoing.once("close", () => clearTimeout(absoluteTimer));
      observation.originalOperationDeadlineReused = true;
      outgoing.on("socket", socket => { observation.requestSocketId = socketId(socket); });
      return outgoing;
    };
    syncBuiltinESMExports();
    report.phase = "actual_sdk";
    const sdkObserved = {};
    for (const [relative, expected] of Object.entries(SDK_FILES)) {
      const filename = path.join(config.openclawRoot, relative), info = fs.lstatSync(filename);
      requireValue(info.isFile() && !info.isSymbolicLink() && info.size <= LIMIT, "actual_sdk_file_invalid");
      sdkObserved[relative] = hash(fs.readFileSync(filename));
      requireValue(sdkObserved[relative] === expected, "actual_sdk_contract_changed");
    }
    report.sdkVersion = JSON.parse(fs.readFileSync(path.join(config.openclawRoot, "package.json"))).version;
    requireValue(report.sdkVersion === "2026.7.1-2", "actual_sdk_version_changed");
    report.sdkSourceSha256 = sdkObserved;
    operation.check();
    const sdk = await import(pathToFileURL(path.join(config.openclawRoot, "dist/plugin-sdk/agent-runtime.js")).href);
    operation.check();
    requireValue(path.resolve(sdk.resolveDefaultAgentDir({})) === path.resolve(config.agentDir), "default_agent_not_scoped");
    const db = path.resolve(sdk.resolveAuthStorePathForDisplay(config.agentDir));
    requireValue(db === path.join(config.agentDir, "openclaw-agent.sqlite"), "sqlite_not_scoped");
    report.defaultAgentScoped = true;
    if (!fs.existsSync(db)) {
      operation.check();
      sdk.saveAuthProfileStore({ version: 1, profiles: {} }, config.agentDir,
        { filterExternalAuthProfiles: false, syncExternalCli: false });
      operation.check();
    }
    const read = () => {
      operation.check();
      sdk.clearRuntimeAuthProfileStoreSnapshots();
      const store = sdk.loadAuthProfileStoreWithoutExternalProfiles(config.agentDir, { allowKeychainPrompt: false });
      operation.check(); return store;
    };
    const snapshot = () => {
      const store = read(), entries = Object.entries(store.profiles ?? {});
      requireValue(entries.length <= 1 && entries.every(([id, value]) => id === record.profileId
        && digest(value) === record.digest), "unselected_profile_or_credential_in_fixture");
      const order = store.order?.[record.credential.provider] ?? null;
      const resolved = sdk.resolveAuthProfileOrder({ cfg: {}, store, provider: record.credential.provider });
      requireValue((order === null || order.every(id => id === record.profileId))
        && resolved.every(id => id === record.profileId), "unselected_order_profile_in_fixture");
      return { profilesByIdSha256: Object.fromEntries(entries.map(([id, value]) => [hash(id), digest(value)])),
        orderProfileIdSha256: order?.map(hash) ?? null, resolvedOrderProfileIdSha256: resolved.map(hash) };
    };
    report.initial = snapshot();
    const clients = globalThis[Symbol.for("openclaw.codexAppServerClientState")];
    requireValue(!clients?.clients?.size, "unexpected_live_codex_clients");
    report.phase = "actual_plugin";
    operation.check();
    const plugin = (await import(pathToFileURL(config.pluginEntry).href)).default;
    operation.check();
    let subscriptions = 0;
    plugin.register({ registrationMode: "full", pluginConfig: raw,
      agent: { events: { registerAgentEventSubscription() { subscriptions += 1; } } },
      registerService(value) { requireValue(!service, "multiple_services"); service = value; },
    });
    requireValue(subscriptions === 1 && service?.id === "openclaw-authbus", "plugin_registration_changed");
    const logCounts = { info: 0, warn: 0, error: 0, debug: 0 };
    const logger = Object.fromEntries(Object.keys(logCounts).map(level => [level, () => { logCounts[level] += 1; }]));
    for (const step of config.steps) {
      operation.check();
      requireValue(step && typeof step === "object" && !Array.isArray(step)
        && (Object.keys(step).length === 0 || Object.keys(step).join(",") === "upsertOwnedSource"
          && step.upsertOwnedSource === true), "only_exact_owned_source_step_allowed");
      if (step.upsertOwnedSource) {
        requireValue(raw.leader === true && await sdk.upsertAuthProfileWithLock({
          agentDir: config.agentDir, profileId: record.profileId, credential: record.credential,
        }), "actual_owned_sdk_upsert_failed");
        operation.check();
      }
      const before = snapshot();
      await service.start({ stateDir: config.stateDir, config: {}, logger }); await service.stop();
      operation.check();
      const status = JSON.parse(privateFile(path.join(config.stateDir, "authbus/status.json")));
      const allowed = ["ok", "leader", "manifestGeneration", "manifestProfiles", "importedProfiles", "changedStores",
        "publishedEvents", "schedulerReports", "agentStores", "verifiedStores", "effectiveMissing", "effectiveMismatched",
        "pendingRuntimeRefreshes", "orderPolicyGeneration", "changedOrders", "managedOrderBindings", "verifiedOrderBindings",
        "schedulerMode", "strictLeaseAssignments", "strictLeaseShadow", "strictLeaseStale", "releaseGeneration"];
      const safe = Object.fromEntries(allowed.filter(key => Object.hasOwn(status, key)).map(key => [key, status[key]]));
      if (status.error) safe.errorSha256 = hash(String(status.error));
      report.cycles.push({ before, after: snapshot(), plugin: safe });
      if (status.ok !== true) { report.error = "actual_plugin_cycle_failed"; code = 3; break; }
    }
    if (!report.error) {
      operation.check();
      requireValue(report.outsideNetworkAttempts === 0 && report.childProcessAttempts === 0, "unexpected_external_effect_attempt");
      report.phase = "complete"; report.logCounts = logCounts; report.ok = true; code = 0;
    }
  } catch (error) {
    report.ok = false; report.error = error.canaryCode ?? "unexpected_owned_consumer_error";
    report.errorClass = typeof error?.name === "string" && /^[A-Za-z]+$/.test(error.name) ? error.name : "Error";
  } finally {
    if (service) { try { await service.stop(); } catch { report.stopFailed = true; code = 2; report.ok = false; } }
    baoAgent?.destroy(); report.authentications = captured.length;
    report.sdkDiagnosticBytes = diagnostics.bytes;
    const diagnosticBytes = Buffer.concat([...diagnostics.stdout, ...diagnostics.stderr]);
    report.sdkDiagnosticSha256 = hash(diagnosticBytes);
    if (diagnostics.bytes > LIMIT || !redacted(report, sensitive)) {
      for (const key of Object.keys(report)) delete report[key];
      Object.assign(report, { schema: "actual-authbus-owned-source-client-v1", ok: false,
        error: "public_owned_evidence_refused", production_mutation: false }); code = 2;
    }
    if (privateOutputsTrusted) {
      try {
        // The source's raw ID/identity and SDK diagnostics stay on the same
        // owner host. No raw diagnostic text is included in public evidence.
        writeExclusive(config.capturePath, { tokens: captured });
        writeExclusive(config.diagnosticsPath, diagnosticBytes, true);
        writeExclusive(config.receiptPath, report);
      } catch { report.ok = false; report.error = "private_receipt_write_failed"; code = 2; }
    }
  }
  if (!redacted(report, sensitive)) {
    publicWrite(JSON.stringify({ schema: "actual-authbus-owned-source-client-v1", ok: false,
      error: "public_owned_evidence_refused", production_mutation: false }) + "\n"); code = 2;
  } else publicWrite(JSON.stringify(report) + "\n");
  process.exitCode = code;
}

function selfTest() {
  const credential = { provider: "openai", type: "oauth", access: "synthetic-owned-access",
    refresh: "synthetic-owned-refresh", expires: 1900000000000, email: "synthetic@example.invalid", accountId: "synthetic-owned" };
  const expected = { ...MAIN_BINDING, profileIdSha256: hash("openai:synthetic-owned"),
    credentialDigest: digest(credential), identityDigest: identity(credential) };
  const candidate = { schema: "authbus-owned-sdk-source-snapshot-v1", hostId: expected.hostId,
    stateDir: expected.stateDir, configSha256: expected.configSha256, inspectReceiptSha256: expected.inspectReceiptSha256,
    sdkContract: { version: "2026.7.1-2", files: SDK_FILES }, constraints: {
      providerLivenessVerified: false, oauthRefreshed: false, productionCutover: false,
      snapshotRequiresRecheckBeforePublication: true, coordinatorOwnershipQualified: false },
    profiles: [{ profileId: "openai:synthetic-owned", credential, digest: expected.credentialDigest,
      identity: expected.identityDigest, source: { scopeAgentDir: expected.ownerAgentDir,
        ownerAgentDir: expected.ownerAgentDir, databasePath: path.join(expected.ownerAgentDir, "openclaw-agent.sqlite"),
        method: "actual_sdk_readonly_persisted_owner" } }] };
  const checks = [];
  function test(name, fn) { fn(); checks.push({ case: name, passed: true }); }
  test("exact_owned_record", () => assert.equal(validateOwnedCandidate(candidate, expected).digest, expected.credentialDigest));
  for (const [name, mutate] of [
    ["changed_credential", value => { value.profiles[0].credential.access += "changed"; }],
    ["changed_profile", value => { value.profiles[0].profileId += "changed"; }],
    ["changed_identity", value => { value.profiles[0].identity = "0".repeat(64); }],
    ["changed_owner", value => { value.profiles[0].source.ownerAgentDir += "-other"; }],
    ["changed_sdk", value => { value.sdkContract.version = "unknown"; }],
    ["provider_liveness_inflated", value => { value.constraints.providerLivenessVerified = true; }],
    ["refresh_authority_inflated", value => { value.constraints.coordinatorOwnershipQualified = true; }],
    ["second_profile", value => { value.profiles.push(value.profiles[0]); }],
    ["unresolved_reference", value => { value.profiles[0].credential.refreshRef = {}; }],
  ]) test(name, () => { const value = structuredClone(candidate); mutate(value); assert.throws(() => validateOwnedCandidate(value, expected)); });
  test("private_identity_and_profile_redaction", () => {
    const secrets = new Set(); rememberPrivate(candidate.profiles[0], secrets);
    assert.equal(redacted({ digest: expected.credentialDigest }, secrets), true);
    for (const value of [candidate.profiles[0].profileId, credential.email, credential.access, credential.refresh])
      assert.equal(redacted({ value }, secrets), false);
  });
  test("json_escaped_private_fields_are_rejected", () => {
    for (const value of ['private-"quoted"', "private\\backslash", "private\nnewline", "私密-\t字段"])
      assert.equal(redacted({ value }, new Set([value])), false);
  });
  test("original_deadline_is_not_reset_between_operations", () => {
    let now = 100000000000n;
    const gate = originalDeadline("110000000000", () => now);
    assert.equal(gate.milliseconds(), 10000);
    now = 109000000000n; assert.equal(gate.milliseconds(), 1000);
    now = 110000000000n; assert.throws(() => gate.check(), /original_operation_deadline_elapsed/);
  });
  test("deadline_shape_clock_domain_and_extension_are_rejected", () => {
    for (const value of ["Infinity", "NaN", -1, "100000000000", "461000000001"])
      assert.throws(() => originalDeadline(value, () => 100000000000n));
  });
  console.log(JSON.stringify({ schema: "authbus-owned-consumer-contract-test-v1", ok: true, checks,
    syntheticOnly: true, actualSdkQualified: false, providerCalled: false, productionMutation: false }));
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  if (process.argv.length === 3 && process.argv[2] === "--self-test") selfTest();
  else await cli();
}
