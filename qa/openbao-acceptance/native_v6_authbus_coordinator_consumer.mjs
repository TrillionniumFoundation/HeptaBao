#!/usr/bin/env node
/** Actual original AuthBus producer/follower in a new isolated SDK store.
 * Synthetic fixtures only; all network is restricted to the new loopback Bao.
 * The original installed plugin is imported unchanged. No provider is called.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import path from "node:path";
import { pathToFileURL } from "node:url";

const LIMIT = 1024 * 1024;
const ORIGINAL_SHA = "b19b6a9e7c1d57ccef8d67994ed3421891788ac30a82ff6bad2eef2ef7e30f9b";
const hash = value => crypto.createHash("sha256").update(value).digest("hex");
const stable = value => Array.isArray(value) ? value.map(stable) : value && typeof value === "object"
  ? Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])])) : value;
const digest = value => hash(JSON.stringify(stable(value)));
const report = { schema: "actual-authbus-central-client-v1", ok: false, production_coordinator_replacement: false,
  production_mutation: false, real_provider_credentials: false, provider_network_allowed: false, observations: [], cycles: [] };
let config, service, baoAgent;
const captured = [];
const socketIds = new WeakMap();
let nextSocketId = 1;

function socketId(socket) {
  if (!socketIds.has(socket)) socketIds.set(socket, nextSocketId++);
  return socketIds.get(socket);
}

function fail(code) { throw Object.assign(new Error(code), { canaryCode: code }); }
function privateFile(filename) {
  const s = fs.lstatSync(filename);
  if (!s.isFile() || s.isSymbolicLink() || s.uid !== process.getuid() || (s.mode & 0o077) || s.size > LIMIT) fail("private_file_custody_invalid");
  return fs.readFileSync(filename);
}
function ownedDirectory(directory) {
  const s = fs.lstatSync(directory);
  if (!s.isDirectory() || s.isSymbolicLink() || s.uid !== process.getuid() || (s.mode & 0o077)) fail("private_directory_custody_invalid");
}
function inside(root, target) {
  if (!path.isAbsolute(target)) return false;
  const relative = path.relative(root, target);
  return relative !== "" && relative !== ".." && !relative.startsWith(".." + path.sep) && !path.isAbsolute(relative);
}
function writeExclusive(filename, value) {
  const fd = fs.openSync(filename, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
  try { fs.writeFileSync(fd, JSON.stringify(value) + "\n"); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  const parent = fs.openSync(path.dirname(filename), fs.constants.O_RDONLY | fs.constants.O_DIRECTORY);
  try { fs.fsyncSync(parent); } finally { fs.closeSync(parent); }
}

async function main() {
  report.phase = "scope";
  if (process.argv.length !== 3) fail("private_config_required");
  config = JSON.parse(privateFile(process.argv[2]));
  if (config.schema !== "authbus-central-client-driver-v1" || !Array.isArray(config.steps) || config.steps.length < 1 || config.steps.length > 2) fail("config_shape_invalid");
  const root = fs.realpathSync(config.workRoot);
  ownedDirectory(root);
  for (const name of ["stateDir", "agentDir", "runDir", "homeDir", "oauthDir", "configPath", "pluginEntry", "capturePath", "receiptPath"]) {
    if (!inside(root, config[name])) fail("mutable_path_outside_fixture");
  }
  for (const name of ["stateDir", "agentDir", "runDir", "homeDir", "oauthDir"]) ownedDirectory(config[name]);
  for (const name of ["roleIdFile", "secretIdFile", "caFile"]) if (!inside(root, config.pluginConfig[name])) fail("binding_outside_fixture");
  const raw = config.pluginConfig;
  if (![true, false].includes(raw.leader) || raw.publishNew !== true || raw.manageOrder !== true || raw.releaseGeneration !== 201
      || raw.pollIntervalMs !== 15000 || raw.maxRefreshesPerCycle !== 1 || raw.refreshMarginMs !== 900000
      || Object.hasOwn(raw, "schedulerMode") || Object.hasOwn(raw, "enforceRefreshLeases")) fail("central_client_contract_changed");
  const target = new URL(raw.address);
  if (target.protocol !== "https:" || target.hostname !== "127.0.0.1" || !target.port || target.username || target.password) fail("loopback_https_required");
  if (hash(privateFile(config.pluginEntry)) !== ORIGINAL_SHA) fail("production_plugin_source_changed");
  process.env.OPENCLAW_STATE_DIR = config.stateDir;
  process.env.OPENCLAW_CONFIG_PATH = config.configPath;
  process.env.OPENCLAW_HOME = config.homeDir;
  process.env.OPENCLAW_OAUTH_DIR = config.oauthDir;
  for (const key of ["GOOGLE_API_KEY", "GEMINI_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "OPENCLAW_GATEWAY_TOKEN"]) delete process.env[key];
  if (process.env.OPENCLAW_AUTH_STORE_READONLY === "1") fail("inherited_readonly_auth_store");

  const denyNetwork = () => fail("network_outside_isolated_bao");
  http.request = http.get = https.get = denyNetwork;
  globalThis.fetch = denyNetwork;
  const connect = net.Socket.prototype.connect;
  net.Socket.prototype.connect = function (...args) {
    const first = Array.isArray(args[0]) ? args[0][0] : args[0];
    const host = first && typeof first === "object" ? first.host ?? first.hostname : args[1];
    const port = first && typeof first === "object" ? first.port : first;
    if (host !== "127.0.0.1" || String(port) !== target.port) fail("socket_outside_isolated_bao");
    return connect.apply(this, args);
  };
  // As in the real-provider consumer, require a new full TLS handshake for
  // each local Bao request so every pin comes from that request's real peer.
  baoAgent = new https.Agent({ keepAlive: false, maxCachedSessions: 0 });
  report.harnessTransport = { isolatedBaoAgent: "fresh_full_tls_handshake_per_request",
    keepAlive: false, maxCachedSessions: 0, productionPluginModified: false };
  const request = https.request;
  https.request = function (options, callback) {
    if (!options || typeof options !== "object" || options instanceof URL
        || (options.hostname ?? options.host) !== target.hostname || String(options.port ?? 443) !== target.port
        || options.rejectUnauthorized !== true || !["GET", "POST"].includes(options.method)) fail("unexpected_https_request");
    const route = options.path === "/v1/auth/approle/login" ? "login"
      : options.path?.startsWith(`/v1/openclaw-auth/data/inbox/${raw.hostId}/`) ? "own_inbox"
      : options.path?.startsWith("/v1/openclaw-auth/data/") && options.method === "GET" ? "canonical_read" : null;
    if (!route) fail("plugin_attempted_noncontract_route");
    const observation = { method: options.method, route, pathSha256: hash(options.path) };
    report.observations.push(observation);
    const outgoing = request.call(https, { ...options, agent: baoAgent }, response => {
      observation.status = response.statusCode;
      observation.tlsAuthorized = response.socket.authorized === true;
      observation.tlsVersion = response.socket.getProtocol?.() ?? null;
      observation.socketId = socketId(response.socket);
      observation.isSessionReused = response.socket.isSessionReused?.() ?? null;
      const certificate = response.socket.getPeerCertificate();
      observation.peerCertificateSha256 = certificate.raw ? hash(certificate.raw) : null;
      if (observation.peerCertificateSha256 !== config.serverCertificateSha256) {
        response.on("error", () => {}); // The request delivers the fixed rejection to the plugin.
        outgoing.destroy(Object.assign(new Error("isolated_peer_pin_changed"), { canaryCode: "isolated_peer_pin_changed" }));
        response.destroy();
        return;
      }
      if (route === "login") {
        const chunks = []; let length = 0;
        response.on("data", chunk => { length += chunk.length; if (length <= LIMIT) chunks.push(chunk); });
        response.on("end", () => {
          if (length > LIMIT) return;
          try {
            const auth = JSON.parse(Buffer.concat(chunks))?.auth;
            if (response.statusCode === 200 && typeof auth?.client_token === "string") captured.push({ token: auth.client_token, accessor: auth.accessor });
          } catch { /* The actual plugin owns JSON validation. */ }
        });
      }
      callback(response);
    });
    outgoing.on("socket", socket => { observation.requestSocketId = socketId(socket); });
    return outgoing;
  };

  report.phase = "actual_sdk";
  const sdk = await import(pathToFileURL(path.join(config.openclawRoot, "dist/plugin-sdk/agent-runtime.js")).href);
  if (path.resolve(sdk.resolveDefaultAgentDir({})) !== path.resolve(config.agentDir)) fail("default_agent_not_scoped");
  const db = path.resolve(sdk.resolveAuthStorePathForDisplay(config.agentDir));
  if (db !== path.join(config.agentDir, "openclaw-agent.sqlite")) fail("sqlite_not_scoped");
  report.defaultAgentScoped = true;
  report.sdkVersion = JSON.parse(fs.readFileSync(path.join(config.openclawRoot, "package.json"), "utf8")).version;
  if (!fs.existsSync(db)) sdk.saveAuthProfileStore({ version: 1, profiles: {} }, config.agentDir, { filterExternalAuthProfiles: false, syncExternalCli: false });
  const read = () => { sdk.clearRuntimeAuthProfileStoreSnapshots(); return sdk.loadAuthProfileStoreWithoutExternalProfiles(config.agentDir, { allowKeychainPrompt: false }); };
  const snapshot = () => {
    const store = read();
    if (Object.keys(store.profiles ?? {}).some(id => !/^\w+:authbus-central-[a-z]+$/.test(id))) fail("external_profile_in_fixture");
    return {
      profiles: Object.fromEntries(Object.entries(store.profiles ?? {}).map(([id, credential]) => [id, digest(credential)])),
      order: store.order?.google ?? null, resolvedOrder: sdk.resolveAuthProfileOrder({ cfg: {}, store, provider: "google" }),
    };
  };
  report.initial = snapshot();
  const clients = globalThis[Symbol.for("openclaw.codexAppServerClientState")];
  if (clients?.clients?.size) fail("unexpected_live_codex_clients");
  report.phase = "actual_plugin";
  const plugin = (await import(pathToFileURL(config.pluginEntry).href)).default;
  let subscriptions = 0;
  plugin.register({ registrationMode: "full", pluginConfig: raw,
    agent: { events: { registerAgentEventSubscription() { subscriptions += 1; } } },
    registerService(value) { if (service) fail("multiple_services"); service = value; },
  });
  if (subscriptions !== 1 || service?.id !== "openclaw-authbus") fail("plugin_registration_changed");
  const logCounts = { info: 0, warn: 0, error: 0, debug: 0 };
  const logger = Object.fromEntries(Object.keys(logCounts).map(level => [level, () => { logCounts[level] += 1; }]));
  for (const step of config.steps) {
    if ((step.upserts?.length ?? 0) > 4) fail("mutation_bound");
    for (const item of step.upserts ?? []) {
      if (!/^\w+:authbus-central-[a-z]+$/.test(item.profileId) || !["api_key", "oauth"].includes(item.credential?.type)) fail("synthetic_profile_shape");
      for (const key of ["key", "access", "refresh"]) if (item.credential[key] !== undefined && !item.credential[key].startsWith("synthetic-authbus-central-")) fail("real_credential_not_allowed");
      if (!await sdk.upsertAuthProfileWithLock({ agentDir: config.agentDir, profileId: item.profileId, credential: item.credential })) fail("actual_sdk_upsert_failed");
    }
    if (step.setOrder && !await sdk.setAuthProfileOrder({ agentDir: config.agentDir, provider: "google", order: step.setOrder })) fail("actual_sdk_order_seed_failed");
    const before = snapshot();
    await service.start({ stateDir: config.stateDir, config: {}, logger });
    await service.stop();
    const status = JSON.parse(privateFile(path.join(config.stateDir, "authbus/status.json")));
    const allowed = ["ok", "leader", "manifestGeneration", "manifestProfiles", "importedProfiles", "changedStores", "publishedEvents", "schedulerReports", "agentStores", "verifiedStores", "effectiveMissing", "effectiveMismatched", "pendingRuntimeRefreshes", "orderPolicyGeneration", "changedOrders", "managedOrderBindings", "verifiedOrderBindings", "schedulerMode", "strictLeaseAssignments", "strictLeaseShadow", "strictLeaseStale", "releaseGeneration"];
    const safe = Object.fromEntries(allowed.filter(key => Object.hasOwn(status, key)).map(key => [key, status[key]]));
    if (status.error) safe.errorSha256 = hash(String(status.error));
    report.cycles.push({ before, after: snapshot(), plugin: safe });
    if (status.ok !== true) { report.error = "actual_plugin_cycle_failed"; return 3; }
  }
  report.phase = "complete";
  report.authentications = captured.length;
  report.logCounts = logCounts;
  report.ok = true;
  return 0;
}

let code = 2;
try { code = await main(); }
catch (error) { report.error = error.canaryCode ?? "unexpected_consumer_error"; report.errorSha256 = hash(String(error.message)); }
finally {
  if (service) { try { await service.stop(); } catch { report.stopFailed = true; } }
  baoAgent?.destroy();
  report.authentications = captured.length;
  if (config) {
    try { writeExclusive(config.capturePath, { tokens: captured }); } catch { report.captureFailed = true; code = 2; }
    try { writeExclusive(config.receiptPath, report); } catch { report.receiptFailed = true; code = 2; }
  }
}
process.stdout.write(JSON.stringify(report) + "\n");
process.exitCode = code;
