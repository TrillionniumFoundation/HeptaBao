#!/usr/bin/env node
/** Run one unchanged AuthBus plugin cycle with the real installed OpenClaw SDK.
 * All mutable paths are within the driver's new private directory. The caller
 * supplies no provider credential: the plugin must obtain it over real HTTPS.
 * HTTPS observation keeps tokens only in a private, local custody file.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import https from "node:https";
import path from "node:path";
import { pathToFileURL } from "node:url";

const LIMIT = 1024 * 1024;
const report = { schema: "actual-openclaw-authbus-consumer-v1", ok: false, productionCutover: false, observations: [] };
let service = null;
let config = null;
let captured = [];
let baoAgent = null;
const socketIds = new WeakMap();
let nextSocketId = 1;

function socketId(socket) {
  if (!socketIds.has(socket)) socketIds.set(socket, nextSocketId++);
  return socketIds.get(socket);
}

function fail(code) { const error = new Error(code); error.canaryCode = code; throw error; }
function hash(value) { return crypto.createHash("sha256").update(value).digest("hex"); }
function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]));
}
function digest(value) { return hash(JSON.stringify(stable(value))); }
function privateFile(filename) {
  const s = fs.lstatSync(filename);
  if (!s.isFile() || s.isSymbolicLink() || s.uid !== process.getuid() || (s.mode & 0o077)) fail("private_file_custody_invalid");
  if (s.size > LIMIT) fail("private_file_size_bound");
  return fs.readFileSync(filename);
}
function inside(root, target) {
  const relative = path.relative(root, target);
  return relative !== "" && relative !== ".." && !relative.startsWith(".." + path.sep) && !path.isAbsolute(relative);
}
function ownedDirectory(directory) {
  const s = fs.lstatSync(directory);
  if (!s.isDirectory() || s.isSymbolicLink() || s.uid !== process.getuid() || (s.mode & 0o077)) fail("private_directory_custody_invalid");
}
function writeExclusive(filename, value) {
  const fd = fs.openSync(filename, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
  try {
    fs.writeFileSync(fd, JSON.stringify(value) + "\n");
    fs.fsyncSync(fd);
  } finally { fs.closeSync(fd); }
  const directoryFd = fs.openSync(path.dirname(filename), fs.constants.O_RDONLY | fs.constants.O_DIRECTORY);
  try { fs.fsyncSync(directoryFd); } finally { fs.closeSync(directoryFd); }
}

function probeError(code) {
  return Object.assign(new Error(code), { canaryCode: code });
}

function probeGoogleModels(apiKey) {
  return new Promise((resolve, reject) => {
    let settled = false;
    let timer;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) reject(error); else resolve(value);
    };
    const headers = { Accept: "application/json" };
    if (apiKey !== undefined) headers["x-goog-api-key"] = apiKey;
    const req = https.request({
      hostname: "generativelanguage.googleapis.com", port: 443,
      path: "/v1beta/models?pageSize=1000", method: "GET",
      // The actual main-host control showed Node's default IPv6 timing out,
      // while the same Node with IPv4 and strict TLS returned HTTP 403. This
      // applies only to this metadata probe; hostname, SNI and CA checks stay
      // intact, with no address substitution or alternate verification path.
      family: 4, rejectUnauthorized: true, timeout: 10000, headers,
    }, (response) => {
      const tlsAuthorized = response.socket.authorized === true;
      const chunks = []; let bytes = 0;
      response.on("data", (chunk) => {
        bytes += chunk.length;
        if (bytes > LIMIT) {
          const error = probeError("provider_response_exceeds_bound");
          response.destroy(error); req.destroy(error); finish(error);
          return;
        }
        chunks.push(chunk);
      });
      response.on("error", (error) => finish(error));
      response.on("end", () => {
        try {
          const value = JSON.parse(Buffer.concat(chunks));
          finish(null, {
            httpStatus: response.statusCode, tlsAuthorized,
            addressFamily: 4, absoluteBudgetMs: 10000,
            modelsArray: Array.isArray(value?.models),
            modelCountThisPage: Array.isArray(value?.models) ? value.models.length : 0,
            hasNextPage: Boolean(value?.nextPageToken),
          });
        } catch { finish(probeError("provider_response_invalid_json")); }
      });
    });
    // A socket inactivity timeout does not bound DNS or a slow response that
    // keeps emitting bytes. The same fixed budget covers the entire request.
    timer = setTimeout(() => {
      const error = probeError("provider_metadata_absolute_timeout");
      req.destroy(error); finish(error);
    }, 10000);
    req.on("timeout", () => {
      const error = probeError("provider_metadata_socket_timeout");
      req.destroy(error); finish(error);
    });
    req.on("error", (error) => finish(error));
    req.end();
  });
}

async function main() {
  report.phase = "private_config";
  if (process.argv.length !== 3) fail("usage_requires_private_driver_config");
  config = JSON.parse(privateFile(process.argv[2]));
  if (config.schema !== "actual-openclaw-authbus-driver-v1") fail("config_schema_invalid");
  const root = fs.realpathSync(config.workRoot);
  ownedDirectory(root);
  for (const key of ["stateDir", "agentDir", "runDir", "openclawHome", "oauthDir", "configPath", "pluginEntry", "capturePath", "receiptPath"]) {
    if (!path.isAbsolute(config[key]) || !inside(root, config[key])) fail("mutable_path_outside_private_root");
  }
  for (const key of ["stateDir", "agentDir", "runDir", "openclawHome", "oauthDir"]) ownedDirectory(config[key]);
  for (const key of ["roleIdFile", "secretIdFile", "caFile"]) {
    if (!inside(root, config.pluginConfig[key])) fail("plugin_binding_outside_private_root");
  }
  if (config.pluginConfig.leader !== false || config.pluginConfig.publishNew !== false || config.pluginConfig.manageOrder !== false || config.pluginConfig.schedulerMode !== "shadow") fail("plugin_mode_would_enable_source_mutation");
  const target = new URL(config.pluginConfig.address);
  if (target.protocol !== "https:" || target.hostname !== "127.0.0.1" || !target.port || target.username || target.password) fail("target_must_be_isolated_loopback_https");
  // These are OpenClaw's documented application overrides; HOME is unchanged.
  process.env.OPENCLAW_STATE_DIR = config.stateDir;
  process.env.OPENCLAW_CONFIG_PATH = config.configPath;
  process.env.OPENCLAW_HOME = config.openclawHome;
  process.env.OPENCLAW_OAUTH_DIR = config.oauthDir;
  if (process.env.OPENCLAW_AUTH_STORE_READONLY === "1") fail("inherited_auth_store_readonly");
  report.scope = { stateDir: config.stateDir, externalCliSyncEnabled: false, oauthRefreshEnabled: false, immutablePluginCopy: true };

  // Observe a freshly authenticated leaf on every isolated Bao request. The
  // main-host r8 receipt had valid CA authentication on resumed TLS sessions
  // but no peer raw DER from Node. Do not substitute a previous socket's leaf:
  // disable both connection reuse and session caching in this harness only.
  baoAgent = new https.Agent({ keepAlive: false, maxCachedSessions: 0 });
  report.harnessTransport = {
    isolatedBaoAgent: "fresh_full_tls_handshake_per_request",
    keepAlive: false, maxCachedSessions: 0, productionPluginModified: false,
  };

  const request = https.request;
  https.request = function observedRequest(options, callback) {
    if (!options || typeof options !== "object" || options instanceof URL) fail("unexpected_https_request_shape");
    const hostname = options.hostname || options.host;
    const isBao = hostname === target.hostname && String(options.port || 443) === target.port;
    const isModels = hostname === "generativelanguage.googleapis.com" && options.method === "GET" && options.path === "/v1beta/models?pageSize=1000";
    if (!isBao && !isModels) fail("unexpected_network_destination");
    if (isBao && options.rejectUnauthorized !== true) fail("bao_tls_verification_disabled");
    const observation = { service: isBao ? "isolated_heptabao" : "google_models", method: options.method, path: options.path };
    report.observations.push(observation);
    const outgoing = request.call(https, isBao ? { ...options, agent: baoAgent } : options, (response) => {
      observation.status = response.statusCode;
      observation.tlsAuthorized = response.socket.authorized === true;
      observation.tlsVersion = response.socket.getProtocol?.() ?? null;
      observation.socketId = socketId(response.socket);
      observation.isSessionReused = response.socket.isSessionReused?.() ?? null;
      const certificate = response.socket.getPeerCertificate?.();
      observation.peerCertificateSha256 = certificate?.raw ? hash(certificate.raw) : null;
      if (isBao && options.path === "/v1/auth/approle/login") {
        let length = 0;
        const chunks = [];
        response.on("data", (chunk) => {
          length += chunk.length;
          if (length <= LIMIT) chunks.push(chunk);
        });
        response.on("end", () => {
          if (length > LIMIT) return;
          try {
            const body = JSON.parse(Buffer.concat(chunks));
            const auth = body?.auth;
            if (response.statusCode === 200 && typeof auth?.client_token === "string") {
              captured.push({ token: auth.client_token, accessor: auth.accessor ?? null, lease_duration: auth.lease_duration, renewable: auth.renewable });
              observation.tokenSha256 = hash(auth.client_token);
              observation.leaseDuration = auth.lease_duration;
              observation.renewable = auth.renewable;
            }
          } catch { /* The unchanged plugin reports malformed JSON itself. */ }
        });
      }
      callback(response);
    });
    outgoing.on("socket", (socket) => {
      observation.requestSocketId = socketId(socket);
    });
    return outgoing;
  };

  // The only imports with application behavior occur after paths are scoped.
  report.phase = "actual_sdk_import";
  const sdk = await import(pathToFileURL(path.join(config.openclawRoot, "dist/plugin-sdk/agent-runtime.js")).href);
  const defaultDir = path.resolve(sdk.resolveDefaultAgentDir({}));
  if (defaultDir !== path.resolve(config.agentDir)) fail("sdk_default_main_store_not_scoped");
  const dbPath = path.resolve(sdk.resolveAuthStorePathForDisplay(config.agentDir));
  if (dbPath !== path.join(config.agentDir, "openclaw-agent.sqlite")) fail("sdk_database_path_not_scoped");
  report.scope.defaultAgentDirScoped = true;
  report.scope.databasePath = dbPath;
  report.sdkVersion = JSON.parse(fs.readFileSync(path.join(config.openclawRoot, "package.json"), "utf8")).version;
  report.providerCanonical = sdk.resolveProviderIdForAuth(config.expectedProvider);
  if (report.providerCanonical !== config.expectedProvider) fail("provider_not_canonical");

  report.phase = "actual_sdk_initialize";
  if (!fs.existsSync(dbPath)) {
    sdk.saveAuthProfileStore({ version: 1, profiles: {} }, config.agentDir, { filterExternalAuthProfiles: false, syncExternalCli: false });
    if (!fs.existsSync(dbPath)) fail("actual_sdk_database_creation_failed");
    report.createdDatabaseThroughActualSdk = true;
  }
  const before = sdk.loadAuthProfileStoreWithoutExternalProfiles(config.agentDir, { allowKeychainPrompt: false });
  const initialProfiles = Object.entries(before.profiles ?? {});
  if (initialProfiles.some(([id]) => id !== config.expectedProfileId)) fail("unexpected_external_profile_mixed_into_isolated_store");
  report.profileCountBefore = initialProfiles.length;
  const clients = globalThis[Symbol.for("openclaw.codexAppServerClientState")];
  if (clients?.clients?.size) fail("isolated_process_has_unexpected_codex_clients");

  report.phase = "actual_plugin_import";
  const plugin = (await import(pathToFileURL(config.pluginEntry).href)).default;
  if (plugin?.id !== "openclaw-authbus" || typeof plugin.register !== "function") fail("actual_plugin_export_mismatch");
  let subscriptions = 0;
  plugin.register({
    registrationMode: "full", pluginConfig: config.pluginConfig,
    agent: { events: { registerAgentEventSubscription() { subscriptions += 1; } } },
    registerService(value) { if (service) fail("unexpected_multiple_plugin_services"); service = value; },
  });
  if (subscriptions !== 1 || service?.id !== "openclaw-authbus") fail("actual_plugin_registration_mismatch");
  const logCounts = { info: 0, warn: 0, error: 0, debug: 0 };
  const logger = Object.fromEntries(Object.keys(logCounts).map((level) => [level, () => { logCounts[level] += 1; }]));
  report.phase = "actual_plugin_cycle";
  await service.start({ stateDir: config.stateDir, logger, config: {} });
  await service.stop();
  service = null;
  const status = JSON.parse(fs.readFileSync(path.join(config.stateDir, "authbus/status.json"), "utf8"));
  report.plugin = {
    ok: status.ok === true, manifestGeneration: status.manifestGeneration ?? null,
    manifestProfiles: status.manifestProfiles ?? null, importedProfiles: status.importedProfiles ?? null,
    agentStores: status.agentStores ?? null, verifiedStores: status.verifiedStores ?? null,
    effectiveMissing: status.effectiveMissing ?? null, effectiveMismatched: status.effectiveMismatched ?? null,
    schedulerReports: status.schedulerReports ?? null, pendingRuntimeRefreshes: status.pendingRuntimeRefreshes ?? null,
    logCounts, errorSha256: status.error ? hash(String(status.error)) : null,
  };
  report.phase = "actual_sdk_readback";
  sdk.clearRuntimeAuthProfileStoreSnapshots();
  const after = sdk.loadAuthProfileStoreWithoutExternalProfiles(config.agentDir, { allowKeychainPrompt: false });
  const entries = Object.entries(after.profiles ?? {});
  report.profileCountAfter = entries.length;
  if (entries.some(([id]) => id !== config.expectedProfileId)) fail("unexpected_external_profile_after_cycle");
  const credential = after.profiles?.[config.expectedProfileId];
  report.credentialDigest = credential ? digest(credential) : null;
  report.actualSdkReadbackMatches = report.credentialDigest === config.expectedDigest;
  report.authentications = captured.length;
  writeExclusive(config.capturePath, { schema: "isolated-plugin-auth-custody-v1", tokens: captured });
  captured = [];
  if (!report.plugin.ok) {
    report.error = "actual_plugin_cycle_failed";
    return 3;
  }
  if (entries.length !== 1 || !report.actualSdkReadbackMatches || status.effectiveMissing || status.effectiveMismatched) fail("actual_plugin_effective_store_mismatch");
  if (credential.provider !== config.expectedProvider || credential.type !== "api_key") fail("expected_real_google_api_key_not_received");

  if (config.verifyProvider === true) {
    report.phase = "official_provider_readback_verification";
    report.providerControl = await probeGoogleModels();
    if (report.providerControl.httpStatus !== 403 || report.providerControl.modelsArray || !report.providerControl.tlsAuthorized) fail("official_provider_no_key_control_failed");
    report.providerProbe = await probeGoogleModels(credential.key);
    if (report.providerProbe.httpStatus !== 200 || !report.providerProbe.modelsArray || !report.providerProbe.tlsAuthorized) fail("actual_sdk_readback_key_not_verified_by_provider");
  }
  report.ok = true;
  report.phase = "complete";
  return 0;
}

let code = 2;
try { code = await main(); }
catch (error) {
  report.error = "consumer_failed";
  report.errorCodeSha256 = hash(error instanceof Error ? error.message : String(error));
  report.errorClass = error?.constructor?.name ?? "unknown";
  report.diagnosticCode = error?.canaryCode ?? (/^[A-Z_0-9]{1,80}$/.test(error?.code ?? "") ? error.code : null);
} finally {
  if (service) { try { await service.stop(); } catch { report.stopFailed = true; } }
  baoAgent?.destroy();
  if (config && captured.length && !fs.existsSync(config.capturePath)) {
    try { writeExclusive(config.capturePath, { schema: "isolated-plugin-auth-custody-v1", tokens: captured }); } catch { report.capturePersistenceFailed = true; }
  }
  if (config && !fs.existsSync(config.receiptPath)) {
    try { writeExclusive(config.receiptPath, report); } catch { report.receiptPersistenceFailed = true; code = 2; }
  }
}
process.stdout.write(JSON.stringify(report) + "\n");
process.exitCode = code;
