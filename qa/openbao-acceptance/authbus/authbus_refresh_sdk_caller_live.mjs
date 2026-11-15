#!/usr/bin/env node
/** Actual installed SDK / actual SQLite / actual loopback HTTPS refresh runner.
 * Credentials and provider responses are synthetic. The TLS control endpoint
 * is an fsynced KV2 emulator, not a native HeptaBao qualification. No installed
 * SDK file, existing auth store, real provider or production service is changed. */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import net from "node:net";
import dns from "node:dns";
import https from "node:https";
import childProcess from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";
import { digest } from "./authbus_admission_authority_candidate.mjs";
import { TrustedAdmissionAuthority, applyFromTrustedControl } from "./authbus_trusted_admission_candidate.mjs";
import { TrustedBaoControlSource, TrustedBaoCoordinator } from "./authbus_trusted_control_candidate.mjs";
import { SdkOAuthRefreshAdmissionRegistry } from "./authbus_refresh_sdk_registry_candidate.mjs";
import { installOAuthRefreshSdkCandidate, verifyOAuthRefreshSdkUnchanged } from "./authbus_refresh_sdk_candidate.mjs";

const fail = code => { throw Object.assign(new Error(code), { diagnosticCode: code }); };
const hash = value => crypto.createHash("sha256").update(value).digest("hex");
function selectOwnedSdkEntrypoint(sdkRoot) {
  const readSource = file => {
    const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    try {
      const before = fs.fstatSync(fd);
      if (!before.isFile() || before.size < 1 || before.size > 262144)
        fail("trusted_refresh_caller_sdk_discovery_file_invalid");
      const bytes = Buffer.alloc(before.size + 1);
      let length = 0;
      while (length < bytes.length) {
        const count = fs.readSync(fd, bytes, length, bytes.length - length, length);
        if (!count) break;
        length += count;
      }
      const after = fs.fstatSync(fd);
      if (length !== before.size || before.dev !== after.dev || before.ino !== after.ino ||
          before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs)
        fail("trusted_refresh_caller_sdk_discovery_file_changed");
      return bytes.subarray(0, length);
    } finally { fs.closeSync(fd); }
  };
  const packageBytes = readSource(path.join(sdkRoot, "package.json"));
  const pkg = JSON.parse(packageBytes.toString("utf8"));
  const bin = pkg.bin?.openclaw;
  if (pkg.name !== "openclaw" || pkg.version !== "2026.7.1-2" || typeof bin !== "string" ||
      !bin || path.isAbsolute(bin) || bin.includes("\\") || bin.split("/").includes(".."))
    fail("trusted_refresh_caller_sdk_discovery_package_invalid");
  const entrypoint = path.resolve(sdkRoot, bin);
  if (!entrypoint.startsWith(sdkRoot + path.sep)) fail("trusted_refresh_caller_sdk_discovery_entrypoint_outside");
  let component = sdkRoot;
  for (const part of path.relative(sdkRoot, entrypoint).split(path.sep)) {
    component = path.join(component, part);
    if (fs.lstatSync(component).isSymbolicLink()) fail("trusted_refresh_caller_sdk_discovery_symlink_forbidden");
  }
  const entryBytes = readSource(entrypoint);
  return Object.freeze({ entrypoint, relative: path.relative(sdkRoot, entrypoint),
    packageSha256: hash(packageBytes), entrypointSha256: hash(entryBytes) });
}
const args = {};
for (let i = 2; i < process.argv.length; i += 2) {
  if (!["--openclaw-root", "--work-dir"].includes(process.argv[i]) || !path.isAbsolute(process.argv[i + 1] ?? "") || args[process.argv[i]])
    fail("trusted_refresh_caller_absolute_cli_required");
  args[process.argv[i]] = path.resolve(process.argv[i + 1]);
}
if (!args["--openclaw-root"] || !args["--work-dir"]) fail("trusted_refresh_caller_missing_cli_argument");
process.umask(0o077);
const root = args["--work-dir"], sdkRoot = fs.realpathSync(args["--openclaw-root"]);
const here = path.dirname(fileURLToPath(import.meta.url)), hostHomeDirectory = os.homedir();
fs.mkdirSync(root, { mode: 0o700 });
const state = path.join(root, "state"), mainAgent = path.join(state, "agents/main/agent");
for (const dir of [state, path.join(state, "agents"), path.join(state, "agents/main"), mainAgent,
  path.join(state, "home"), path.join(state, "credentials")]) fs.mkdirSync(dir, { mode: 0o700 });
const cfgPath = path.join(state, "openclaw.json");
const cfg = { agents: { list: [{ id: "main", default: true, agentDir: mainAgent }] } };
fs.writeFileSync(cfgPath, JSON.stringify(cfg) + "\n", { mode: 0o600 });
process.env.OPENCLAW_STATE_DIR = state;
process.env.OPENCLAW_CONFIG_PATH = cfgPath;
process.env.OPENCLAW_HOME = path.join(state, "home");
process.env.OPENCLAW_OAUTH_DIR = path.join(state, "credentials");
for (const key of ["GOOGLE_API_KEY", "GEMINI_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "OPENCLAW_GATEWAY_TOKEN",
  "CHUTES_CLIENT_ID", "CHUTES_CLIENT_SECRET", "OPENCLAW_BUNDLED_PLUGINS_DIR", "OPENCLAW_TEST_TRUST_BUNDLED_PLUGINS_DIR"])
  delete process.env[key];
// The SDK still validates this package-local plugin override itself. Its other
// package discovery paths also inspect argv[1] and cwd; below, the isolated
// process supplies the package and its verified bin as discovery context.
// The test-only trust override remains absent and the home guard stays closed.
process.env.OPENCLAW_BUNDLED_PLUGINS_DIR = path.join(sdkRoot, "dist/extensions");
if (process.env.OPENCLAW_AUTH_STORE_READONLY === "1") fail("trusted_refresh_caller_inherited_readonly_store");
const keyFile = path.join(root, "fixture.key"), certFile = path.join(root, "fixture.crt");
childProcess.execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", keyFile,
  "-out", certFile, "-days", "1", "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1"], { stdio: "ignore" });
const certificate = fs.readFileSync(certFile), serverKey = fs.readFileSync(keyFile);
const report = { schema: "authbus-refresh-r5-actual-sdk-caller", ok: false,
  syntheticCredentials: true, syntheticProvider: true, tlsControlEmulator: true,
  actualSdk: false, actualSqlite: false, actualSdkOAuthManager: false, actualProviderHttps: false,
  actualNativeHeptaBao: false, actualColdSdkProcess: false, productionMutation: false,
  bundledPluginDiscovery: "sdk-production-validated-override-and-package-bin-argv-cwd",
  ownedCertificateGenerationProcesses: 1, externalNetworkAttempts: 0, externalProcessAttempts: 0,
  outsideFixtureWriteAttempts: 0, outsideFixtureHomeReadAttempts: 0, blockedHomeReads: [], ownerReader: "exact-sdk-persisted-local", checks: [], cases: [],
  sourceManifest: ["authbus_refresh_sdk_caller_live.mjs", "authbus_refresh_sdk_candidate.mjs", "authbus_refresh_sdk_registry_candidate.mjs",
    "authbus_refresh_store_sdk_candidate.mjs", "authbus_refresh_registry_candidate.mjs", "authbus_trusted_control_candidate.mjs",
    "authbus_trusted_admission_candidate.mjs", "authbus_admission_authority_candidate.mjs", "authbus_admission_registry_candidate.mjs",
    "authbus_dispatch_registry_candidate.mjs", "authbus_dispatch_sdk_candidate.mjs", "authbus_sdk_admission_candidate.mjs",
    "authbus_sdk_explicit_deny_candidate.mjs"].map(name => ({ name, sha256: hash(fs.readFileSync(path.join(here, name))) })) };
const check = (name, passed) => { report.checks.push({ case: name, passed: Boolean(passed) }); if (!passed) fail(name); };
const inside = (candidate, directory) => candidate === directory || candidate.startsWith(directory + path.sep);
const asPath = value => value instanceof URL ? fileURLToPath(value) : Buffer.isBuffer(value) ? value.toString("utf8") : typeof value === "string" ? value : null;
const checkWrite = value => {
  const decoded = asPath(value); if (decoded === null) return;
  const absolute = path.resolve(decoded);
  if (!inside(absolute, root)) { report.outsideFixtureWriteAttempts++; fail("trusted_refresh_caller_outside_write_forbidden"); }
  let current = root;
  for (const part of path.relative(root, absolute).split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    try { if (fs.lstatSync(current).isSymbolicLink()) { report.outsideFixtureWriteAttempts++; fail("trusted_refresh_caller_symlink_write_forbidden"); } }
    catch (error) { if (error.code === "ENOENT") break; throw error; }
  }
};
let diagnosticPhase = "guard-install";
const diagnosticPathClass = absolute => {
  const filename = path.basename(absolute);
  const knownNames = new Set(["package.json", "openclaw.json", "auth-profiles.json", "auth.json", "credentials.json", ".credentials.json", "openclaw-agent.sqlite"]);
  let parent = sdkRoot;
  for (let depth = 0; depth < 10; depth++, parent = path.dirname(parent))
    if (absolute === path.join(parent, "package.json")) return "sdk-ancestor-package-json:" + depth;
  return knownNames.has(filename) ? "outside-known-file:" + filename : /\.(m?js|cjs|ts)$/.test(filename) ? "outside-source-file" : "outside-other-file";
};
const checkRead = value => {
  const decoded = asPath(value); if (decoded === null) return;
  const absolute = path.resolve(decoded);
  if (inside(absolute, hostHomeDirectory) && !inside(absolute, root) && !inside(absolute, sdkRoot)) {
    report.outsideFixtureHomeReadAttempts++;
    if (report.blockedHomeReads.length < 24) report.blockedHomeReads.push({ phase: diagnosticPhase,
      targetSha256: hash(absolute), targetClass: diagnosticPathClass(absolute),
      sdkFrames: String(new Error("owned-read-guard").stack).split("\n").filter(line => line.includes(sdkRoot + path.sep))
        .slice(0, 8).map(line => line.slice(line.indexOf(sdkRoot) + sdkRoot.length + 1).slice(0, 240)) });
    fail("trusted_refresh_caller_external_home_read_forbidden");
  }
};
const restores = [];
const guard = (object, name, inspect) => {
  const previous = object[name]; if (typeof previous !== "function") return;
  restores.push(() => { object[name] = previous; });
  object[name] = function (...values) { inspect(values); return previous.apply(this, values); };
};
const isWrite = flags => typeof flags === "string" ? /[wa+]/.test(flags) : Number.isInteger(flags) &&
  Boolean(flags & (fs.constants.O_WRONLY | fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_TRUNC | fs.constants.O_APPEND));
function durable(file, value) {
  const temporary = file + ".new-" + crypto.randomUUID();
  const fd = fs.openSync(temporary, "wx", 0o600);
  try { fs.writeFileSync(fd, JSON.stringify(value)); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  fs.renameSync(temporary, file);
  const directory = fs.openSync(path.dirname(file), "r");
  try { fs.fsyncSync(directory); } finally { fs.closeSync(directory); }
}
const reply = (response, status, value) => {
  response.writeHead(status, { "content-type": "application/json" });
  response.end(value === undefined ? undefined : JSON.stringify(value));
};
const cells = new Map(), tokens = new Map();
let hook, control, provider, active, sdk, bridge, oauth, oauthLib, chutes, runtime, database, sdkSource, sdkCredentialState;
let activeUninstall, currentSource, currentCoordinator;
const allowedPorts = new Set();
const previousFetch = globalThis.fetch;
const previousArgvEntrypoint = process.argv[1];
const previousWorkingDirectory = process.cwd();
let sdkDiscovery;
async function boundedBody(request, max = 65536) {
  const chunks = []; let size = 0;
  for await (const chunk of request) { size += chunk.length; if (size > max) fail("fixture_http_body_excessive"); chunks.push(chunk); }
  return Buffer.concat(chunks).toString("utf8");
}
async function expectFailure(name, action) {
  let error;
  try { await action(); } catch (caught) { error = caught; }
  check(name, Boolean(error));
  return error?.diagnosticCode ?? error?.code ?? "sdk_refused";
}
try {
  control = https.createServer({ key: serverKey, cert: certificate }, async (request, response) => {
    try {
      const raw = await boundedBody(request), body = raw ? JSON.parse(raw) : null;
      if (request.url === "/v1/auth/approle/login") {
        if (!["reader", "issuer"].includes(body?.role_id) || body.secret_id !== "synthetic-" + body.role_id) return reply(response, 403, {});
        const token = crypto.randomUUID(); tokens.set(token, body.role_id);
        return reply(response, 200, { auth: { client_token: token, lease_duration: 300 } });
      }
      const role = tokens.get(request.headers["x-vault-token"]);
      if (!role) return reply(response, 403, {});
      if (request.url === "/v1/auth/token/revoke-self") { tokens.delete(request.headers["x-vault-token"]); return reply(response, 204); }
      if (request.url === "/v1/auth/token/lookup-self") return reply(response, 200, { data: {} });
      const cell = cells.get(request.url);
      if (!cell) return reply(response, 404, {});
      const stored = fs.existsSync(cell.controlFile) ? JSON.parse(fs.readFileSync(cell.controlFile)) : { version: 0, document: null };
      if (request.method === "GET") return stored.document ? reply(response, 200, { data: { data: stored.document,
        metadata: { version: stored.version, destroyed: false, deletion_time: "" } } }) : reply(response, 404, {});
      if (role !== "issuer" || request.method !== "POST") return reply(response, 403, {});
      if (body?.options?.cas !== stored.version) return reply(response, 400, {});
      const previous = stored.document?.refreshAttempts?.at(-1), next = body.data.refreshAttempts?.at(-1);
      const starting = next?.status === "UNKNOWN" && previous?.status !== "UNKNOWN";
      durable(cell.controlFile, { version: stored.version + 1, document: body.data });
      if (starting && cell.scenario === "intent-ack-lost") return response.destroy();
      return reply(response, 200, { data: { version: stored.version + 1 } });
    } catch { reply(response, 500, {}); }
  });
  provider = https.createServer({ key: serverKey, cert: certificate }, async (request, response) => {
    try {
      const cell = active;
      if (!cell) return reply(response, 409, {});
      const body = await boundedBody(request), document = JSON.parse(fs.readFileSync(cell.controlFile)).document;
      const attempt = document.refreshAttempts?.at(-1);
      if (attempt?.status !== "UNKNOWN" || document.assignments?.[0]?.status !== "REFRESH_PENDING") return reply(response, 409, {});
      const data = request.headers["content-type"]?.startsWith("application/json") ? JSON.parse(body) : Object.fromEntries(new URLSearchParams(body));
      if (request.url !== "/v1/oauth/token" || request.method !== "POST" || data.grant_type !== "refresh_token" || data.refresh_token !== cell.original.refresh)
        return reply(response, 400, {});
      cell.providerCount++;
      cell.unknownObservedAtProvider++;
      durable(cell.providerFile, { count: cell.providerCount, unknownObserved: cell.unknownObservedAtProvider });
      if (cell.scenario === "provider-ack-lost") return response.destroy();
      return reply(response, 200, { access_token: "synthetic-new-access-" + cell.scenario,
        refresh_token: "synthetic-new-refresh-" + cell.scenario, expires_in: 900 });
    } catch { reply(response, 500, {}); }
  });
  await Promise.all([new Promise(resolve => control.listen(0, "127.0.0.1", resolve)), new Promise(resolve => provider.listen(0, "127.0.0.1", resolve))]);
  allowedPorts.add(control.address().port); allowedPorts.add(provider.address().port);
  guard(net.Socket.prototype, "connect", values => {
    const args = Array.isArray(values[0]) ? values[0] : values;
    const first = args[0];
    const port = Number(typeof first === "object" && first ? first.port : first);
    const host = typeof first === "object" && first ? first.host ?? first.hostname : typeof args[1] === "string" ? args[1] : "localhost";
    if (host !== "127.0.0.1" || !allowedPorts.has(port)) { report.externalNetworkAttempts++; fail("trusted_refresh_caller_external_network_forbidden"); }
  });
  for (const name of ["lookup", "resolve", "resolve4", "resolve6", "resolveAny", "resolveCname", "resolveMx", "resolveTxt", "reverse"])
    for (const object of [dns, dns.promises]) guard(object, name, values => {
      if (values[0] !== "127.0.0.1") { report.externalNetworkAttempts++; fail("trusted_refresh_caller_external_dns_forbidden"); }
    });
  for (const name of ["spawn", "spawnSync", "exec", "execSync", "execFile", "execFileSync", "fork"])
    guard(childProcess, name, () => { report.externalProcessAttempts++; fail("trusted_refresh_caller_external_process_forbidden"); });
  for (const object of [fs, fs.promises]) {
    for (const name of ["writeFile", "writeFileSync", "appendFile", "appendFileSync", "mkdir", "mkdirSync", "mkdtemp", "mkdtempSync",
      "unlink", "unlinkSync", "rm", "rmSync", "rmdir", "rmdirSync", "truncate", "truncateSync", "chmod", "chmodSync", "chown", "chownSync", "createWriteStream"])
      guard(object, name, values => checkWrite(values[0]));
    for (const name of ["symlink", "symlinkSync"]) guard(object, name, values => {
      checkWrite(values[1]); checkWrite(path.resolve(path.dirname(asPath(values[1])), asPath(values[0])));
    });
    for (const name of ["rename", "renameSync", "link", "linkSync"]) guard(object, name, values => { checkWrite(values[0]); checkWrite(values[1]); });
    for (const name of ["copyFile", "copyFileSync", "cp", "cpSync"]) guard(object, name, values => { checkRead(values[0]); checkWrite(values[1]); });
    for (const name of ["open", "openSync"]) guard(object, name, values => isWrite(values[1]) ? checkWrite(values[0]) : checkRead(values[0]));
    for (const name of ["readFile", "readFileSync", "createReadStream"]) guard(object, name, values => checkRead(values[0]));
  }
  syncBuiltinESMExports();
  // This is the fixture's sole provider transport. The SDK still constructs
  // its real token URL/body; only the destination is mapped to owned TLS.
  globalThis.fetch = (url, init = {}) => {
    if (String(url) !== "https://platform.claude.com/v1/oauth/token" || init.redirect !== "error") {
      report.externalNetworkAttempts++; fail("trusted_refresh_caller_unmapped_provider_request");
    }
    return new Promise((resolve, reject) => {
      const request = https.request({ hostname: "127.0.0.1", port: provider.address().port, path: "/v1/oauth/token",
        method: init.method, headers: Object.fromEntries(new Headers(init.headers)), ca: certificate, signal: init.signal }, response => {
        const chunks = []; let size = 0;
        response.on("data", chunk => { size += chunk.length; if (size > 65536) response.destroy(); else chunks.push(chunk); });
        response.on("error", reject);
        response.on("end", () => resolve(new Response(Buffer.concat(chunks), { status: response.statusCode,
          headers: Object.fromEntries(Object.entries(response.headers).filter(([, value]) => typeof value === "string")) })));
      });
      request.on("error", reject); if (init.body) request.write(String(init.body)); request.end();
    });
  };
  diagnosticPhase = "sdk-import";
  sdkDiscovery = selectOwnedSdkEntrypoint(sdkRoot);
  // This does not execute the SDK CLI or change the QA module being imported.
  // It makes SDK package-root discovery use the actual declared package bin,
  // instead of treating this external fixture script as the SDK entrypoint.
  process.argv[1] = sdkDiscovery.entrypoint;
  process.chdir(sdkRoot);
  report.sdkDiscoveryContext = { relative: sdkDiscovery.relative,
    packageSha256: sdkDiscovery.packageSha256, entrypointSha256: sdkDiscovery.entrypointSha256,
    fixtureArgvAndCwdOnly: true, cwdIsSelectedSdkRoot: process.cwd() === sdkRoot, entrypointExecuted: false };
  hook = installOAuthRefreshSdkCandidate(sdkRoot, report);
  report.qualification = await hook.loadOwnedRefreshFunctions();
  sdk = await import(pathToFileURL(path.join(sdkRoot, "dist/plugin-sdk/agent-runtime.js")).href);
  bridge = await import(pathToFileURL(path.join(sdkRoot, "dist/profiles-DyU-YCq2.js")).href);
  oauth = await import(pathToFileURL(path.join(sdkRoot, "dist/oauth-B4aOCsid.js")).href);
  oauthLib = await import(pathToFileURL(path.join(sdkRoot, "dist/oauth-BcZS_BvC.js")).href);
  chutes = await import(pathToFileURL(path.join(sdkRoot, "dist/chutes-oauth-YFvuN1-a.js")).href);
  runtime = await import(pathToFileURL(path.join(sdkRoot, "dist/provider-runtime.runtime--yRUs3av.js")).href);
  sdkSource = await import(pathToFileURL(path.join(sdkRoot, "dist/source-check-ZSz5NzGW.js")).href);
  sdkCredentialState = await import(pathToFileURL(path.join(sdkRoot, "dist/credential-state-BY-oz-QV.js")).href);
  check("actual_sdk_required_interfaces", typeof oauth.n === "function" && typeof oauth.t === "function" &&
    typeof oauthLib.t === "function" && typeof bridge.heptaBaoCommitManagedOAuthCredential === "function" &&
    typeof sdk.resolveProviderIdForAuth === "function" && typeof sdk.loadAuthProfileStoreWithoutExternalProfiles === "function" &&
    typeof sdkSource.v === "function" && sdkCredentialState.t === 300000);
  report.sdkOAuthRefreshMarginMs = sdkCredentialState.t;
  report.actualSdk = true;
  report.sdkVersion = JSON.parse(fs.readFileSync(path.join(sdkRoot, "package.json"))).version;
  const readStore = hook.qualification.readOwnedStore;
  const writeStore = (agentDir, profiles, profileId, providerId) => sdk.saveAuthProfileStore({ version: 1, profiles,
    order: { [providerId]: [profileId] }, lastGood: { [providerId]: profileId } }, agentDir,
    { filterExternalAuthProfiles: false, syncExternalCli: false });
  const scenarios = ["usable-own-store", "manager-success", "intent-ack-lost", "provider-ack-lost", "sqlite-abort",
    "sdk-change-before-send", "local-fence-change", "duplicate-final-send", "late-after-rejection", "original-deadline", "cross-provider-entry"];
  for (const scenario of scenarios) {
    const cellRoot = path.join(root, scenario); fs.mkdirSync(cellRoot, { mode: 0o700 });
    const agentDir = path.join(cellRoot, "agent"), directory = path.join(cellRoot, "authority");
    fs.mkdirSync(agentDir, { mode: 0o700 }); fs.mkdirSync(directory, { mode: 0o700 });
    const providerId = sdk.resolveProviderIdForAuth("anthropic", { config: cfg }), profileId = "anthropic:authbus-r5-" + scenario;
    const original = { type: "oauth", provider: "anthropic", access: "synthetic-old-access-" + scenario,
      refresh: "synthetic-old-refresh-" + scenario,
      // This fixture is usable according to the actual SDK's 5-minute refresh
      // margin. The independent 10-second authority/refresh lease is unchanged.
      expires: scenario === "usable-own-store" ? Date.now() + sdkCredentialState.t + 60000 : 1 };
    check(scenario + ":actual_sdk_fixture_expiry_classification", sdkSource.v(original) === (scenario === "usable-own-store"));
    const main = { ...original, access: "synthetic-main-access-" + scenario, refresh: "synthetic-main-refresh-" + scenario, expires: Date.now() + 3600000 };
    // Establish a real local owner before adding the deliberately newer main
    // copy. The SDK otherwise classifies a pristine older seed as inherited.
    diagnosticPhase = scenario + ":scoped-seed";
    writeStore(agentDir, { [profileId]: original }, profileId, providerId);
    diagnosticPhase = scenario + ":main-seed";
    writeStore(mainAgent, { [profileId]: main }, profileId, providerId);
    diagnosticPhase = scenario + ":owner-read";
    check(scenario + ":actual_sqlite_seed", fs.existsSync(path.join(agentDir, "openclaw-agent.sqlite")) && digest(readStore(agentDir).profiles[profileId]) === digest(original));
    report.actualSqlite = true;
    for (const role of ["reader", "issuer"]) {
      fs.writeFileSync(path.join(cellRoot, role + ".role"), role, { mode: 0o600 });
      fs.writeFileSync(path.join(cellRoot, role + ".secret"), "synthetic-" + role, { mode: 0o600 });
    }
    const config = { schemaVersion: 1, address: "https://127.0.0.1:" + control.address().port, caFile: certFile,
      kvMount: "authbus", controlPath: scenario, issuerId: "r5-sdk-owned-fixture", maxLeaseMs: 30000,
      ...Object.fromEntries(["reader", "issuer"].map(role => [role, { roleIdFile: path.join(cellRoot, role + ".role"), secretIdFile: path.join(cellRoot, role + ".secret") }])) };
    const scope = { hostId: "sdk-r5-fixture", agentId: scenario, agentDir, provider: providerId };
    const binding = { scope, model: "synthetic-r5-model", profileId, credentialDigest: digest(original) };
    const cell = { scenario, original, providerCount: 0, unknownObservedAtProvider: 0,
      controlFile: path.join(cellRoot, "control.json"), providerFile: path.join(cellRoot, "provider-count.json") };
    cells.set("/v1/authbus/data/" + scenario, cell); active = cell;
    diagnosticPhase = scenario + ":trusted-bootstrap";
    currentSource = new TrustedBaoControlSource(config);
    currentCoordinator = new TrustedBaoCoordinator(config, { bindings: [binding] });
    const authority = new TrustedAdmissionAuthority({ directory, scope, controlSource: currentSource });
    const registry = new SdkOAuthRefreshAdmissionRegistry({ authorities: [authority],
      resolveDefaultAgentDir: () => mainAgent, resolveProviderIdForAuth: sdk.resolveProviderIdForAuth, readStore,
      sdkRefreshQualification: hook.qualification,
      refreshBindings: [{ scope, controlSource: currentSource, coordinator: currentCoordinator,
        commitCredential: bridge.heptaBaoCommitManagedOAuthCredential, leaseMs: 10000 }] });
    activeUninstall = registry.install();
    const request = currentSource.bootstrapRequest(scope, binding);
    await currentCoordinator.issue(request, { leaseMs: 10000 });
    await applyFromTrustedControl({ authority, controlSource: currentSource, updateStore: () => true,
      verifyStore: grant => grant.digest === digest(readStore(agentDir).profiles[profileId]) });
    check(scenario + ":trusted_initial_admission", authority.inspect().allowed);
    const params = { cfg, store: readStore(agentDir), agentDir, profileId, credential: original };
    const oldPermit = authority.inspect(), before = digest(readStore(agentDir));
    diagnosticPhase = scenario + ":actual-caller";
    const actualRawRefresh = credential => oauthLib.n("anthropic").refreshToken(credential);
    if (scenario === "usable-own-store") {
      const resolved = await oauth.n(params);
      const after = readStore(agentDir);
      report.usableOwnerObservation = {
        resultPresent: Boolean(resolved), apiKeyType: typeof resolved?.apiKey,
        apiKeyMatchesScoped: resolved?.apiKey === original.access,
        apiKeyMatchesMain: resolved?.apiKey === main.access,
        resultCredentialMatchesScoped: digest(resolved?.credential ?? null) === digest(original),
        storedCredentialMatchesScoped: digest(after.profiles?.[profileId] ?? null) === digest(original),
        storeUnchanged: digest(after) === before,
        providerCount: cell.providerCount,
        oauthSdkObservations: { ...registry.oauthSdkObservations },
        refreshObservations: { ...registry.refreshObservations },
      };
      check("usable:actual_sdk_uses_scoped_credential", resolved?.apiKey === original.access && digest(after) === before);
      check("usable:no_provider_or_main_store_adoption", cell.providerCount === 0 && registry.oauthSdkObservations.usableResolutions === 1);
      await expectFailure("entry:runtime_without_private_context_denied", () => oauth.t({ credential: original }));
      await expectFailure("entry:provider_library_without_private_context_denied", () => oauthLib.t("anthropic", { anthropic: original }));
      await expectFailure("entry:raw_builtin_without_private_context_denied", () => actualRawRefresh(original));
      await expectFailure("entry:plugin_facade_without_private_context_denied", () => runtime.o({ provider: "anthropic", context: original }));
      check("entry:no_unowned_refresh_side_effect", cell.providerCount === 0 && JSON.parse(fs.readFileSync(cell.controlFile)).document.refreshAttempts.length === 0);
    } else if (scenario === "manager-success") {
      const resolved = await oauth.n(params), stored = readStore(agentDir).profiles[profileId];
      check("manager:actual_sdk_returns_new_credential", resolved?.apiKey === stored.access && stored.access !== original.access && stored.refresh !== original.refresh);
      const document = JSON.parse(fs.readFileSync(cell.controlFile)).document, attempt = document.refreshAttempts.at(-1);
      check("manager:actual_https_once_after_durable_unknown", cell.providerCount === 1 && cell.unknownObservedAtProvider === 1);
      check("manager:actual_sdk_write_precedes_published_grant", attempt.status === "PUBLISHED" && attempt.sdkVerified &&
        attempt.publishedDigest === digest(stored) && authority.inspect().epoch > attempt.publishedEpoch && attempt.publishedEpoch > oldPermit.epoch);
      registry.advanceAfterRefresh(params, oldPermit, profileId, resolved.apiKey);
      await expectFailure("manager:old_wire_cannot_use_successor", () => registry.advanceAfterRefresh(params, oldPermit, profileId, original.access));
      await expectFailure("manager:successor_without_scope_denied", () => registry.advanceAfterRefresh({ cfg, agentDir }, oldPermit, profileId, resolved.apiKey));
      await expectFailure("manager:successor_cannot_claim_unmanaged_provider", () => registry.advanceAfterRefresh({ ...params, provider: "unmanaged-fixture-provider" }, oldPermit, profileId, resolved.apiKey));
      await expectFailure("manager:old_wire_cannot_bind_auth_result", () => registry.bindCredentialResult(params, oldPermit, profileId, { apiKey: original.access }, original.access));
      report.actualSdkOAuthManager = true; report.actualProviderHttps = true;
      const coldSource = new TrustedBaoControlSource(config), coldCoordinator = new TrustedBaoCoordinator(config, { bindings: [binding] });
      try {
        const cold = new TrustedAdmissionAuthority({ directory, scope, controlSource: coldSource });
        check("manager:cold_authority_cannot_reuse_positive_record", !cold.inspect().allowed);
        await expectFailure("manager:cold_old_credential_issuer_denied", () => coldCoordinator.issue(coldSource.bootstrapRequest(scope, binding), { leaseMs: 10000 }));
      } finally { await coldSource.close(); await coldCoordinator.close(); }
    } else {
      let timers = [];
      const triggerNames = [];
      if (scenario === "sqlite-abort") {
        const { DatabaseSync } = await import("node:sqlite"); database = new DatabaseSync(path.join(agentDir, "openclaw-agent.sqlite"));
        const tables = database.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' AND sql NOT LIKE 'CREATE VIRTUAL%'").all();
        const quote = value => '"' + value.replaceAll('"', '""') + '"';
        for (let i = 0; i < tables.length; i++) for (const event of ["INSERT", "UPDATE"]) {
          const name = "r5_caller_abort_" + i + "_" + event.toLowerCase(); triggerNames.push(name);
          database.exec("CREATE TRIGGER " + quote(name) + " BEFORE " + event + " ON " + quote(tables[i].name) + " BEGIN SELECT RAISE(ABORT,'synthetic_r5_caller_abort'); END");
        }
        cell.abortTriggerCount = triggerNames.length;
      }
      const faultAdapter = {
        needsRefresh: true,
        buildApiKey: credential => credential.access,
        refreshCredential: async credential => {
          if (scenario === "sdk-change-before-send") {
            const changed = { ...credential, access: "synthetic-concurrent-access", refresh: "synthetic-concurrent-refresh" };
            check("final-send:actual_sdk_concurrent_change_committed", await bridge.heptaBaoCommitManagedOAuthCredential({ agentDir, profileId,
              expectedCredentialDigest: digest(credential), credential: changed }) === true);
          }
          if (scenario === "local-fence-change") authority.closeUnresolved();
          if (scenario === "late-after-rejection") {
            timers.push(new Promise(resolve => setTimeout(() => { actualRawRefresh(credential).then(() => resolve(false), () => resolve(true)); }, 25)));
            fail("synthetic_provider_promise_timeout");
          }
          if (scenario === "original-deadline") await new Promise(resolve => setTimeout(resolve, 11000));
          if (scenario === "cross-provider-entry") return await chutes.a({ credential: { ...credential, provider: "chutes", clientId: "synthetic-client" } });
          const refreshed = await actualRawRefresh(credential);
          if (scenario === "duplicate-final-send") await actualRawRefresh(credential);
          return refreshed;
        },
      };
      const throughRealManager = ["intent-ack-lost", "provider-ack-lost", "sqlite-abort"].includes(scenario);
      try {
        cell.failureCode = await expectFailure(scenario + ":refresh_refused", () => throughRealManager
          ? oauth.n(params) : registry.resolveManagedOAuthAccess(params, faultAdapter));
      } finally {
        if (database) {
          for (const name of triggerNames) database.exec('DROP TRIGGER "' + name + '"');
          database.close(); database = null;
        }
      }
      if (timers.length) check("late:actual_sdk_continuation_after_rejection_denied", (await Promise.all(timers)).every(Boolean));
      const expectedCalls = ["provider-ack-lost", "sqlite-abort", "duplicate-final-send"].includes(scenario) ? 1 : 0;
      check(scenario + ":exact_provider_count", cell.providerCount === expectedCalls && cell.unknownObservedAtProvider === expectedCalls);
      check(scenario + ":admission_remains_closed", !authority.inspect().allowed);
      const persisted = JSON.parse(fs.readFileSync(cell.controlFile)).document;
      check(scenario + ":durable_unknown_retained", persisted.refreshAttempts.at(-1)?.status === "UNKNOWN" && persisted.assignments[0].status === "REFRESH_PENDING");
      if (scenario !== "sdk-change-before-send") check(scenario + ":actual_sqlite_old_credential_retained", digest(readStore(agentDir)) === before);
      const countBeforeRetry = cell.providerCount;
      await expectFailure(scenario + ":same_sdk_retry_denied", () => oauth.n({ ...params, store: readStore(agentDir) }));
      const coldSource = new TrustedBaoControlSource(config), coldCoordinator = new TrustedBaoCoordinator(config, { bindings: [binding] });
      try {
        await expectFailure(scenario + ":new_coordinator_unknown_owner_denied", () => coldCoordinator.issue(coldSource.bootstrapRequest(scope, binding), { leaseMs: 10000 }));
      } finally { await coldSource.close(); await coldCoordinator.close(); }
      check(scenario + ":no_second_provider_request", cell.providerCount === countBeforeRetry);
    }
    report.cases.push({ scenario, providerCount: cell.providerCount, unknownObservedAtProvider: cell.unknownObservedAtProvider,
      ...(cell.failureCode ? { failureCode: cell.failureCode } : {}), ...(cell.abortTriggerCount ? { abortTriggerCount: cell.abortTriggerCount } : {}),
      oauthSdkObservations: { ...registry.oauthSdkObservations }, refreshObservations: { ...registry.refreshObservations } });
    activeUninstall(); activeUninstall = null;
    await currentSource.close(); currentSource = null; await currentCoordinator.close(); currentCoordinator = null;
    active = null;
  }
  check("no_external_network_or_process_attempt", report.externalNetworkAttempts === 0 && report.externalProcessAttempts === 0);
  check("no_outside_fixture_write_or_home_read_attempt", report.outsideFixtureWriteAttempts === 0 && report.outsideFixtureHomeReadAttempts === 0);
  const discoveryAfter = selectOwnedSdkEntrypoint(sdkRoot);
  check("sdk_discovery_context_unchanged", process.argv[1] === sdkDiscovery.entrypoint &&
    process.cwd() === sdkRoot && digest(discoveryAfter) === digest(sdkDiscovery));
  check("actual_required_hook_modules_loaded", ["dist/oauth-B4aOCsid.js", "dist/oauth-BcZS_BvC.js", "dist/profiles-DyU-YCq2.js",
    "dist/store-DH33UrUj.js", "dist/source-check-ZSz5NzGW.js", "dist/chutes-oauth-YFvuN1-a.js", "dist/provider-runtime.runtime--yRUs3av.js"]
    .every(relative => report.oauthRefreshSdkModules.find(item => item.relative === relative)?.loaded));
  report.ok = true;
} catch (error) {
  report.error = { code: error.diagnosticCode ?? error.code ?? "trusted_refresh_sdk_caller_failure", messageSha256: hash(String(error.message)) };
} finally {
  try { database?.close(); } catch {}
  try { await currentSource?.close(); await currentCoordinator?.close(); } catch {}
  activeUninstall?.();
  globalThis.fetch = previousFetch;
  hook?.deregister();
  process.argv[1] = previousArgvEntrypoint;
  process.chdir(previousWorkingDirectory);
  for (const restore of restores.reverse()) restore();
  syncBuiltinESMExports();
  control?.closeAllConnections(); provider?.closeAllConnections();
  await Promise.all([control, provider].filter(Boolean).map(server => new Promise(resolve => server.close(resolve))));
  try { report.installedSdkUnchanged = verifyOAuthRefreshSdkUnchanged(sdkRoot); if (!report.installedSdkUnchanged) report.ok = false; }
  catch { report.installedSdkUnchanged = false; report.ok = false; }
  report.checksPassed = report.checks.filter(item => item.passed).length;
  fs.writeFileSync(path.join(root, "public-receipt.json"), JSON.stringify(report, null, 2) + "\n", { mode: 0o600 });
  process.stdout.write(JSON.stringify(report) + "\n");
  if (!report.ok) process.exitCode = 1;
}
