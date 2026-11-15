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
import { createRequire, syncBuiltinESMExports } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";
import { digest } from "./authbus_admission_authority_candidate.mjs";
import { TrustedAdmissionAuthority, applyFromTrustedControl } from "./authbus_trusted_admission_candidate.mjs";
import { TrustedBaoControlSource, TrustedBaoCoordinator } from "./authbus_trusted_control_candidate.mjs";
import { SdkOAuthRefreshAdmissionRegistry } from "./authbus_refresh_sdk_registry_candidate.mjs";
import { installOAuthRefreshSdkCandidate, verifyOAuthRefreshSdkUnchanged } from "./authbus_refresh_sdk_candidate.mjs";
import { ownOpenAiFixtureEnvironment, ownOpenAiFixtureTrust, createOwnedOpenAiConnectProxy } from "./authbus_refresh_sdk_openai_fixture.mjs";

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
// Capture inherited proxy/debug values before this isolated process clears
// any of them; cleanup restores that exact original process environment.
const fixtureEnvironment = ownOpenAiFixtureEnvironment();
process.env.OPENCLAW_STATE_DIR = state;
process.env.OPENCLAW_CONFIG_PATH = cfgPath;
process.env.OPENCLAW_HOME = path.join(state, "home");
process.env.OPENCLAW_OAUTH_DIR = path.join(state, "credentials");
for (const key of ["GOOGLE_API_KEY", "GEMINI_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "OPENCLAW_GATEWAY_TOKEN",
  "CHUTES_CLIENT_ID", "CHUTES_CLIENT_SECRET", "OPENCLAW_BUNDLED_PLUGINS_DIR", "OPENCLAW_TEST_TRUST_BUNDLED_PLUGINS_DIR",
  "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy", "OPENCLAW_PROXY_ACTIVE"])
  delete process.env[key];
// The SDK still validates this package-local plugin override itself. Its other
// package discovery paths also inspect argv[1] and cwd; below, the isolated
// process supplies the package and its verified bin as discovery context.
// The test-only trust override remains absent and the home guard stays closed.
process.env.OPENCLAW_BUNDLED_PLUGINS_DIR = path.join(sdkRoot, "dist/extensions");
if (process.env.OPENCLAW_AUTH_STORE_READONLY === "1") fail("trusted_refresh_caller_inherited_readonly_store");
const keyFile = path.join(root, "fixture.key"), certFile = path.join(root, "fixture.crt");
childProcess.execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", keyFile,
  "-out", certFile, "-days", "1", "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1,DNS:auth.openai.com"], { stdio: "ignore" });
const certificate = fs.readFileSync(certFile), serverKey = fs.readFileSync(keyFile);
const report = { schema: "authbus-refresh-r5-actual-openai-sdk", ok: false,
  nodeVersion: process.version, pid: process.pid, parentPid: process.ppid,
  syntheticCredentials: true, syntheticProvider: true, tlsControlEmulator: true,
  actualSdk: false, actualSqlite: false, actualSdkOAuthManager: false, actualProviderHttps: false,
  actualOpenAiSdkOAuthManager: false, actualOpenAiSdkGuard: false, actualOpenAiFacade: false,
  sdkGuardUsesOwnedMockedFetchBranch: true, actualUndiciRefreshTransport: false,
  actualNativeHeptaBao: false, actualColdSdkProcess: false, productionMutation: false,
  bundledPluginDiscovery: "sdk-production-validated-override-and-package-bin-argv-cwd",
  ownedCertificateGenerationProcesses: 1, externalNetworkAttempts: 0, externalProcessAttempts: 0,
  outsideFixtureWriteAttempts: 0, outsideFixtureHomeReadAttempts: 0, blockedHomeReads: [], ownerReader: "exact-sdk-persisted-local", checks: [], cases: [],
  sourceManifest: ["authbus_refresh_sdk_openai_live.mjs", "authbus_refresh_sdk_openai_fixture.mjs", "authbus_refresh_sdk_caller_live.mjs", "authbus_refresh_sdk_candidate.mjs", "authbus_refresh_sdk_registry_candidate.mjs",
    "authbus_refresh_store_sdk_candidate.mjs", "authbus_refresh_registry_candidate.mjs", "authbus_trusted_control_candidate.mjs",
    "authbus_trusted_admission_candidate.mjs", "authbus_admission_authority_candidate.mjs", "authbus_admission_registry_candidate.mjs",
    "authbus_dispatch_registry_candidate.mjs", "authbus_dispatch_sdk_candidate.mjs", "authbus_sdk_admission_candidate.mjs",
    "authbus_sdk_explicit_deny_candidate.mjs"].map(name => ({ name, sha256: hash(fs.readFileSync(path.join(here, name))) })) };
const check = (name, passed) => { report.checks.push({ case: name, phase: diagnosticPhase, passed: Boolean(passed) }); if (!passed) fail(name); };
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
let hook, control, provider, active, sdk, bridge, oauth, oauthLib, chutes, runtime, database;
let openaiRuntime, openaiFlow, runtimeFetch, fetchGuard, sdkSource, sdkCredentialState;
let activeUninstall, currentSource, currentCoordinator;
const allowedPorts = new Set();
const previousFetch = globalThis.fetch;
const previousArgvEntrypoint = process.argv[1];
const previousWorkingDirectory = process.cwd();
let sdkDiscovery, connectProxy, fixtureTrust, undiciRuntime, undiciGlobal, originalUndiciDispatcher, undiciPackagePin, facadeTracker;
report.ownedUndiciProxy = { connections: 0, denials: 0, upstreamFailures: 0 };
report.realExternalProvider = false;
report.configSha256 = hash(fs.readFileSync(cfgPath));
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
      if (starting && cell.kind === "intent-ack-lost") return response.destroy();
      return reply(response, 200, { data: { version: stored.version + 1 } });
    } catch { reply(response, 500, {}); }
  });
  provider = https.createServer({ key: serverKey, cert: certificate }, async (request, response) => {
    response.setHeader("connection", "close");
    try {
      const cell = active;
      if (!cell) return reply(response, 409, {});
      const body = await boundedBody(request), document = JSON.parse(fs.readFileSync(cell.controlFile)).document;
      const attempt = document.refreshAttempts?.at(-1);
      if (attempt?.status !== "UNKNOWN" || document.assignments?.[0]?.status !== "REFRESH_PENDING") return reply(response, 409, {});
      const data = request.headers["content-type"]?.startsWith("application/json") ? JSON.parse(body) : Object.fromEntries(new URLSearchParams(body));
      const tokenPath = cell.providerId === "openai" ? "/oauth/token" : "/v1/oauth/token";
      if (request.url !== tokenPath || request.method !== "POST" || data.grant_type !== "refresh_token" || data.refresh_token !== cell.original.refresh)
        return reply(response, 400, {});
      if (cell.transport === "undici") {
        if (request.socket.servername !== "auth.openai.com" || request.headers.host !== "auth.openai.com")
          return reply(response, 400, {});
        cell.undiciProviderTlsRequests++;
      }
      cell.providerCount++;
      cell.unknownObservedAtProvider++;
      durable(cell.providerFile, { count: cell.providerCount, unknownObserved: cell.unknownObservedAtProvider });
      if (cell.kind === "provider-ack-lost") return response.destroy();
      if (cell.kind === "redirect") {
        response.writeHead(307, { location: "https://unowned.invalid/oauth/token" });
        return response.end();
      }
      const access = cell.providerId === "openai"
        ? [Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url"),
          Buffer.from(JSON.stringify({ exp: Math.floor(Date.now() / 1000) + 900,
            "https://api.openai.com/auth": { chatgpt_account_id: "synthetic-r5-account-" + cell.scenario } })).toString("base64url"),
          "synthetic-signature"].join(".")
        : "synthetic-new-access-" + cell.scenario;
      return reply(response, 200, { access_token: access,
        refresh_token: "synthetic-new-refresh-" + cell.scenario, expires_in: 900 });
    } catch { reply(response, 500, {}); }
  });
  await Promise.all([new Promise(resolve => control.listen(0, "127.0.0.1", resolve)), new Promise(resolve => provider.listen(0, "127.0.0.1", resolve))]);
  connectProxy = await createOwnedOpenAiConnectProxy({ providerPort: provider.address().port, activeCell: () => active, observations: report.ownedUndiciProxy });
  allowedPorts.add(control.address().port); allowedPorts.add(provider.address().port); allowedPorts.add(connectProxy.port);
  fixtureTrust = ownOpenAiFixtureTrust(certificate);
  report.processLocalTlsTrust = { certificateSha256: fixtureTrust.certificateSha256, restorationComparison: fixtureTrust.restorationComparison,
    rejectUnauthorizedDisabled: false, persistentTrustChange: false };
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
  // The 27 mapped cases use this explicit fixture transport. The five Undici
  // cases must never enter it: they keep the real token URL and SDK runtime
  // fetch through the separate exact-target loopback CONNECT listener.
  globalThis.fetch = (url, init = {}) => {
    if (active) active.mappedFetchCalls++;
    const destinations = { "https://platform.claude.com/v1/oauth/token": "/v1/oauth/token",
      "https://auth.openai.com/oauth/token": "/oauth/token" };
    const targetPath = destinations[String(url)];
    if (!targetPath || init.redirect !== "error") {
      report.externalNetworkAttempts++; fail("trusted_refresh_caller_unmapped_provider_request");
    }
    return new Promise((resolve, reject) => {
      const request = https.request({ hostname: "127.0.0.1", port: provider.address().port, path: targetPath,
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
  // This selects the actual SDK's mock-fetch branch for mapped cases. The
  // five Undici cases remove this marker and require real runtime dispatch,
  // CONNECT, and verified provider TLS, with mappedFetchCalls remaining zero.
  Object.defineProperty(globalThis.fetch, "mock", { value: Object.freeze({}), configurable: true });
  diagnosticPhase = "sdk-import";
  sdkDiscovery = selectOwnedSdkEntrypoint(sdkRoot);
  check("sdk_discovery_matches_actual_owner_r5_input", sdkDiscovery.relative === "openclaw.mjs" &&
    sdkDiscovery.packageSha256 === "695b6ee36df7fc69606dc390cf97bb2ca809114337b18c573707637cd2a4e3db" &&
    sdkDiscovery.entrypointSha256 === "f643b005d6db233a0b45204e8d8e943256874ccc6897b8a6e0cf42a9b376a188");
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
  openaiRuntime = await import(pathToFileURL(path.join(sdkRoot, "dist/openai-chatgpt-provider.runtime-DGoPIR1g.js")).href);
  openaiFlow = await import(pathToFileURL(path.join(sdkRoot, "dist/openai-chatgpt-oauth-flow.runtime-DOVvnAqe.js")).href);
  runtimeFetch = await import(pathToFileURL(path.join(sdkRoot, "dist/runtime-fetch-k5Zth7kk.js")).href);
  fetchGuard = await import(pathToFileURL(path.join(sdkRoot, "dist/fetch-guard-6VNcgVVc.js")).href);
  sdkSource = await import(pathToFileURL(path.join(sdkRoot, "dist/source-check-ZSz5NzGW.js")).href);
  sdkCredentialState = await import(pathToFileURL(path.join(sdkRoot, "dist/credential-state-BY-oz-QV.js")).href);
  facadeTracker = await import(pathToFileURL(path.join(sdkRoot, "dist/facade-loader-ClPyIgA5.js")).href);
  const activeProxyState = await import(pathToFileURL(path.join(sdkRoot, "dist/active-proxy-state-DJLhrP_Z.js")).href);
  check("undici:no_injected_runtime_or_existing_managed_proxy", globalThis.__OPENCLAW_TEST_UNDICI_RUNTIME_DEPS__ === undefined &&
    typeof activeProxyState.r === "function" && activeProxyState.r() === undefined && activeProxyState.n() === undefined);
  undiciRuntime = await import(pathToFileURL(path.join(sdkRoot, "dist/undici-runtime-BL8ZN-Ey.js")).href);
  const sdkRequire = createRequire(pathToFileURL(path.join(sdkRoot, "dist/undici-runtime-BL8ZN-Ey.js")));
  const actualUndici = sdkRequire("undici");
  const packageFile = fs.realpathSync(sdkRequire.resolve("undici/package.json"));
  const entryFile = fs.realpathSync(sdkRequire.resolve("undici"));
  const packageStat = fs.lstatSync(packageFile);
  const entryStat = fs.lstatSync(entryFile);
  check("undici:owned_actual_package", inside(packageFile, sdkRoot) && packageStat.isFile() && !packageStat.isSymbolicLink() && packageStat.size <= 65536 &&
    inside(entryFile, sdkRoot) && entryStat.isFile() && !entryStat.isSymbolicLink() && entryStat.size <= 262144);
  const packageBytes = fs.readFileSync(packageFile), packageInfo = JSON.parse(packageBytes);
  check("undici:actual_fetch_function_identity", packageInfo.name === "undici" && typeof actualUndici.fetch === "function" &&
    undiciRuntime.a().fetch === actualUndici.fetch && globalThis.__OPENCLAW_TEST_UNDICI_RUNTIME_DEPS__ === undefined);
  undiciGlobal = undiciRuntime.i(); originalUndiciDispatcher = undiciGlobal.getGlobalDispatcher();
  undiciPackagePin = { file: packageFile, sha256: hash(packageBytes), entryFile, entrySha256: hash(fs.readFileSync(entryFile)) };
  report.undiciRuntimeBinding = { packageVersion: packageInfo.version, packageRelative: path.relative(sdkRoot, packageFile),
    packageSha256: undiciPackagePin.sha256, entryRelative: path.relative(sdkRoot, entryFile), entrySha256: undiciPackagePin.entrySha256,
    libraryPinScope: "package-metadata-and-entrypoint", actualPackageFetchIdentity: true, testRuntimeOverride: false, dnsOverride: false,
    route: "actual-sdk-managed-env-proxy", actualExecutionQualifiedByScenarioOnly: true };
  check("actual_sdk_required_interfaces", typeof oauth.n === "function" && typeof oauth.t === "function" &&
    typeof oauthLib.t === "function" && typeof bridge.heptaBaoCommitManagedOAuthCredential === "function" &&
    typeof sdk.resolveProviderIdForAuth === "function" && typeof sdk.loadAuthProfileStoreWithoutExternalProfiles === "function" &&
    typeof sdkSource.v === "function" && sdkCredentialState.t === 300000);
  report.sdkOAuthRefreshMarginMs = sdkCredentialState.t;
  report.actualSdk = true;
  report.sdkVersion = JSON.parse(fs.readFileSync(path.join(sdkRoot, "package.json"))).version;
  report.actualProviderAliases = Object.fromEntries(["openai", "openai-codex", "anthropic"].map(name =>
    [name, sdk.resolveProviderIdForAuth(name, { config: cfg })]));
  const readStore = hook.qualification.readOwnedStore;
  const writeStore = (agentDir, profiles, profileId, providerId) => sdk.saveAuthProfileStore({ version: 1, profiles,
    order: { [providerId]: [profileId] }, lastGood: { [providerId]: profileId } }, agentDir,
    { filterExternalAuthProfiles: false, syncExternalCli: false });
  const coreScenarios = ["usable-own-store", "manager-success", "intent-ack-lost", "provider-ack-lost", "sqlite-abort",
    "sdk-change-before-send", "local-fence-change", "duplicate-final-send", "late-after-rejection", "original-deadline", "cross-provider-entry"];
  const scenarios = [...coreScenarios, ...coreScenarios.map(name => "openai-" + name),
    "openai-guard-after-await", "openai-runtime-without-ticket", "openai-runtime-or-mock-without-ticket",
    "openai-runtime-factory-replacement", "openai-redirect",
    ...["manager-success", "intent-ack-lost", "provider-ack-lost", "sqlite-abort", "guard-after-await"].map(name => "openai-undici-" + name)];
  report.expectedScenarioCount = 32;
  check("actual_exact_scenario_inventory", scenarios.length === report.expectedScenarioCount && new Set(scenarios).size === report.expectedScenarioCount);
  for (const scenario of scenarios) {
    diagnosticPhase = scenario + ":fixture";
    const usesUndici = scenario.startsWith("openai-undici-");
    const kind = usesUndici ? scenario.slice("openai-undici-".length) : scenario.startsWith("openai-") ? scenario.slice("openai-".length) : scenario;
    const providerName = scenario.startsWith("openai-") ? "openai" : "anthropic";
    const cellRoot = path.join(root, scenario); fs.mkdirSync(cellRoot, { mode: 0o700 });
    const agentDir = path.join(cellRoot, "agent"), directory = path.join(cellRoot, "authority");
    fs.mkdirSync(agentDir, { mode: 0o700 }); fs.mkdirSync(directory, { mode: 0o700 });
    const providerId = sdk.resolveProviderIdForAuth(providerName, { config: cfg }), profileId = providerName + ":authbus-r5-" + scenario;
    check(scenario + ":actual_sdk_canonical_provider", providerId === providerName);
    const original = { type: "oauth", provider: providerName, access: "synthetic-old-access-" + scenario,
      refresh: "synthetic-old-refresh-" + scenario,
      // Positive fixture exceeds the actual SDK refresh margin. Authority and
      // refresh leases retain their original independent 10-second deadline.
      expires: kind === "usable-own-store" ? Date.now() + sdkCredentialState.t + 60000 : 1 };
    check(scenario + ":actual_sdk_fixture_expiry_classification", sdkSource.v(original) === (kind === "usable-own-store"));
    const main = { ...original, access: "synthetic-main-access-" + scenario, refresh: "synthetic-main-refresh-" + scenario, expires: Date.now() + 3600000 };
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
    const cell = { scenario, kind, providerId, original, transport: usesUndici ? "undici" : "mapped-https",
      providerCount: 0, unknownObservedAtProvider: 0, mappedFetchCalls: 0, undiciProviderTlsRequests: 0, undiciConnects: 0,
      controlFile: path.join(cellRoot, "control.json"), providerFile: path.join(cellRoot, "provider-count.json") };
    cells.set("/v1/authbus/data/" + scenario, cell); active = cell;
    if (usesUndici) {
      fixtureEnvironment.useProxy(connectProxy.origin);
      delete globalThis.fetch.mock;
    } else {
      fixtureEnvironment.clearProxy();
      Object.defineProperty(globalThis.fetch, "mock", { value: Object.freeze({}), configurable: true });
    }
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
    const actualRawRefresh = credential => oauthLib.n(providerName).refreshToken(credential);
    const openaiTokenInit = credential => ({ method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: credential.refresh, client_id: "app_EMoamEEZ73f0CkXaXp7hrann" }) });
    if (kind === "usable-own-store") {
      const resolved = await oauth.n(params);
      const after = readStore(agentDir);
      const usableObservation = {
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
      (report.usableOwnerObservations ??= []).push({ scenario, ...usableObservation });
      check("usable:actual_sdk_uses_scoped_credential", resolved?.apiKey === original.access && digest(after) === before);
      check("usable:no_provider_or_main_store_adoption", cell.providerCount === 0 && registry.oauthSdkObservations.usableResolutions === 1);
      await expectFailure("entry:runtime_without_private_context_denied", () => oauth.t({ credential: original }));
      await expectFailure("entry:provider_library_without_private_context_denied", () => oauthLib.t(providerName, { [providerName]: original }));
      await expectFailure("entry:raw_builtin_without_private_context_denied", () => actualRawRefresh(original));
      await expectFailure("entry:plugin_facade_without_private_context_denied", () => runtime.o({ provider: providerName, context: original }));
      if (providerName === "openai") {
        await expectFailure("openai:runtime_direct_refresh_denied", () => openaiRuntime.r(original.refresh));
        await expectFailure("openai:runtime_direct_get_api_key_denied", () => openaiRuntime.n("openai", { openai: original }));
        await expectFailure("openai:flow_direct_refresh_denied", () => openaiFlow.r(original.refresh));
        await expectFailure("openai:flow_testing_refresh_denied", () => openaiFlow.i.refreshAccessToken(original.refresh));
        await expectFailure("openai:runtime_fetch_direct_refresh_denied", () => runtimeFetch.t("https://auth.openai.com/oauth/token", openaiTokenInit(original)));
        await expectFailure("openai:runtime_mock_direct_refresh_denied", () => runtimeFetch.n("https://auth.openai.com/oauth/token", openaiTokenInit(original)));
        for (const [label, target] of [
          ["default-port", "https://auth.openai.com:443/oauth/token"],
          ["query", "https://auth.openai.com/oauth/token?fixture=unbound"],
          ["encoded-path", "https://auth.openai.com/oauth/%74oken"],
          ["url-object", new URL("https://auth.openai.com/oauth/token")],
          ["request-object", new Request("https://auth.openai.com/oauth/token", openaiTokenInit(original))],
        ]) {
          const code = await expectFailure("openai:runtime_direct_" + label + "_denied", () =>
            runtimeFetch.n(target, openaiTokenInit(original)));
          check("openai:runtime_direct_" + label + "_denied_before_runtime", code === "trusted_refresh_guarded_runtime_ticket_required");
        }
        const directGuardCode = await expectFailure("openai:guard_direct_default_port_denied", () => fetchGuard.r({
          url: "https://auth.openai.com:443/oauth/token", init: openaiTokenInit(original) }));
        check("openai:guard_direct_denied_before_dns", directGuardCode === "trusted_refresh_guarded_request_context_required");
        await expectFailure("openai:provider_registry_replacement_denied", () => oauthLib.i({ id: "openai", refreshToken: async () => original }));
      }
      check("entry:no_unowned_refresh_side_effect", cell.providerCount === 0 && JSON.parse(fs.readFileSync(cell.controlFile)).document.refreshAttempts.length === 0);
    } else if (kind === "manager-success") {
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
      if (providerName === "openai") {
        check("openai:actual_guard_request_and_final_dispatch", registry.oauthSdkObservations.guardedRequests === 1 &&
          registry.oauthSdkObservations.allowedDispatches === 1 && registry.oauthSdkObservations.guardedRuntimeEntries === (usesUndici ? 1 : 0));
        check("openai:actual_activated_facade_loaded", facadeTracker.n().includes("openai") &&
          report.oauthRefreshSdkModules.find(item => item.relative === "dist/extensions/openai/api.js")?.loaded === true);
        report.actualOpenAiSdkOAuthManager = true; report.actualOpenAiSdkGuard = true; report.actualOpenAiFacade = true;
        if (usesUndici) {
          check("openai:actual_undici_tls_dispatch_once", cell.mappedFetchCalls === 0 && cell.undiciConnects === 1 && cell.undiciProviderTlsRequests === 1);
          report.actualUndiciRefreshTransport = true;
        }
      }
      const coldSource = new TrustedBaoControlSource(config), coldCoordinator = new TrustedBaoCoordinator(config, { bindings: [binding] });
      try {
        const cold = new TrustedAdmissionAuthority({ directory, scope, controlSource: coldSource });
        check("manager:cold_authority_cannot_reuse_positive_record", !cold.inspect().allowed);
        await expectFailure("manager:cold_old_credential_issuer_denied", () => coldCoordinator.issue(coldSource.bootstrapRequest(scope, binding), { leaseMs: 10000 }));
      } finally { await coldSource.close(); await coldCoordinator.close(); }
    } else {
      let timers = [];
      const triggerNames = [];
      if (kind === "sqlite-abort") {
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
          if (kind === "sdk-change-before-send") {
            const changed = { ...credential, access: "synthetic-concurrent-access", refresh: "synthetic-concurrent-refresh" };
            check("final-send:actual_sdk_concurrent_change_committed", await bridge.heptaBaoCommitManagedOAuthCredential({ agentDir, profileId,
              expectedCredentialDigest: digest(credential), credential: changed }) === true);
          }
          if (kind === "local-fence-change") authority.closeUnresolved();
          if (kind === "late-after-rejection") {
            timers.push(new Promise(resolve => setTimeout(() => { actualRawRefresh(credential).then(() => resolve(false), () => resolve(true)); }, 25)));
            fail("synthetic_provider_promise_timeout");
          }
          if (kind === "original-deadline") await new Promise(resolve => setTimeout(resolve, 11000));
          if (kind === "cross-provider-entry") return await chutes.a({ credential: { ...credential, provider: "chutes", clientId: "synthetic-client" } });
          if (kind === "runtime-without-ticket") return await runtimeFetch.t("https://auth.openai.com/oauth/token", openaiTokenInit(credential));
          if (kind === "runtime-or-mock-without-ticket") return await runtimeFetch.n("https://auth.openai.com/oauth/token", openaiTokenInit(credential));
          if (kind === "runtime-factory-replacement") {
            cell.unqualifiedRuntimeCalls = 0;
            const unqualified = () => { cell.unqualifiedRuntimeCalls++; return credential; };
            return await openaiRuntime.t({ ensureGlobalUndiciEnvProxyDispatcher: unqualified,
              getOAuthApiKey: unqualified, refreshOpenAICodexToken: unqualified }).refreshOpenAICodexToken(credential.refresh);
          }
          if (kind === "guard-after-await") {
            const descriptor = Object.getOwnPropertyDescriptor(globalThis.fetch, "mock");
            let queued = false;
            Object.defineProperty(globalThis.fetch, "mock", { configurable: true, get() {
              if (!queued) { queued = true; queueMicrotask(() => { authority.closeUnresolved(); cell.fenceChangedDuringGuardAwait = true; }); }
              return usesUndici ? undefined : Object.freeze({});
            } });
            try { return await actualRawRefresh(credential); }
            finally { if (descriptor) Object.defineProperty(globalThis.fetch, "mock", descriptor); else delete globalThis.fetch.mock; }
          }
          const refreshed = await actualRawRefresh(credential);
          if (kind === "duplicate-final-send") await actualRawRefresh(credential);
          return refreshed;
        },
      };
      const throughRealManager = ["intent-ack-lost", "provider-ack-lost", "sqlite-abort", "redirect"].includes(kind);
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
      const expectedCalls = ["provider-ack-lost", "sqlite-abort", "duplicate-final-send", "redirect"].includes(kind) ? 1 : 0;
      check(scenario + ":exact_provider_count", cell.providerCount === expectedCalls && cell.unknownObservedAtProvider === expectedCalls);
      check(scenario + ":admission_remains_closed", !authority.inspect().allowed);
      const persisted = JSON.parse(fs.readFileSync(cell.controlFile)).document;
      check(scenario + ":durable_unknown_retained", persisted.refreshAttempts.at(-1)?.status === "UNKNOWN" && persisted.assignments[0].status === "REFRESH_PENDING");
      if (kind !== "sdk-change-before-send") check(scenario + ":actual_sqlite_old_credential_retained", digest(readStore(agentDir)) === before);
      if (kind === "guard-after-await") check("openai:actual_guard_await_fence_veto", cell.fenceChangedDuringGuardAwait &&
        registry.oauthSdkObservations.guardedRequests === 1 && registry.oauthSdkObservations.allowedDispatches === 0);
      if (kind === "runtime-factory-replacement") check("openai:unqualified_runtime_never_invoked", cell.unqualifiedRuntimeCalls === 0);
      const countBeforeRetry = cell.providerCount;
      await expectFailure(scenario + ":same_sdk_retry_denied", () => oauth.n({ ...params, store: readStore(agentDir) }));
      const coldSource = new TrustedBaoControlSource(config), coldCoordinator = new TrustedBaoCoordinator(config, { bindings: [binding] });
      try {
        await expectFailure(scenario + ":new_coordinator_unknown_owner_denied", () => coldCoordinator.issue(coldSource.bootstrapRequest(scope, binding), { leaseMs: 10000 }));
      } finally { await coldSource.close(); await coldCoordinator.close(); }
      check(scenario + ":no_second_provider_request", cell.providerCount === countBeforeRetry);
    }
    if (usesUndici) check(scenario + ":actual_runtime_route_exact_and_no_mapped_fetch", cell.mappedFetchCalls === 0 &&
      cell.undiciConnects === cell.providerCount && cell.undiciProviderTlsRequests === cell.providerCount &&
      registry.oauthSdkObservations.guardedRuntimeEntries === cell.providerCount);
    report.cases.push({ scenario, kind, providerId, transport: cell.transport, providerCount: cell.providerCount,
      unknownObservedAtProvider: cell.unknownObservedAtProvider, mappedFetchCalls: cell.mappedFetchCalls,
      undiciConnects: cell.undiciConnects, undiciProviderTlsRequests: cell.undiciProviderTlsRequests,
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
    "dist/store-DH33UrUj.js", "dist/source-check-ZSz5NzGW.js", "dist/chutes-oauth-YFvuN1-a.js", "dist/provider-runtime.runtime--yRUs3av.js",
    "dist/extensions/openai/api.js", "dist/openai-chatgpt-provider.runtime-DGoPIR1g.js", "dist/openai-chatgpt-oauth-flow.runtime.js",
    "dist/openai-chatgpt-oauth-flow.runtime-DOVvnAqe.js", "dist/fetch-guard-6VNcgVVc.js", "dist/runtime-fetch-k5Zth7kk.js"]
    .every(relative => report.oauthRefreshSdkModules.find(item => item.relative === relative)?.loaded));
  check("all_exact_scenarios_completed", report.cases.length === report.expectedScenarioCount);
  check("openai:actual_undici_route_all_five_cases", report.cases.filter(item => item.transport === "undici").length === 5 &&
    report.actualUndiciRefreshTransport === true && report.ownedUndiciProxy.connections === 3 &&
    report.ownedUndiciProxy.denials === 0 && report.ownedUndiciProxy.upstreamFailures === 0);
  check("undici:actual_package_entrypoint_and_runtime_override_unchanged", hash(fs.readFileSync(undiciPackagePin.file)) === undiciPackagePin.sha256 &&
    hash(fs.readFileSync(undiciPackagePin.entryFile)) === undiciPackagePin.entrySha256 &&
    globalThis.__OPENCLAW_TEST_UNDICI_RUNTIME_DEPS__ === undefined);
  report.ok = true;
} catch (error) {
  report.error = { code: error.diagnosticCode ?? error.code ?? "trusted_refresh_sdk_caller_failure", messageSha256: hash(String(error.message)) };
} finally {
  try { database?.close(); } catch {}
  try { await currentSource?.close(); await currentCoordinator?.close(); } catch {}
  activeUninstall?.();
  const contextCleanupCodes = [];
  try {
    if (undiciGlobal && originalUndiciDispatcher) {
      const activeDispatcher = undiciGlobal.getGlobalDispatcher();
      undiciGlobal.setGlobalDispatcher(originalUndiciDispatcher);
      if (activeDispatcher !== originalUndiciDispatcher) await activeDispatcher.destroy();
    }
  } catch (error) { contextCleanupCodes.push(error.diagnosticCode ?? error.code ?? "openai_fixture_dispatcher_cleanup_failed"); }
  try { await connectProxy?.close(); } catch (error) { contextCleanupCodes.push(error.diagnosticCode ?? error.code ?? "openai_fixture_proxy_cleanup_failed"); }
  try { fixtureTrust?.restore(); } catch (error) { contextCleanupCodes.push(error.diagnosticCode ?? error.code ?? "openai_fixture_trust_cleanup_failed"); }
  try { fixtureEnvironment.restore(); } catch (error) { contextCleanupCodes.push(error.diagnosticCode ?? error.code ?? "openai_fixture_environment_cleanup_failed"); }
  report.fixtureProcessContextRestored = Boolean(contextCleanupCodes.length === 0 &&
    (!fixtureTrust || fixtureTrust.isRestored()) && fixtureEnvironment.isRestored() && (!connectProxy || connectProxy.isClosed()));
  if (!report.fixtureProcessContextRestored) { report.ok = false; report.contextCleanupCodes = contextCleanupCodes; }
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
  report.sourceFilesUnchanged = report.sourceManifest.every(item => hash(fs.readFileSync(path.join(here, item.name))) === item.sha256);
  report.configUnchanged = hash(fs.readFileSync(cfgPath)) === report.configSha256;
  if (!report.sourceFilesUnchanged || !report.configUnchanged) report.ok = false;
  report.checksPassed = report.checks.filter(item => item.passed).length;
  fs.writeFileSync(path.join(root, "public-receipt.json"), JSON.stringify(report, null, 2) + "\n", { mode: 0o600 });
  process.stdout.write(JSON.stringify(report) + "\n");
  if (!report.ok) process.exitCode = 1;
}
