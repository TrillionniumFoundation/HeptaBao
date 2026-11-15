#!/usr/bin/env node
/**
 * Isolated actual SDK / SQLite / loopback HTTP dispatch validation.
 * Run only on the main host against the frozen SDK copy. No actual provider
 * credential or installed configuration is read; no provider egress is allowed.
 */
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import http from "node:http";
import net from "node:net";
import childProcess from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";
import { AdmissionAuthority, digest } from "./authbus_admission_authority_candidate.mjs";
import { DispatchAdmissionRegistry, REQUEST_CAPABILITY_SYMBOL } from "./authbus_dispatch_registry_candidate.mjs";
import { installSdkCandidate, verifyInstalledSdkUnchanged } from "./authbus_sdk_explicit_deny_candidate.mjs";
import { installDispatchSdkCandidate, verifyDispatchSdkUnchanged } from "./authbus_dispatch_sdk_candidate.mjs";

const fail = code => { throw Object.assign(new Error(code), { diagnosticCode: code }); };
const sha256 = value => crypto.createHash("sha256").update(value).digest("hex");
const PROFILE = "openai:authbus-dispatch-fixture";
const CREDENTIAL = { type: "api_key", provider: "openai", key: "synthetic-final-dispatch-loopback-only" };
const FIXTURE_HOSTNAME = "authbus-dispatch-fixture.invalid";
const SOURCE_FILES = ["authbus_admission_authority_candidate.mjs", "authbus_admission_registry_candidate.mjs",
  "authbus_sdk_admission_candidate.mjs", "authbus_sdk_explicit_deny_candidate.mjs",
  "authbus_dispatch_registry_candidate.mjs", "authbus_dispatch_sdk_candidate.mjs", "authbus_dispatch_sdk_live.mjs"];
const args = {};
for (let i = 2; i < process.argv.length; i += 2) {
  if (!["--openclaw-root", "--work-dir"].includes(process.argv[i]) || !path.isAbsolute(process.argv[i + 1] ?? "")) fail("absolute_cli_arguments_required");
  args[process.argv[i]] = path.resolve(process.argv[i + 1]);
}
if (!args["--openclaw-root"] || !args["--work-dir"]) fail("missing_cli_argument");
const root = args["--work-dir"], openclawRoot = args["--openclaw-root"];
process.umask(0o077);
fs.mkdirSync(root, { mode: 0o700 });
const toolsDirectory = path.dirname(fileURLToPath(import.meta.url));
const report = { schema: "authbus-final-dispatch-actual-sdk-r1", ok: false, checks: [],
  syntheticCredentials: true, actualSdk: false, actualSqlite: false, actualLoopbackHttp: false,
  actualSimpleCompletion: false, actualSharedLlmHttpDispatchQualified: false, naturalDeadlineWaited: false,
  coldProcessQualified: false, actualEmbeddedAgentLifecycle: false, allProductDispatchCoverageQualified: false,
  oauthRefreshOwnershipQualified: false, productionBootstrapQualified: false, productionMutation: false,
  providerNetworkAllowed: false, externalNetworkAttempts: 0, externalProcessAttempts: 0,
  candidateSourceBindings: SOURCE_FILES.map(relative => ({ relative, sha256: sha256(fs.readFileSync(path.join(toolsDirectory, relative))) })) };
const check = (name, passed) => { report.checks.push({ case: name, passed: Boolean(passed) }); if (!passed) fail(name); };
const sleepUntil = deadline => new Promise(resolve => setTimeout(resolve, Math.max(0, deadline - Date.now())));
const counts = new Map();
const count = pathname => counts.get(pathname) ?? 0;
let sdkHook, dispatchHook, uninstall, server, fixturePort = 0;
const originalConnect = net.Socket.prototype.connect;
const originalProcess = Object.fromEntries(["spawn", "spawnSync", "exec", "execSync", "execFile", "execFileSync", "fork"].map(name => [name, childProcess[name]]));
let redirectDeadline = 0;

try {
  const state = path.join(root, "state"), agent = path.join(state, "agents/main/agent");
  for (const directory of [state, path.join(state, "agents"), path.join(state, "agents/main"), agent,
    path.join(state, "home"), path.join(state, "credentials"), path.join(state, "admission")]) fs.mkdirSync(directory, { mode: 0o700 });
  const cfg = { agents: { list: [{ id: "main", default: true, agentDir: agent }] } };
  const cfgPath = path.join(state, "openclaw.json");
  fs.writeFileSync(cfgPath, JSON.stringify(cfg) + "\n", { mode: 0o600 });
  process.env.OPENCLAW_STATE_DIR = state;
  process.env.OPENCLAW_CONFIG_PATH = cfgPath;
  process.env.OPENCLAW_HOME = path.join(state, "home");
  process.env.OPENCLAW_OAUTH_DIR = path.join(state, "credentials");
  for (const name of ["GOOGLE_API_KEY", "GEMINI_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "OPENCLAW_GATEWAY_TOKEN"]) delete process.env[name];
  if (process.env.OPENCLAW_AUTH_STORE_READONLY === "1") fail("inherited_readonly_auth_store");
  server = http.createServer(async (req, res) => {
    const pathname = new URL(req.url, "http://127.0.0.1").pathname;
    counts.set(pathname, count(pathname) + 1);
    if (req.headers.authorization !== "Bearer " + CREDENTIAL.key) {
      res.writeHead(401, { "content-type": "application/json" }); res.end('{"error":"fixture_auth_rejected"}'); return;
    }
    if (pathname === "/redirect-expire") {
      await sleepUntil(redirectDeadline + 50);
      res.writeHead(302, { location: "/redirect-target" }); res.end(); return;
    }
    if (pathname === "/v1/chat/completions") {
      let body = "";
      for await (const chunk of req) body += chunk.toString("utf8");
      if (body.length > 131072) { res.writeHead(413); res.end(); return; }
      let payload;
      try { payload = JSON.parse(body); } catch { res.writeHead(400); res.end(); return; }
      const base = { id: "synthetic-dispatch-completion", created: Math.floor(Date.now() / 1000), model: "synthetic-model" };
      if (payload.stream) {
        res.writeHead(200, { "content-type": "text/event-stream" });
        res.write("data: " + JSON.stringify({ ...base, object: "chat.completion.chunk", choices: [{ index: 0, delta: { role: "assistant", content: "synthetic-dispatch-ok" }, finish_reason: null }] }) + "\n\n");
        res.write("data: " + JSON.stringify({ ...base, object: "chat.completion.chunk", choices: [{ index: 0, delta: {}, finish_reason: "stop" }], usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } }) + "\n\n");
        res.end("data: [DONE]\n\n");
      } else {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ...base, object: "chat.completion", choices: [{ index: 0, message: { role: "assistant", content: "synthetic-dispatch-ok" }, finish_reason: "stop" }], usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } }));
      }
      return;
    }
    res.writeHead(200, { "content-type": "application/json" }); res.end('{"ok":true}');
  });
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  fixturePort = server.address().port;
  net.Socket.prototype.connect = function (...values) {
    const first = Array.isArray(values[0]) ? values[0][0] : values[0];
    const options = typeof first === "object" && first !== null ? first : { port: first, host: values[1] };
    const host = options.host ?? options.hostname ?? "localhost";
    if (Number(options.port) !== fixturePort || !["127.0.0.1", "localhost", FIXTURE_HOSTNAME].includes(host)) {
      report.externalNetworkAttempts += 1;
      fail("external_network_forbidden");
    }
    return originalConnect.apply(this, values);
  };
  const denyProcess = () => { report.externalProcessAttempts += 1; fail("external_process_forbidden"); };
  for (const name of Object.keys(originalProcess)) childProcess[name] = denyProcess;
  syncBuiltinESMExports();
  const authority = new AdmissionAuthority({ directory: path.join(state, "admission"),
    scope: { hostId: "isolated-main", agentId: "main", agentDir: agent, provider: "openai" } });
  let sdk;
  const read = () => { sdk.clearRuntimeAuthProfileStoreSnapshots(); return sdk.loadAuthProfileStoreWithoutExternalProfiles(agent, { allowKeychainPrompt: false }); };
  const registry = new DispatchAdmissionRegistry({ authorities: [authority],
    resolveDefaultAgentDir: value => sdk.resolveDefaultAgentDir(value),
    resolveProviderIdForAuth: (value, options) => sdk.resolveProviderIdForAuth(value, options),
    readStore: directory => { if (path.resolve(directory) !== path.resolve(agent)) fail("fresh_store_read_scope_escape"); return read(); } });
  uninstall = registry.install();
  sdkHook = installSdkCandidate(openclawRoot, report);
  dispatchHook = installDispatchSdkCandidate(openclawRoot, report);
  sdk = await import(pathToFileURL(path.join(openclawRoot, "dist/plugin-sdk/agent-runtime.js")).href);
  const modelAuth = await import(pathToFileURL(path.join(openclawRoot, "dist/model-auth-CJEm9SNp.js")).href);
  const stream = await import(pathToFileURL(path.join(openclawRoot, "dist/stream-BcRkg2P0.js")).href);
  const guard = await import(pathToFileURL(path.join(openclawRoot, "dist/fetch-guard-6VNcgVVc.js")).href);
  const simple = await import(pathToFileURL(path.join(openclawRoot, "dist/simple-completion-runtime-DNwDdfY4.js")).href);
  check("all_actual_sdk_overlays_loaded", report.sdkCandidateModules.every(item => item.loaded) && report.dispatchSdkModules.every(item => item.loaded));
  check("actual_sdk_agent_scope", path.resolve(sdk.resolveDefaultAgentDir(cfg)) === path.resolve(agent));
  report.actualSdk = true;
  report.sdkVersion = JSON.parse(fs.readFileSync(path.join(openclawRoot, "package.json"), "utf8")).version;
  const databasePath = path.join(agent, "openclaw-agent.sqlite");
  check("new_scoped_database_absent", !fs.existsSync(databasePath));
  sdk.saveAuthProfileStore({ version: 1, profiles: {} }, agent, { filterExternalAuthProfiles: false, syncExternalCli: false });
  check("actual_sdk_fixture_credential_seeded", Boolean(await sdk.upsertAuthProfileWithLock({ agentDir: agent, profileId: PROFILE, credential: CREDENTIAL })));
  let epoch = 10;
  const apply = async (ttl = 30000) => {
    const grant = { epoch: ++epoch, status: "ASSIGNED", mode: "enforce", model: "synthetic-model", profileId: PROFILE,
      digest: digest(CREDENTIAL), leaseId: "synthetic-dispatch-lease-" + epoch, expiresAt: Date.now() + ttl };
    await authority.apply(grant, {
      updateStore: () => { const store = read(); store.order = { openai: [PROFILE] }; store.lastGood = { openai: PROFILE };
        sdk.saveAuthProfileStore(store, agent, { filterExternalAuthProfiles: false, syncExternalCli: false }); return true; },
      verifyStore: () => read().order?.openai?.[0] === PROFILE && digest(read().profiles[PROFILE]) === grant.digest,
    });
    return grant;
  };
  const rawModel = { id: "synthetic-model", name: "Synthetic dispatch fixture", provider: "openai", api: "openai-completions",
    baseUrl: "http://127.0.0.1:" + fixturePort + "/v1", reasoning: false, input: ["text"],
    cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 }, contextWindow: 8192, maxTokens: 64 };
  const prepare = async () => {
    const auth = await sdk.getApiKeyForModel({ model: rawModel, cfg, agentDir: agent, profileId: PROFILE });
    check("actual_resolver_owns_selected_profile_" + epoch, auth.profileId === PROFILE && auth.apiKey === CREDENTIAL.key);
    return { auth, model: modelAuth.n(rawModel, auth) };
  };
  const fetchArgs = (prepared, pathname, extra = {}) => ({ url: "http://" + FIXTURE_HOSTNAME + ":" + fixturePort + pathname,
    init: { headers: { authorization: "Bearer " + prepared.auth.apiKey } },
    capture: { meta: { provider: prepared.model.provider, model: prepared.model.id } },
    [REQUEST_CAPABILITY_SYMBOL]: registry.captureModelDispatch(prepared.model),
    dispatcherPolicy: { mode: "direct" }, policy: { allowPrivateNetwork: true }, timeoutMs: 10000,
    lookupFn: async hostname => { if (hostname !== FIXTURE_HOSTNAME) fail("fixture_dns_scope_escape"); return [{ address: "127.0.0.1", family: 4 }]; }, ...extra });
  const consume = async options => { const result = await guard.r(options); try { await result.response.text(); return result.response.status; } finally { await result.release(); } };
  const denied = async (name, request, pathname, before = count(pathname)) => {
    let wasDenied = false;
    try { await request(); } catch (error) { wasDenied = /^(authbus_|admission_)/.test(error.diagnosticCode ?? ""); }
    check(name + "_denied", wasDenied);
    check(name + "_zero_receiver_delta", count(pathname) === before);
  };

  await apply();
  const first = await prepare();
  const completion = await simple.t({ model: first.model, auth: first.auth, cfg,
    context: { messages: [{ role: "user", content: "synthetic dispatch check", timestamp: Date.now() }] }, options: { maxTokens: 8 } });
  check("actual_simple_completion_reaches_loopback_receiver", count("/v1/chat/completions") === 1);
  check("actual_simple_completion_parses_fixture_answer", completion.content?.some(part => part.type === "text" && part.text.includes("synthetic-dispatch-ok")));
  report.actualSimpleCompletion = true;
  report.actualLoopbackHttp = true;
  const boundFetch = stream.a(first.model, 10000, { sanitizeSse: false });
  const direct = await boundFetch("http://127.0.0.1:" + fixturePort + "/transport-positive", { headers: { authorization: "Bearer " + first.auth.apiKey } });
  check("actual_model_fetch_positive", direct.status === 200 && count("/transport-positive") === 1); await direct.text();

  const expiring = await apply(1500), expiryPrepared = await prepare();
  let delayedLookupEntered = false;
  const expiryOptions = fetchArgs(expiryPrepared, "/expiry-after-dns", { lookupFn: async hostname => {
    if (hostname !== FIXTURE_HOSTNAME) fail("fixture_dns_scope_escape");
    delayedLookupEntered = true; await sleepUntil(expiring.expiresAt + 50);
    return [{ address: "127.0.0.1", family: 4 }];
  } });
  await denied("expiry_after_actual_async_dns", () => consume(expiryOptions), "/expiry-after-dns");
  check("actual_dns_pause_entered_and_natural_deadline_elapsed", delayedLookupEntered && Date.now() > expiring.expiresAt);
  report.naturalDeadlineWaited = true;
  check("expiry_is_durably_closed", JSON.parse(fs.readFileSync(authority.filename)).phase === "expired");

  await apply();
  const stale = await prepare(), staleOptions = fetchArgs(stale, "/failed-revocation");
  const { DatabaseSync } = await import("node:sqlite");
  const db = new DatabaseSync(databasePath);
  const before = digest(read());
  const revoke = { epoch: ++epoch, status: "UNASSIGNED", mode: "enforce", model: "synthetic-model" };
  db.exec("CREATE TRIGGER authbus_dispatch_abort BEFORE INSERT ON auth_profile_state BEGIN SELECT RAISE(ABORT,'synthetic_dispatch_revoke_abort'); END");
  let failed = false;
  try { await authority.apply(revoke, { updateStore: async () => {
    const saved = await sdk.setAuthProfileOrder({ agentDir: agent, provider: "openai", order: [], explicitDeny: true });
    if (!saved) fail("synthetic_dispatch_revoke_abort");
    return saved;
  }, verifyStore: () => read().order?.openai?.length === 0 }); }
  catch { failed = true; }
  finally { db.exec("DROP TRIGGER authbus_dispatch_abort"); db.close(); }
  check("real_sqlite_abort_preserves_previous_store", failed && digest(read()) === before);
  check("failed_revoke_is_durable_pending", JSON.parse(fs.readFileSync(authority.filename)).phase === "pending");
  report.actualSqlite = true;
  await denied("failed_revoke_after_actual_resolution", () => consume(staleOptions), "/failed-revocation");
  await authority.apply(revoke, { updateStore: async () => {
    const saved = await sdk.setAuthProfileOrder({ agentDir: agent, provider: "openai", order: [], explicitDeny: true });
    if (!saved) fail("fixture_revocation_recovery_failed");
    return saved;
  }, verifyStore: () => read().order?.openai?.length === 0 && !read().lastGood?.openai });
  await apply();
  const current = await prepare();
  await denied("old_capability_after_higher_epoch", () => consume({ ...staleOptions, url: "http://" + FIXTURE_HOSTNAME + ":" + fixturePort + "/stale-epoch" }), "/stale-epoch");
  await denied("wrong_wire_credential", () => consume(fetchArgs(current, "/wrong-wire", { init: { headers: { authorization: "Bearer synthetic-wrong-wire" } } })), "/wrong-wire");
  await denied("missing_capability", () => consume(fetchArgs(current, "/missing-capability", { [REQUEST_CAPABILITY_SYMBOL]: null })), "/missing-capability");

  const redirectGrant = await apply(1500), redirectPrepared = await prepare();
  redirectDeadline = redirectGrant.expiresAt;
  const redirectOptions = fetchArgs(redirectPrepared, "/redirect-expire");
  await denied("redirect_after_natural_expiry", () => consume(redirectOptions), "/redirect-target");
  check("redirect_first_request_was_authorized", count("/redirect-expire") === 1);
  check("all_network_was_scoped_to_fixture", report.externalNetworkAttempts === 0 && report.externalProcessAttempts === 0);
  report.actualSharedLlmHttpDispatchQualified = true;
  report.dispatchObservations = registry.dispatchObservations;
  report.receiverCounts = Object.fromEntries(counts);
  report.remainingBlockers = ["non_llm_dispatch_callers_not_integrated", "derived_runtime_credentials_not_qualified",
    "oauth_refresh_lease_ownership_not_qualified", "production_gateway_authority_bootstrap_not_integrated",
    "cold_same_epoch_control_reconciliation_requires_additional_freshness_protocol"];
  report.ok = true;
} catch (error) {
  report.ok = false;
  report.errorCode = error.diagnosticCode ?? "actual_dispatch_regression_failed";
  report.errorSha256 = sha256(String(error.message));
} finally {
  try { report.installedSdkUnchanged = verifyInstalledSdkUnchanged(openclawRoot) && verifyDispatchSdkUnchanged(openclawRoot); }
  catch { report.installedSdkUnchanged = false; }
  report.candidateSourcesUnchanged = report.candidateSourceBindings.every(binding => sha256(fs.readFileSync(path.join(toolsDirectory, binding.relative))) === binding.sha256);
  report.diagnosticsRedacted = !JSON.stringify(report).includes(CREDENTIAL.key);
  report.ok &&= report.installedSdkUnchanged && report.candidateSourcesUnchanged && report.diagnosticsRedacted;
  dispatchHook?.deregister(); sdkHook?.deregister(); uninstall?.();
  net.Socket.prototype.connect = originalConnect;
  for (const [name, implementation] of Object.entries(originalProcess)) childProcess[name] = implementation;
  syncBuiltinESMExports();
  if (server) { server.closeAllConnections?.(); await new Promise(resolve => server.close(resolve)); }
  fs.writeFileSync(path.join(root, "public.json"), JSON.stringify(report, null, 2) + "\n", { mode: 0o600 });
  process.stdout.write(JSON.stringify(report) + "\n");
  if (!report.ok) process.exitCode = 3;
}
