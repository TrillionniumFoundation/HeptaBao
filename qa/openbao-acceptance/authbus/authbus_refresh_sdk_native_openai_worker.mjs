#!/usr/bin/env node
/** Actual installed SDK worker for the parent-owned native HeptaBao fixture.
 * Only the parent owns the native process, TLS proxy and synthetic provider.
 * No file or HTTP witness here can mint a trusted admission proof. A new Node
 * process always constructs new source/authority objects over the actual old
 * SQLite/authority files and must obtain a fresh, higher native CAS epoch.
 */
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { createRequire } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";
import { digest } from "./authbus_admission_authority_candidate.mjs";
import { TrustedAdmissionAuthority, applyFromTrustedControl } from "./authbus_trusted_admission_candidate.mjs";
import { TrustedBaoControlSource, TrustedBaoCoordinator } from "./authbus_trusted_control_candidate.mjs";
import { SdkOAuthRefreshAdmissionRegistry } from "./authbus_refresh_sdk_registry_candidate.mjs";
import { installOAuthRefreshSdkCandidate, verifyOAuthRefreshSdkUnchanged } from "./authbus_refresh_sdk_candidate.mjs";
import { fail, hash, inside, readOwned, durable, selectOwnedSdkEntrypoint, installFixtureSafety }
  from "./authbus_refresh_sdk_native_openai_fixture.mjs";
import { createOwnedOpenAiConnectProxy, ownOpenAiFixtureEnvironment, ownOpenAiFixtureTrust }
  from "./authbus_refresh_sdk_openai_fixture.mjs";

const PROVIDER_COUNTS = Object.freeze({ "manager-success": 1, "intent-ack-lost": 0, "provider-ack-lost": 1,
  "sqlite-abort": 1, "guard-after-await": 0 });
const CASES = Object.freeze(Object.keys(PROVIDER_COUNTS));
const RUNTIME_FILES = Object.freeze(["authbus_refresh_sdk_caller_live.mjs", "authbus_refresh_sdk_candidate.mjs",
  "authbus_refresh_sdk_registry_candidate.mjs", "authbus_refresh_store_sdk_candidate.mjs", "authbus_refresh_registry_candidate.mjs",
  "authbus_trusted_control_candidate.mjs", "authbus_trusted_admission_candidate.mjs", "authbus_admission_authority_candidate.mjs",
  "authbus_admission_registry_candidate.mjs", "authbus_dispatch_registry_candidate.mjs", "authbus_dispatch_sdk_candidate.mjs",
  "authbus_sdk_admission_candidate.mjs", "authbus_sdk_explicit_deny_candidate.mjs",
  "authbus_refresh_sdk_native_openai_fixture.mjs", "authbus_refresh_sdk_native_openai_worker.mjs",
  "authbus_refresh_sdk_openai_fixture.mjs"]);
const here = path.dirname(fileURLToPath(import.meta.url));
const privateDirectory = directory => {
  if (!path.isAbsolute(directory) || fs.realpathSync(directory) !== directory) fail("native_sdk_directory_not_canonical");
  const stat = fs.lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid() || (stat.mode & 0o077) !== 0)
    fail("native_sdk_directory_not_private");
};
function loadConfiguration() {
  if (process.argv.length !== 4 || process.argv[2] !== "--config" || !path.isAbsolute(process.argv[3])) fail("native_sdk_config_cli_invalid");
  const configPath = process.argv[3], configBytes = readOwned(configPath), config = JSON.parse(configBytes.toString("utf8"));
  if (config.schema !== "authbus-native-openai-refresh-sdk-worker-v1" || !["warm", "cold-before-server", "cold-after-server"].includes(config.phase) ||
      !/^[0-9]{1,30}$/.test(config.originalDeadlineNs) || !Array.isArray(config.cases) ||
      JSON.stringify(config.cases.map(value => value.scenario)) !== JSON.stringify(CASES)) fail("native_sdk_config_shape_invalid");
  for (const dir of [config.parentRoot, config.root]) privateDirectory(dir);
  if (!inside(config.root, config.parentRoot) || config.root === config.parentRoot || !inside(configPath, config.root))
    fail("native_sdk_fixture_scope_invalid");
  const sdkRoot = fs.realpathSync(config.sdkRoot);
  if (sdkRoot !== config.sdkRoot || !path.isAbsolute(sdkRoot) || inside(sdkRoot, config.parentRoot) || inside(config.parentRoot, sdkRoot))
    fail("native_sdk_package_scope_invalid");
  const validPort = value => Number.isInteger(value) && value > 1023 && value <= 65535;
  if (!validPort(config.controlPort) || !validPort(config.providerPort) || config.controlPort === config.providerPort)
    fail("native_sdk_fixture_ports_invalid");
  if (!inside(config.caFile, config.root) || !inside(config.reportFile, config.root) || !path.isAbsolute(config.reportFile))
    fail("native_sdk_fixture_file_scope_invalid");
  for (const role of ["reader", "issuer"]) for (const field of ["roleIdFile", "secretIdFile"])
    if (!path.isAbsolute(config[role]?.[field] ?? "") || !inside(config[role][field], config.root)) fail("native_sdk_role_scope_invalid");
  for (const item of config.cases) {
    if (item.original?.type !== "oauth" || item.original.provider !== "openai" || item.original.expires !== 1 ||
        typeof item.original.access !== "string" || !item.original.access.startsWith("synthetic-") ||
        typeof item.original.refresh !== "string" || !item.original.refresh.startsWith("synthetic-") ||
        digest(item.original) !== item.originalDigest) fail("native_sdk_synthetic_fixture_invalid");
  }
  if (!Array.isArray(config.sourceManifest) || config.sourceManifest.length !== RUNTIME_FILES.length ||
      !RUNTIME_FILES.every(name => config.sourceManifest.filter(value => value.name === name).length === 1)) fail("native_sdk_source_manifest_invalid");
  const sourceManifest = RUNTIME_FILES.map(name => ({ name, sha256: hash(fs.readFileSync(path.join(here, name))) }));
  if (!sourceManifest.every(item => config.sourceManifest.find(value => value.name === item.name)?.sha256 === item.sha256))
    fail("native_sdk_source_pin_mismatch");
  if (process.hrtime.bigint() >= BigInt(config.originalDeadlineNs)) fail("native_sdk_original_deadline");
  return { config, configPath, configSha256: hash(configBytes), sourceManifest, sdkRoot };
}

async function main() {
  process.umask(0o077);
  const { config, configPath, configSha256, sourceManifest, sdkRoot } = loadConfiguration();
  const root = config.root, phase = config.phase, warm = phase === "warm";
  const report = { schema: "authbus-refresh-r5-native-openai-sdk-worker", ok: false, phase,
    syntheticCredentials: true, syntheticProvider: true, tlsControlEmulator: false,
    actualSdk: false, actualSqlite: false, actualSdkOAuthManager: false, actualProviderHttps: false,
    actualNativeHeptaBao: false, nativeBackendQualifiedByParentOnly: true, actualColdSdkProcess: false,
    actualOpenAiSdkOAuthManager: false, actualOpenAiSdkGuard: false, actualOpenAiFacade: false,
    actualUndiciRuntimeBound: false, actualUndiciRefreshTransport: false,
    realExternalProvider: false, productionMutation: false, parentPid: process.ppid, pid: process.pid,
    nodeVersion: process.version, originalDeadlineNs: config.originalDeadlineNs, configSha256, sourceManifest,
    externalNetworkAttempts: 0, externalProcessAttempts: 0, outsideFixtureWriteAttempts: 0,
    outsideFixtureHomeReadAttempts: 0, blockedHomeReads: [], checks: [], cases: [],
    ownedUndiciProxy: { connections: 0, denials: 0, upstreamFailures: 0 } };
  const check = (name, passed) => { report.checks.push({ case: name, passed: Boolean(passed) }); if (!passed) fail(name); };
  const expectFailure = async (name, action, exactCode) => {
    let error; try { await action(); } catch (caught) { error = caught; }
    check(name, Boolean(error) && (!exactCode || error.diagnosticCode === exactCode));
    return error?.diagnosticCode ?? "sdk_refused";
  };
  const state = path.join(root, "state"), mainAgent = path.join(state, "agents/main/agent"), cfgPath = path.join(state, "openclaw.json");
  const cfg = { agents: { list: [{ id: "main", default: true, agentDir: mainAgent }] } };
  if (warm) {
    for (const dir of [state, path.join(state, "agents"), path.join(state, "agents/main"), mainAgent,
      path.join(state, "home"), path.join(state, "credentials")]) fs.mkdirSync(dir, { mode: 0o700 });
    durable(cfgPath, cfg, { create: true });
  } else {
    for (const dir of [state, mainAgent, path.join(state, "home"), path.join(state, "credentials")]) privateDirectory(dir);
    check("cold:owned_config_unchanged", digest(JSON.parse(readOwned(cfgPath).toString("utf8"))) === digest(cfg));
  }
  process.env.OPENCLAW_STATE_DIR = state;
  process.env.OPENCLAW_CONFIG_PATH = cfgPath;
  process.env.OPENCLAW_HOME = path.join(state, "home");
  process.env.OPENCLAW_OAUTH_DIR = path.join(state, "credentials");
  for (const key of ["GOOGLE_API_KEY", "GEMINI_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "OPENCLAW_GATEWAY_TOKEN",
    "CHUTES_CLIENT_ID", "CHUTES_CLIENT_SECRET", "OPENCLAW_BUNDLED_PLUGINS_DIR", "OPENCLAW_TEST_TRUST_BUNDLED_PLUGINS_DIR"])
    delete process.env[key];
  process.env.OPENCLAW_BUNDLED_PLUGINS_DIR = path.join(sdkRoot, "dist/extensions");
  if (process.env.OPENCLAW_AUTH_STORE_READONLY === "1") fail("native_sdk_inherited_readonly_store");
  const certificate = readOwned(config.caFile);
  const previousArgv = process.argv[1], previousCwd = process.cwd();
  let hook, safety, uninstall, database, source, coordinator, oldCoordinator, sdkDiscovery;
  let proxy, trust, environment, activeCell, undiciGlobal, originalUndiciDispatcher, undiciPackagePin;
  const diagnostics = { stdoutBytes: 0, stderrBytes: 0 }, diagnosticHashes = {}, outputRestores = [];
  for (const name of ["stdout", "stderr"]) {
    const originalWrite = process[name].write, h = crypto.createHash("sha256"); diagnosticHashes[name] = h;
    process[name].write = function (chunk, encoding, callback) {
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), typeof encoding === "string" ? encoding : "utf8");
      diagnostics[name + "Bytes"] += bytes.length; h.update(bytes);
      if (typeof encoding === "function") encoding(); else if (typeof callback === "function") callback();
      return true;
    };
    outputRestores.push(() => { process[name].write = originalWrite; });
  }
  try {
    environment = ownOpenAiFixtureEnvironment(); environment.clearProxy();
    proxy = await createOwnedOpenAiConnectProxy({ providerPort: config.providerPort, activeCell: () => activeCell,
      observations: report.ownedUndiciProxy });
    trust = ownOpenAiFixtureTrust(certificate);
    safety = installFixtureSafety({ sdkRoot, root, parentRoot: config.parentRoot, deadlineNs: config.originalDeadlineNs,
      controlPort: config.controlPort, providerPort: config.providerPort, connectProxyPort: proxy.port, certificate, report });
    safety.setPhase("sdk-import");
    sdkDiscovery = selectOwnedSdkEntrypoint(sdkRoot); process.argv[1] = sdkDiscovery.entrypoint; process.chdir(sdkRoot);
    report.sdkDiscoveryContext = { relative: sdkDiscovery.relative, packageSha256: sdkDiscovery.packageSha256,
      entrypointSha256: sdkDiscovery.entrypointSha256, fixtureArgvAndCwdOnly: true, entrypointExecuted: false };
    check("sdk_discovery_matches_exact_owner", sdkDiscovery.packageSha256 === "695b6ee36df7fc69606dc390cf97bb2ca809114337b18c573707637cd2a4e3db" &&
      sdkDiscovery.entrypointSha256 === "f643b005d6db233a0b45204e8d8e943256874ccc6897b8a6e0cf42a9b376a188");
    hook = installOAuthRefreshSdkCandidate(sdkRoot, report); report.qualification = await hook.loadOwnedRefreshFunctions();
    const sdk = await import(pathToFileURL(path.join(sdkRoot, "dist/plugin-sdk/agent-runtime.js")).href);
    const bridge = await import(pathToFileURL(path.join(sdkRoot, "dist/profiles-DyU-YCq2.js")).href);
    const oauth = await import(pathToFileURL(path.join(sdkRoot, "dist/oauth-B4aOCsid.js")).href);
    const oauthLib = await import(pathToFileURL(path.join(sdkRoot, "dist/oauth-BcZS_BvC.js")).href);
    const facadeTracker = await import(pathToFileURL(path.join(sdkRoot, "dist/facade-loader-ClPyIgA5.js")).href);
    const activeProxyState = await import(pathToFileURL(path.join(sdkRoot, "dist/active-proxy-state-DJLhrP_Z.js")).href);
    const undiciRuntime = await import(pathToFileURL(path.join(sdkRoot, "dist/undici-runtime-BL8ZN-Ey.js")).href);
    check("undici:no_injected_runtime_or_existing_managed_proxy", globalThis.__OPENCLAW_TEST_UNDICI_RUNTIME_DEPS__ === undefined &&
      activeProxyState.r() === undefined && activeProxyState.n() === undefined);
    const sdkRequire = createRequire(pathToFileURL(path.join(sdkRoot, "dist/undici-runtime-BL8ZN-Ey.js")));
    const actualUndici = sdkRequire("undici");
    const packageFile = fs.realpathSync(sdkRequire.resolve("undici/package.json"));
    const entryFile = fs.realpathSync(sdkRequire.resolve("undici"));
    const packageStat = fs.lstatSync(packageFile), entryStat = fs.lstatSync(entryFile);
    check("undici:owned_actual_package", inside(packageFile, sdkRoot) && packageStat.isFile() && !packageStat.isSymbolicLink() && packageStat.size <= 65536 &&
      inside(entryFile, sdkRoot) && entryStat.isFile() && !entryStat.isSymbolicLink() && entryStat.size <= 262144);
    const packageBytes = fs.readFileSync(packageFile), packageInfo = JSON.parse(packageBytes);
    undiciPackagePin = { file: packageFile, sha256: hash(packageBytes), entryFile, entrySha256: hash(fs.readFileSync(entryFile)) };
    check("undici:actual_qualified_fetch_function_identity", packageInfo.name === "undici" && packageInfo.version === "8.5.0" &&
      undiciPackagePin.sha256 === "4eed584bdf6a1545381c24674dfe8938421f7c66313c8960fb40f28f3a55c306" &&
      undiciPackagePin.entrySha256 === "93fc85c00a59b58f410c901e5477d56770de3816bfbe183e751624aeb4a5e6a5" &&
      typeof actualUndici.fetch === "function" && undiciRuntime.a().fetch === actualUndici.fetch && globalThis.fetch.mock === undefined);
    undiciGlobal = undiciRuntime.i(); originalUndiciDispatcher = undiciGlobal.getGlobalDispatcher();
    report.undiciRuntimeBinding = { packageVersion: packageInfo.version, packageRelative: path.relative(sdkRoot, packageFile),
      packageSha256: undiciPackagePin.sha256, entryRelative: path.relative(sdkRoot, entryFile), entrySha256: undiciPackagePin.entrySha256,
      libraryPinScope: "package-metadata-and-entrypoint", testRuntimeOverride: false, dnsOverride: false,
      route: "actual-sdk-managed-env-proxy", actualPackageFetchIdentity: true };
    report.actualUndiciRuntimeBound = true;
    environment.useProxy(proxy.origin);
    const sdkSource = await import(pathToFileURL(path.join(sdkRoot, "dist/source-check-ZSz5NzGW.js")).href);
    const sdkCredentialState = await import(pathToFileURL(path.join(sdkRoot, "dist/credential-state-BY-oz-QV.js")).href);
    check("actual_sdk_required_interfaces", typeof oauth.n === "function" && typeof bridge.heptaBaoCommitManagedOAuthCredential === "function" &&
      typeof sdk.saveAuthProfileStore === "function" && typeof sdk.resolveProviderIdForAuth === "function" &&
      typeof sdkSource.v === "function" && sdkCredentialState.t === 300000);
    report.actualSdk = true; report.sdkVersion = "2026.7.1-2"; report.sdkOAuthRefreshMarginMs = sdkCredentialState.t;
    const readStore = hook.qualification.readOwnedStore;
    const writeStore = (agentDir, profileId, providerId, credential) => sdk.saveAuthProfileStore({ version: 1,
      profiles: { [profileId]: credential }, order: { [providerId]: [profileId] }, lastGood: { [providerId]: profileId } }, agentDir,
      { filterExternalAuthProfiles: false, syncExternalCli: false });
    for (const item of config.cases) {
      safety.remainingMs();
      const scenario = item.scenario, cellRoot = path.join(root, scenario), agentDir = path.join(cellRoot, "agent"), directory = path.join(cellRoot, "authority");
      if (warm) for (const dir of [cellRoot, agentDir, directory]) fs.mkdirSync(dir, { mode: 0o700 });
      else for (const dir of [cellRoot, agentDir, directory]) privateDirectory(dir);
      const providerId = sdk.resolveProviderIdForAuth("openai", { config: cfg });
      check(scenario + ":actual_provider_binding", providerId === "openai");
      const profileId = "openai:authbus-r5-native-" + scenario, original = item.original;
      const scope = { hostId: "sdk-r5-native-openai-fixture", agentId: scenario, agentDir, provider: providerId };
      const baseBinding = { scope, model: "synthetic-r5-native-openai-model", profileId, credentialDigest: digest(original) };
      const cell = { transport: "undici", undiciConnects: 0, fenceChangedDuringGuardAwait: false }; activeCell = cell;
      const recordPath = path.join(cellRoot, "cold-owner.json");
      const previous = warm ? null : JSON.parse(readOwned(recordPath).toString("utf8"));
      if (warm) {
        safety.setPhase(scenario + ":scoped-seed"); writeStore(agentDir, profileId, providerId, original);
        safety.setPhase(scenario + ":main-seed"); writeStore(mainAgent, profileId, providerId,
          { ...original, access: "synthetic-main-access-" + scenario, refresh: "synthetic-main-refresh-" + scenario, expires: Date.now() + 3600000 });
        check(scenario + ":actual_sqlite_seed", fs.existsSync(path.join(agentDir, "openclaw-agent.sqlite")) &&
          digest(readStore(agentDir).profiles[profileId]) === digest(original) && !sdkSource.v(original));
      } else {
        check(scenario + ":cold_distinct_process_and_same_scope", previous.schema === "authbus-r5-native-openai-cold-owner-v1" &&
          previous.pid !== process.pid && previous.phase !== phase && digest(previous.scope) === digest(scope));
        check(scenario + ":cold_actual_sqlite_exact_readback", fs.existsSync(path.join(agentDir, "openclaw-agent.sqlite")) &&
          previous.credentialDigest === digest(readStore(agentDir).profiles[profileId]));
      }
      report.actualSqlite = true;
      const current = readStore(agentDir).profiles[profileId], beforeStoreDigest = digest(readStore(agentDir));
      const control = { schemaVersion: 1, address: "https://127.0.0.1:" + config.controlPort, caFile: config.caFile,
        kvMount: "authbus", controlPath: scenario, issuerId: "r5-sdk-native-fixture", maxLeaseMs: 30000,
        reader: config.reader, issuer: config.issuer };
      source = new TrustedBaoControlSource(control);
      const binding = { ...baseBinding, credentialDigest: digest(current) };
      coordinator = new TrustedBaoCoordinator(control, { bindings: [binding] });
      const authority = new TrustedAdmissionAuthority({ directory, scope, controlSource: source });
      const registry = new SdkOAuthRefreshAdmissionRegistry({ authorities: [authority], resolveDefaultAgentDir: () => mainAgent,
        resolveProviderIdForAuth: sdk.resolveProviderIdForAuth, readStore, sdkRefreshQualification: hook.qualification,
        refreshBindings: [{ scope, controlSource: source, coordinator, commitCredential: bridge.heptaBaoCommitManagedOAuthCredential, leaseMs: 10000 }] });
      uninstall = registry.install();
      const params = { cfg, store: readStore(agentDir), agentDir, profileId, credential: current };
      let failureCode, abortTriggerCount = 0;
      safety.setPhase(scenario + (warm ? ":warm-native" : ":cold-native"));
      if (warm) {
        await coordinator.issue(source.bootstrapRequest(scope, binding), { leaseMs: 10000 });
        await applyFromTrustedControl({ authority, controlSource: source, updateStore: () => true,
          verifyStore: grant => grant.digest === digest(readStore(agentDir).profiles[profileId]) });
        check(scenario + ":native_trusted_initial_admission", authority.inspect().allowed);
        check(scenario + ":actual_native_reader_write_denied", await source.probeWriteDenial());
        check(scenario + ":actual_native_reader_renewed", await source.renew());
        check(scenario + ":actual_native_issuer_renewed", await coordinator.renew());
        const oldPermit = authority.inspect();
        if (scenario === "manager-success") {
          const resolved = await oauth.n(params), stored = readStore(agentDir).profiles[profileId];
          check("manager:actual_sdk_refresh_committed", resolved?.apiKey === stored.access && stored.access !== original.access &&
            stored.refresh !== original.refresh && sdkSource.v(stored));
          check("manager:strict_successor_epoch", authority.inspect().allowed && authority.inspect().epoch > oldPermit.epoch &&
            authority.inspect().credentialDigest === digest(stored));
          registry.advanceAfterRefresh(params, oldPermit, profileId, resolved.apiKey);
          await expectFailure("manager:old_wire_cannot_use_successor", () => registry.advanceAfterRefresh(params, oldPermit, profileId, original.access));
          await expectFailure("manager:successor_without_scope_denied", () => registry.advanceAfterRefresh({ cfg, agentDir }, oldPermit, profileId, resolved.apiKey));
          await expectFailure("manager:successor_cannot_claim_unmanaged", () => registry.advanceAfterRefresh({ ...params, provider: "unmanaged-fixture-provider" }, oldPermit, profileId, resolved.apiKey));
          check("manager:actual_one_shot_dispatch", registry.oauthSdkObservations.allowedDispatches === 1 && registry.refreshObservations.published === 1);
          check("openai:actual_guard_request_and_runtime_dispatch", registry.oauthSdkObservations.guardedRequests === 1 &&
            registry.oauthSdkObservations.guardedRuntimeEntries === 1 && cell.undiciConnects === 1);
          check("openai:actual_activated_facade_loaded", facadeTracker.n().includes("openai") &&
            report.oauthRefreshSdkModules.find(item => item.relative === "dist/extensions/openai/api.js")?.loaded === true);
          report.actualSdkOAuthManager = true; report.actualProviderHttps = true;
          report.actualOpenAiSdkOAuthManager = true; report.actualOpenAiSdkGuard = true;
          report.actualOpenAiFacade = true; report.actualUndiciRefreshTransport = true;
        } else {
          const triggers = [];
          if (scenario === "sqlite-abort") {
            const { DatabaseSync } = await import("node:sqlite"); database = new DatabaseSync(path.join(agentDir, "openclaw-agent.sqlite"));
            const tables = database.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' AND sql NOT LIKE 'CREATE VIRTUAL%'").all();
            const quote = value => '"' + value.replaceAll('"', '""') + '"';
            for (let i = 0; i < tables.length; i++) for (const event of ["INSERT", "UPDATE"]) {
              const name = "r5_native_abort_" + i + "_" + event.toLowerCase(); triggers.push(name);
              database.exec("CREATE TRIGGER " + quote(name) + " BEFORE " + event + " ON " + quote(tables[i].name) + " BEGIN SELECT RAISE(ABORT,'synthetic_r5_native_abort'); END");
            }
            abortTriggerCount = triggers.length;
            check("sqlite-abort:actual_18_abort_triggers", abortTriggerCount === 18);
          }
          let invoke = () => oauth.n(params);
          if (scenario === "guard-after-await") {
            // Same real guard fault as SDK32: UNKNOWN is already durable when
            // the registered adapter invokes the actual SDK OpenAI refresh.
            // The mock-branch probe only queues a fence closure and returns
            // undefined; it never supplies a fetch or Undici implementation.
            const adapter = { needsRefresh: true, buildApiKey: credential => credential.access,
              refreshCredential: async credential => {
                const descriptor = Object.getOwnPropertyDescriptor(globalThis.fetch, "mock");
                let queued = false;
                Object.defineProperty(globalThis.fetch, "mock", { configurable: true, get() {
                  if (!queued) { queued = true; queueMicrotask(() => {
                    authority.closeUnresolved(); cell.fenceChangedDuringGuardAwait = true;
                  }); }
                  return undefined;
                } });
                try { return await oauthLib.n("openai").refreshToken(credential); }
                finally { if (descriptor) Object.defineProperty(globalThis.fetch, "mock", descriptor); else delete globalThis.fetch.mock; }
              } };
            invoke = () => registry.resolveManagedOAuthAccess(params, adapter);
          }
          try { failureCode = await expectFailure(scenario + ":actual_refresh_path_refuses_unknown_outcome", invoke); }
          finally {
            if (database) { for (const name of triggers) database.exec('DROP TRIGGER "' + name + '"'); database.close(); database = null; }
          }
          check(scenario + ":admission_remains_closed", !authority.inspect().allowed);
          check(scenario + ":actual_sqlite_original_retained", digest(readStore(agentDir)) === beforeStoreDigest);
          if (scenario === "guard-after-await") check("openai:actual_guard_await_fence_veto", cell.fenceChangedDuringGuardAwait &&
            registry.oauthSdkObservations.guardedRequests === 1 && registry.oauthSdkObservations.allowedDispatches === 0);
          await expectFailure(scenario + ":same_sdk_retry_denied", () => oauth.n({ ...params, store: readStore(agentDir) }));
          await expectFailure(scenario + ":native_unknown_issue_denied", () => coordinator.issue(source.bootstrapRequest(scope, binding), { leaseMs: 10000 }),
            "trusted_refresh_outcome_unknown");
          check(scenario + ":bounded_final_dispatches", registry.oauthSdkObservations.allowedDispatches === PROVIDER_COUNTS[scenario]);
        }
      } else {
        check(scenario + ":cold_source_new_boot_same_provenance", source.identity.bootId !== previous.bootId && source.identity.sourceDigest === previous.sourceDigest);
        check(scenario + ":cold_authority_starts_closed", !authority.inspect().allowed);
        await expectFailure(scenario + ":cold_sdk_cannot_use_cached_positive", () => oauth.n(params));
        await expectFailure(scenario + ":cold_old_native_grant_not_boot_proof", () => applyFromTrustedControl({ authority, controlSource: source,
          updateStore: () => fail("cold_untrusted_store_update_forbidden"), verifyStore: () => true }));
        if (scenario === "manager-success") {
          oldCoordinator = new TrustedBaoCoordinator(control, { bindings: [baseBinding] });
          await expectFailure("cold:published_original_digest_is_fenced", () => oldCoordinator.issue(source.bootstrapRequest(scope, baseBinding), { leaseMs: 10000 }),
            "trusted_refresh_old_credential_fenced");
          const oldClose = await oldCoordinator.close(); oldCoordinator = null;
          check("cold:old_issuer_bearer_revoked", oldClose.revoked && oldClose.coldDenied);
          const fresh = await coordinator.issue(source.bootstrapRequest(scope, binding), { leaseMs: 10000, epochFloor: previous.epoch });
          check("cold:fresh_native_higher_epoch", fresh.grant.epoch > previous.epoch && fresh.bootId === source.identity.bootId);
          await applyFromTrustedControl({ authority, controlSource: source, updateStore: () => true,
            verifyStore: grant => grant.digest === digest(readStore(agentDir).profiles[profileId]) });
          const resolved = await oauth.n({ ...params, store: readStore(agentDir) });
          check("cold:actual_sdk_uses_published_credential_after_fresh_grant", resolved?.apiKey === current.access &&
            digest(resolved.credential) === binding.credentialDigest && digest(readStore(agentDir)) === beforeStoreDigest && authority.inspect().allowed);
          // resolveApiKeyForProfile selects the credential from its supplied
          // store, not an extra credential parameter. Exercise that real stale
          // caller entry while leaving the actual SQLite owner unchanged.
          await expectFailure("cold:actual_sdk_stale_original_cannot_use_fresh_grant", () => oauth.n({ ...params,
            store: { ...readStore(agentDir), profiles: { [profileId]: original } } }));
          check("cold:usable_resolution_without_provider", registry.oauthSdkObservations.usableResolutions === 1 && registry.oauthSdkObservations.allowedDispatches === 0);
        } else {
          failureCode = await expectFailure(scenario + ":cold_native_unknown_still_denied", () => coordinator.issue(source.bootstrapRequest(scope, binding), { leaseMs: 10000,
            epochFloor: previous.epoch }), "trusted_refresh_outcome_unknown");
          await expectFailure(scenario + ":cold_sdk_retry_still_denied", () => oauth.n({ ...params, store: readStore(agentDir) }));
          check(scenario + ":cold_unknown_keeps_old_store_closed", !authority.inspect().allowed && digest(readStore(agentDir)) === beforeStoreDigest);
          check(scenario + ":cold_zero_provider_dispatch", registry.oauthSdkObservations.allowedDispatches === 0);
        }
      }
      const storedDigest = digest(readStore(agentDir).profiles[profileId]), local = authority._read();
      const expectedConnects = warm ? PROVIDER_COUNTS[scenario] : 0;
      check(scenario + ":actual_undici_route_exact_without_mapped_fetch", cell.undiciConnects === expectedConnects &&
        registry.oauthSdkObservations.allowedDispatches === expectedConnects &&
        registry.oauthSdkObservations.guardedRuntimeEntries === expectedConnects && globalThis.fetch.mock === undefined);
      durable(recordPath, { schema: "authbus-r5-native-openai-cold-owner-v1", phase, pid: process.pid, scope,
        credentialDigest: storedDigest, originalDigest: digest(original), sourceDigest: source.identity.sourceDigest,
        bootId: source.identity.bootId, epoch: local.grant?.epoch ?? local.acceptedEpoch, revision: local.revision }, { create: warm });
      const row = { scenario, originalDigest: digest(original), credentialDigest: storedDigest,
        sourceDigest: source.identity.sourceDigest, bootId: source.identity.bootId, previousEpoch: previous?.epoch ?? null,
        epoch: local.grant?.epoch ?? local.acceptedEpoch, scopeDigest: digest(scope), providerDispatches: registry.oauthSdkObservations.allowedDispatches,
        undiciConnects: cell.undiciConnects, transport: "actual-sdk-undici-owned-connect",
        entrypoint: warm && scenario === "guard-after-await" ? "registered-fault-adapter-to-actual-sdk-refresh" : "actual-sdk-shared-manager",
        ...(failureCode ? { failureCode } : {}), ...(abortTriggerCount ? { abortTriggerCount } : {}),
        oauthSdkObservations: { ...registry.oauthSdkObservations }, refreshObservations: { ...registry.refreshObservations } };
      uninstall(); uninstall = null;
      const readerClose = await source.close(), issuerClose = await coordinator.close();
      check(scenario + ":actual_native_bearer_revocations", readerClose.revoked && readerClose.coldDenied && issuerClose.revoked && issuerClose.coldDenied);
      row.readerTransport = source.publicCounts(); row.issuerTransport = coordinator.publicCounts();
      source = null; coordinator = null; activeCell = null; report.cases.push(row);
    }
    safety.remainingMs();
    check("all_five_native_openai_transport_cases_completed", report.cases.length === CASES.length);
    check("no_external_network_or_process_attempt", report.externalNetworkAttempts === 0 && report.externalProcessAttempts === 0);
    check("no_outside_fixture_write_or_private_read_attempt", report.outsideFixtureWriteAttempts === 0 && report.outsideFixtureHomeReadAttempts === 0);
    check("sdk_discovery_context_unchanged", process.argv[1] === sdkDiscovery.entrypoint && process.cwd() === sdkRoot &&
      digest(selectOwnedSdkEntrypoint(sdkRoot)) === digest(sdkDiscovery));
    check("actual_required_hook_modules_loaded", ["dist/oauth-B4aOCsid.js", "dist/oauth-BcZS_BvC.js", "dist/profiles-DyU-YCq2.js",
      "dist/store-DH33UrUj.js", "dist/source-check-ZSz5NzGW.js"].every(relative => report.oauthRefreshSdkModules.find(item => item.relative === relative)?.loaded));
    if (warm) check("actual_required_openai_hook_modules_loaded", ["dist/extensions/openai/api.js",
      "dist/openai-chatgpt-provider.runtime-DGoPIR1g.js", "dist/openai-chatgpt-oauth-flow.runtime.js",
      "dist/openai-chatgpt-oauth-flow.runtime-DOVvnAqe.js", "dist/fetch-guard-6VNcgVVc.js", "dist/runtime-fetch-k5Zth7kk.js"]
      .every(relative => report.oauthRefreshSdkModules.find(item => item.relative === relative)?.loaded));
    check("undici:actual_package_entrypoint_and_runtime_override_unchanged", hash(fs.readFileSync(undiciPackagePin.file)) === undiciPackagePin.sha256 &&
      hash(fs.readFileSync(undiciPackagePin.entryFile)) === undiciPackagePin.entrySha256 &&
      globalThis.__OPENCLAW_TEST_UNDICI_RUNTIME_DEPS__ === undefined);
    check("undici:exact_five_case_transport_total", report.ownedUndiciProxy.connections === (warm ? 3 : 0) &&
      report.ownedUndiciProxy.denials === 0 && report.ownedUndiciProxy.upstreamFailures === 0);
    report.actualColdSdkProcess = !warm;
    report.ok = true;
  } catch (error) {
    report.error = { code: error.diagnosticCode ?? error.code ?? "native_sdk_worker_failure", messageSha256: hash(String(error.message)) };
  } finally {
    const cleanupErrors = [];
    for (const callback of [() => database?.close(), () => source?.close(), () => coordinator?.close(), () => oldCoordinator?.close(), () => uninstall?.()])
      try { await callback(); } catch { cleanupErrors.push("native_sdk_cleanup_failed"); }
    activeCell = null;
    try {
      if (undiciGlobal && originalUndiciDispatcher) {
        const currentDispatcher = undiciGlobal.getGlobalDispatcher();
        undiciGlobal.setGlobalDispatcher(originalUndiciDispatcher);
        if (currentDispatcher !== originalUndiciDispatcher) await currentDispatcher.destroy();
      }
    } catch { cleanupErrors.push("native_openai_dispatcher_cleanup_failed"); }
    try { await proxy?.close(); } catch { cleanupErrors.push("native_openai_proxy_cleanup_failed"); }
    try { trust?.restore(); environment?.restore(); } catch { cleanupErrors.push("native_openai_process_context_cleanup_failed"); }
    report.fixtureProcessContextRestored = Boolean(proxy?.isClosed() && trust?.isRestored() && environment?.isRestored());
    if (!report.fixtureProcessContextRestored) cleanupErrors.push("native_openai_process_context_not_restored");
    try { hook?.deregister(); } catch { cleanupErrors.push("native_sdk_hook_cleanup_failed"); }
    try { safety?.restore(); } catch { cleanupErrors.push("native_sdk_guard_cleanup_failed"); }
    process.argv[1] = previousArgv; process.chdir(previousCwd);
    for (const restore of outputRestores) restore();
    if (cleanupErrors.length) { report.ok = false; report.cleanupErrors = cleanupErrors; }
    report.diagnostics = { ...diagnostics, stdoutSha256: diagnosticHashes.stdout.digest("hex"), stderrSha256: diagnosticHashes.stderr.digest("hex"), rawOutputSuppressed: true };
    try {
      report.installedSdkUnchanged = verifyOAuthRefreshSdkUnchanged(sdkRoot);
      report.sourceFilesUnchanged = sourceManifest.every(item => hash(fs.readFileSync(path.join(here, item.name))) === item.sha256);
      report.configUnchanged = hash(readOwned(configPath)) === configSha256;
      if (!report.installedSdkUnchanged || !report.sourceFilesUnchanged || !report.configUnchanged) report.ok = false;
    } catch { report.installedSdkUnchanged = false; report.ok = false; }
    if (process.hrtime.bigint() >= BigInt(config.originalDeadlineNs)) { report.ok = false; report.originalDeadlineExceeded = true; }
    report.checksPassed = report.checks.filter(item => item.passed).length;
    durable(config.reportFile, report, { create: true });
    process.stdout.write(JSON.stringify({ schema: report.schema, ok: report.ok, phase, checksPassed: report.checksPassed,
      checksTotal: report.checks.length, pid: report.pid, receiptSha256: hash(fs.readFileSync(config.reportFile)) }) + "\n");
    if (!report.ok) process.exitCode = 1;
  }
}

await main().catch(error => {
  process.stderr.write(JSON.stringify({ schema: "authbus-native-openai-sdk-bootstrap-error", code: error.diagnosticCode ?? "native_sdk_bootstrap_failed",
    messageSha256: hash(String(error.message)) }) + "\n");
  process.exitCode = 2;
});
