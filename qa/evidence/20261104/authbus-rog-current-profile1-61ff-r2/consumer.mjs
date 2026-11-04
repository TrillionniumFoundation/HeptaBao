#!/usr/bin/env node
/** Exercise ROG source profile 1 through the original installed SDK explicit-profile resolver.
 * The new private state is populated from the real HeptaBao TLS/AppRole API.
 * No provider request, OAuth refresh or production write is permitted here.
 */
import fs from 'node:fs';
import path from 'node:path';
import https from 'node:https';
import http from 'node:http';
import childProcess from 'node:child_process';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { syncBuiltinESMExports } from 'node:module';

process.umask(0o077);
const hash = value => createHash('sha256').update(value).digest('hex');
const stable = value => Array.isArray(value) ? value.map(stable) : value && typeof value === 'object'
  ? Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])])) : value;
const digest = value => hash(JSON.stringify(stable(value)));
const report = { schema: 'heptabao.rog-current-explicit-profile-consumer.v1', ok: false,
  productionChanged: false, productionTrafficCutover: false, providerCalled: false,
  refreshDispatched: false, modelCalled: false, j3160Contacted: false,
  credentialValuesPublished: false, accountIdentitiesPublished: false,
  allAccountsQualified: false, checks: [], wire: [] };
let service, baoAgent, plan;
let blockedOperations = 0;
const tokens = [];
const sensitive = [];

function need(value, code) { if (!value) throw Object.assign(new Error(code), { safeCode: code }); }
function check(code, value) { report.checks.push({ case: code, passed: value === true }); need(value, code); }
function privateRead(file) {
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const s = fs.fstatSync(fd);
    need(s.isFile() && s.uid === process.getuid() && (s.mode & 0o077) === 0 && s.nlink === 1 && s.size <= 1024 * 1024,
      'private_file_custody');
    const data = fs.readFileSync(fd), after = fs.fstatSync(fd), current = fs.lstatSync(file);
    need([after, current].every(x => x.dev === s.dev && x.ino === s.ino && x.size === s.size && x.mtimeMs === s.mtimeMs),
      'private_file_changed');
    return data;
  } finally { fs.closeSync(fd); }
}
function save(file, value) {
  const fd = fs.openSync(file, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
  try { fs.writeFileSync(fd, JSON.stringify(value)); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}
function within(root, file) {
  const rel = path.relative(root, file);
  return rel !== '' && rel !== '..' && !rel.startsWith('../') && !path.isAbsolute(rel);
}
function deny() { blockedOperations++; throw Object.assign(new Error('unexpected_operation_refused'), { safeCode: 'unexpected_operation_refused' }); }
function secrets(credential) {
  return Object.entries(credential ?? {}).filter(([key, value]) => typeof value === 'string' && value.length >= 8
    && !['provider', 'type', 'chatgptPlanType'].includes(key)).map(([, value]) => value);
}

try {
  plan = JSON.parse(privateRead(process.argv[2]));
  report.mode = plan.mode;
  check('scoped_application_roots', process.env.OPENCLAW_STATE_DIR === plan.stateRoot
    && process.env.OPENCLAW_CONFIG_PATH === path.join(plan.stateRoot, 'openclaw.json')
    && process.env.OPENCLAW_OAUTH_DIR === path.join(plan.stateRoot, 'oauth'));
  check('private_work_scope', within(plan.workRoot, plan.stateRoot) && within(plan.workRoot, plan.pluginEntry)
    && within(plan.workRoot, plan.selectionOutput) && within(plan.workRoot, plan.custodyOutput));
  const cfg = JSON.parse(privateRead(path.join(plan.stateRoot, 'openclaw.json')));
  const agentDir = path.join(plan.stateRoot, 'agents/main/agent');
  const target = new URL(plan.pluginConfig.address);
  check('loopback_https_only', target.protocol === 'https:' && target.hostname === '127.0.0.1' && !!target.port);
  check('private_plugin_mode', plan.pluginConfig.leader === false && plan.pluginConfig.publishNew === false
    && plan.pluginConfig.schedulerMode === 'shadow' && plan.pluginConfig.manageOrder === true);
  for (const [file, expected] of Object.entries(plan.sourcePins)) check('source.' + path.basename(file), hash(fs.readFileSync(file)) === expected);
  const originalHttpsRequest = https.request;
  for (const method of ['log', 'warn', 'error', 'info', 'debug']) console[method] = () => {};
  globalThis.fetch = deny;
  http.request = deny; http.get = deny;
  for (const method of ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork']) childProcess[method] = deny;
  baoAgent = new https.Agent({ keepAlive: false, maxCachedSessions: 0 });
  https.request = (options, callback) => {
    need(options && typeof options === 'object' && !(options instanceof URL), 'https_shape');
    need((options.hostname || options.host) === target.hostname && String(options.port || 443) === target.port
      && options.rejectUnauthorized === true, 'https_endpoint_or_trust');
    const route = options.path;
    const allowed = options.method === 'POST' && route === '/v1/auth/approle/login'
      || options.method === 'GET' && route.startsWith('/v1/openclaw-auth/data/')
      || options.method === 'POST' && route.startsWith('/v1/openclaw-auth/data/inbox/' + plan.pluginConfig.hostId + '/');
    need(allowed, 'https_operation_scope');
    const item = { method: options.method, path: route };
    report.wire.push(item);
    return originalHttpsRequest({ ...options, agent: baoAgent }, response => {
      item.status = response.statusCode;
      item.tlsVerified = response.socket.authorized === true;
      const certificate = response.socket.getPeerCertificate?.();
      item.peerSha256 = certificate?.raw ? hash(certificate.raw) : null;
      need(item.tlsVerified && item.peerSha256 === plan.serverCertificateSha256, 'https_peer_pin');
      if (route === '/v1/auth/approle/login') {
        let size = 0; const chunks = [];
        response.on('data', part => { size += part.length; if (size <= 1024 * 1024) chunks.push(part); });
        response.on('end', () => {
          if (size > 1024 * 1024) return;
          try {
            const value = JSON.parse(Buffer.concat(chunks));
            if (response.statusCode === 200 && typeof value.auth?.client_token === 'string') {
              tokens.push(value.auth.client_token); sensitive.push(value.auth.client_token);
            }
          } catch {}
        });
      }
      callback(response);
    });
  };
  syncBuiltinESMExports();
  const sdk = await import(pathToFileURL(path.join(plan.sdkRoot, 'dist/plugin-sdk/agent-runtime.js')));
  const storeApi = await import(pathToFileURL(path.join(plan.sdkRoot, 'dist/store-DH33UrUj.js')));
  const profileAuth = await import(pathToFileURL(path.join(plan.sdkRoot, 'dist/oauth-B4aOCsid.js')));
  const orderApi = await import(pathToFileURL(path.join(plan.sdkRoot, 'dist/order-CeBlX0NH.js')));
  check('sdk_default_scope', path.resolve(sdk.resolveDefaultAgentDir({})) === agentDir);
  check('sdk_database_scope', path.resolve(sdk.resolveAuthStorePathForDisplay(agentDir)) === path.join(agentDir, 'openclaw-agent.sqlite'));
  const current = sdk.loadAuthProfileStoreWithoutExternalProfiles(agentDir, { allowKeychainPrompt: false });
  for (const [id, cred] of Object.entries(current.profiles)) { sensitive.push(id); sensitive.push(...secrets(cred)); }
  if (plan.mode === 'rollback') {
    const before = JSON.parse(privateRead(plan.baselineOutput));
    const candidate = JSON.parse(privateRead(plan.selectionOutput));
    check('rollback_expected_candidate', digest(current) === candidate.storeSha256);
    let applied = false;
    const result = await storeApi.m({ agentDir, updater: store => {
      if (digest(store) !== candidate.storeSha256) return false;
      for (const key of Object.keys(store)) delete store[key];
      Object.assign(store, structuredClone(before)); applied = true; return true;
    } });
    check('installed_sdk_atomic_rollback', result !== null && applied);
    sdk.clearRuntimeAuthProfileStoreSnapshots();
    check('rollback_logical_store_exact', digest(sdk.loadAuthProfileStoreWithoutExternalProfiles(agentDir, { allowKeychainPrompt: false })) === digest(before));
    report.rollbackScope = 'Isolated logical auth store restored with the installed SDK; original live stores untouched.';
    check('rollback_original_order_preserved', digest(current.order ?? null) === digest(before.order ?? null));
    report.originalOrderPreserved = true;
  } else {
    const before = current;
    check('original_selected_identity_present', Object.hasOwn(before.profiles, plan.expectedProfileId));
    check('source_account_identity_matches', before.profiles[plan.expectedProfileId].accountId === plan.expectedAccountId);
    if (plan.mode === 'initial') save(plan.baselineOutput, before);
    check('original_config_order_and_exclusions_preserved', digest(cfg.auth ?? {}) === plan.sourceAuthConfigSha256
      && digest(cfg.models ?? {}) === plan.sourceModelsConfigSha256
      && digest(cfg.agents.defaults.model) === plan.sourceDefaultModelSha256
      && digest(plan.pluginConfig.orderExcludeAgentIds ?? []) === plan.sourceOrderExclusionsSha256);
    const effectiveOrderBefore = orderApi.i({ cfg, store: structuredClone(before), provider: before.profiles[plan.expectedProfileId].provider });
    let removed = false;
    const missing = await storeApi.m({ agentDir, saveOptions: { preserveStateProfileIds: [plan.expectedProfileId] }, updater: store => {
      if (digest(store) !== digest(before) || !Object.hasOwn(store.profiles, plan.expectedProfileId)) return false;
      delete store.profiles[plan.expectedProfileId]; removed = true; return true;
    } });
    check('isolated_sdk_cas_removes_only_selected_profile', missing !== null && removed);
    sdk.clearRuntimeAuthProfileStoreSnapshots();
    const recoveryStart = sdk.loadAuthProfileStoreWithoutExternalProfiles(agentDir, { allowKeychainPrompt: false });
    check('selected_profile_absent_before_actual_plugin', !Object.hasOwn(recoveryStart.profiles, plan.expectedProfileId)
      && digest(recoveryStart.order ?? null) === digest(before.order ?? null)
      && digest(recoveryStart.usageStats ?? null) === digest(before.usageStats ?? null));

    const plugin = (await import(pathToFileURL(plan.pluginEntry))).default;
    check('installed_plugin_export', plugin?.id === 'openclaw-authbus' && typeof plugin.register === 'function');
    let subscriptions = 0;
    plugin.register({ registrationMode: 'full', pluginConfig: plan.pluginConfig,
      agent: { events: { registerAgentEventSubscription() { subscriptions++; } } },
      registerService(value) { need(!service, 'single_plugin_service'); service = value; } });
    check('installed_service_registration', subscriptions === 1 && service?.id === 'openclaw-authbus');
    const logs = { info: 0, warn: 0, error: 0, debug: 0 };
    const logger = Object.fromEntries(Object.keys(logs).map(key => [key, () => { logs[key]++; }]));
    await service.start({ stateDir: plan.stateRoot, logger, config: cfg });
    await service.stop(); service = null;
    const status = JSON.parse(privateRead(path.join(plan.stateRoot, 'authbus/status.json')));
    report.plugin = Object.fromEntries(['ok', 'manifestProfiles', 'importedProfiles', 'agentStores', 'verifiedStores',
      'effectiveMissing', 'effectiveMismatched', 'changedOrders', 'verifiedOrderBindings', 'schedulerReports', 'pendingRuntimeRefreshes'].map(k => [k, status[k] ?? null]));
    report.plugin.logCounts = logs;
    if (status.error) report.plugin.errorSha256 = hash(String(status.error));
    check('actual_plugin_cycle', status.ok === true);
    sdk.clearRuntimeAuthProfileStoreSnapshots();
    const after = sdk.loadAuthProfileStoreWithoutExternalProfiles(agentDir, { allowKeychainPrompt: false });
    const cred = after.profiles[plan.expectedProfileId];
    sensitive.push(...secrets(cred));
    check('real_profile_exact', digest(cred) === plan.expectedCredentialSha256);
    check('account_identity_preserved', cred.accountId === plan.expectedAccountId);
    check('other_profiles_unchanged', Object.entries(before.profiles).filter(([id]) => id !== plan.expectedProfileId)
      .every(([id, v]) => digest(v) === digest(after.profiles[id])) && Object.keys(after.profiles).length === Object.keys(before.profiles).length);
    check('actual_plugin_restores_missing_profile', status.importedProfiles === 1);
    const order = orderApi.i({ cfg, store: structuredClone(after), provider: cred.provider });
    check('original_effective_order_preserved', digest(order) === digest(effectiveOrderBefore));
    check('original_stored_order_and_usage_preserved', digest(after.order ?? null) === digest(before.order ?? null)
      && digest(after.usageStats ?? null) === digest(before.usageStats ?? null));
    // Explicit-profile resolution proves this recovered credential without
    // overriding the host's independent default profile or exclusion policy.
    const resolved = await profileAuth.n({ cfg, store: after, profileId: plan.expectedProfileId, agentDir, forceRefresh: false });
    check('original_sdk_explicit_profile_selected', resolved?.profileId === plan.expectedProfileId);
    check('original_sdk_explicit_profile_exact_access', resolved.apiKey === cred.access);
    report.sourceOrderSha256 = digest(before.order ?? null);
    report.effectiveOrderSha256 = digest(order);
    report.sourceUsageSha256 = digest(before.usageStats ?? null);
    // Resolution may annotate its in-memory store. Bind rollback to a fresh
    // installed-SDK read of the committed store, not those runtime annotations.
    sdk.clearRuntimeAuthProfileStoreSnapshots();
    const committed = sdk.loadAuthProfileStoreWithoutExternalProfiles(agentDir, { allowKeychainPrompt: false });
    check('committed_selected_profile_exact', digest(committed.profiles[plan.expectedProfileId]) === plan.expectedCredentialSha256);
    check('committed_original_order_exact', digest(committed.order ?? null) === digest(before.order ?? null));
    check('committed_original_usage_exact', digest(committed.usageStats ?? null) === digest(before.usageStats ?? null));
    check('actual_login_and_tls_reads', tokens.length === 1 && report.wire.some(x => x.method === 'GET'
      && x.path === '/v1/openclaw-auth/data/profiles/' + plan.expectedProfileKey && x.status === 200));
    save(plan.selectionOutput, { schema: 'heptabao.private-default-model-selection.v1',
      profileId: plan.expectedProfileId, credential: cred, resolvedApiKey: resolved.apiKey,
      storeSha256: digest(committed), credentialSha256: digest(cred), model: plan.model,
      source: 'actual_installed_sdk_explicit_profile_resolver_after_actual_authbus_recovery' });
    report.actualExplicitProfileSelectionQualified = true;
    report.defaultGatewaySelectionQualified = false;
    report.productionOrderOverrideQualified = false;
    report.profileCount = Object.keys(after.profiles).length;
    report.selectedProfileCount = 1;
    report.sdkVersion = JSON.parse(fs.readFileSync(path.join(plan.sdkRoot, 'package.json'))).version;
  }
  check('no_unexpected_network_or_process_operations', blockedOperations === 0);
  check('all_source_pins_unchanged', Object.entries(plan.sourcePins).every(([file, expected]) => hash(fs.readFileSync(file)) === expected));
  check('report_contains_no_credential_values', sensitive.every(v => !JSON.stringify(report).includes(v)));
  report.ok = true;
} catch (error) {
  report.error = error?.safeCode ?? 'actual_plugin_consumer_failed';
  report.errorClass = error?.constructor?.name ?? 'unknown';
  report.errorCodeSha256 = hash(String(error?.message ?? error));
  report.sourceFrame = String(error?.stack ?? '').split('\n').slice(1, 5).map(line => line.match(/([A-Za-z0-9_.-]+\.(?:js|mjs)):(\d+):(\d+)/)?.slice(1) ?? ['native']);
} finally {
  if (service) { try { await service.stop(); } catch {} }
  baoAgent?.destroy();
  if (plan) {
    try { save(plan.custodyOutput, { tokens }); } catch {}
  }
}
process.stdout.write(JSON.stringify(report) + '\n');
process.exitCode = report.ok ? 0 : 1;
