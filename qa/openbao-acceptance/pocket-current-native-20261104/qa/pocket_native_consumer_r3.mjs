#!/usr/bin/env node
/** Separate Pocket current-native contract. Original generic consumer stays frozen.
 * Two exact current agent sources, real AuthBus TLS/AppRole import, actual installed
 * registry/default native factory, and SDK plus full auth-row CAS rollback.
 * No provider egress or production write is permitted.
 */
import fs from 'node:fs';
import { createPocketNativeObserver } from './pocket_native_observer_r3.mjs';
import { captureAuthRows, restoreAuthRowsWithCas, authRowsDigest } from './pocket_native_auth_rows_cas_r1.mjs';
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
const report = { schema: 'heptabao.pocket-current-native-consumer.v1', ok: false,
  productionChanged: false, productionTrafficCutover: false, providerNetworkEgress: false,
  refreshNetworkEgress: false, modelCalled: false, j3160Contacted: false,
  nativeBackendAttemptsNotCounted: true, providerAvailabilityQualified: false,
  credentialValuesPublished: false, accountIdentitiesPublished: false,
  allAccountsQualified: false, checks: [], wire: [] };
let service, baoAgent, plan, nativeObserver, sdkRuntime, storeRuntime, baselineDoc;
const agentIds = ['main','tg8687951891'];
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
  const originalExecFileSync = childProcess.execFileSync;
  const originalSpawn = childProcess.spawn;
  nativeObserver = createPocketNativeObserver(plan, originalSpawn, check);
  for (const method of ['log', 'warn', 'error', 'info', 'debug']) console[method] = () => {};
  globalThis.fetch = deny;
  http.request = deny; http.get = deny;
  for (const method of ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork']) childProcess[method] = deny;
  childProcess.spawn = (...args) => nativeObserver.spawn(...args);
  childProcess.execFileSync = (file, args, options) => {
    if (file !== 'mount' || !Array.isArray(args) || args.length || options !== undefined) return deny();
    const s = fs.lstatSync('/sbin/mount');
    need(process.platform === 'darwin' && s.isFile() && s.uid === 0 && (s.mode & 0o022) === 0, 'trusted_mount_tool');
    return originalExecFileSync('/sbin/mount', [], { timeout: 3000, maxBuffer: 262144,
      stdio: ['ignore', 'pipe', 'pipe'], env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin' } });
  };
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
  const rawBefore = Object.fromEntries(agentIds.map(id => [id, captureAuthRows(plan.stateRoot,id)]));
  const sdk = await import(pathToFileURL(path.join(plan.sdkRoot, 'dist/plugin-sdk/agent-runtime.js')));
  const storeApi = await import(pathToFileURL(path.join(plan.sdkRoot, 'dist/store-DH33UrUj.js')));
  storeRuntime=storeApi;
  sdkRuntime = sdk;
  const orderApi = await import(pathToFileURL(path.join(plan.sdkRoot, 'dist/order-CeBlX0NH.js')));
  check('sdk_default_scope', path.resolve(sdk.resolveDefaultAgentDir({})) === agentDir);
  check('sdk_database_scope', path.resolve(sdk.resolveAuthStorePathForDisplay(agentDir)) === path.join(agentDir, 'openclaw-agent.sqlite'));
  const current = sdk.loadAuthProfileStoreWithoutExternalProfiles(agentDir, { allowKeychainPrompt: false });
  for (const [id, cred] of Object.entries(current.profiles)) { sensitive.push(id); sensitive.push(...secrets(cred)); }
  const currentStores = () => {
    sdk.clearRuntimeAuthProfileStoreSnapshots();
    return Object.fromEntries(agentIds.map(id => [id, sdk.loadAuthProfileStoreWithoutExternalProfiles(
      path.join(plan.stateRoot,'agents',id,'agent'), { allowKeychainPrompt: false })]));
  };
  const localStores = async () => {
    const result = {};
    for (const id of agentIds) {
      let observed;
      const value = await storeApi.m({agentDir:path.join(plan.stateRoot,'agents',id,'agent'),updater:store=>{
        observed=structuredClone(store); return false;
      }});
      check('actual_sdk_local_store_capture.'+id, value!==null && observed!==undefined && digest(value)===digest(observed));
      result[id]=observed;
    }
    return result;
  };
  const allCurrent = currentStores();
  const allLocal = await localStores();
  for (const store of Object.values(allCurrent)) for (const [id,cred] of Object.entries(store.profiles)) {
    sensitive.push(id); sensitive.push(...secrets(cred));
  }
  if (plan.mode === 'rollback') {
    baselineDoc = JSON.parse(privateRead(plan.baselineOutput));
    const candidate = JSON.parse(privateRead(plan.candidateOutput));
    check('rollback_two_agent_scope', digest(Object.keys(candidate.stores).sort()) === digest(agentIds.toSorted())
      && digest(Object.keys(baselineDoc.stores).sort()) === digest(agentIds.toSorted()));
    for (const id of agentIds) {
      check('rollback_expected_effective_candidate.'+id, digest(allCurrent[id]) === digest(candidate.stores[id]));
      check('rollback_expected_local_candidate.'+id, digest(allLocal[id]) === digest(candidate.localStores[id]));
      check('rollback_expected_raw_candidate.'+id, authRowsDigest(rawBefore[id]) === authRowsDigest(candidate.authRows[id]));
    }
    for (const id of agentIds) {
      const directory = path.join(plan.stateRoot,'agents',id,'agent');
      let applied = false;
      const result = await storeApi.m({ agentDir: directory, updater: store => {
        if (digest(store) !== digest(candidate.localStores[id])) return false;
        for (const key of Object.keys(store)) delete store[key];
        Object.assign(store, structuredClone(baselineDoc.localStores[id])); applied = true; return true;
      } });
      check('installed_sdk_atomic_rollback.'+id, result !== null && applied);
    }
    // Restore the exact pre-SDK local representation, including tg's profile-free primary row and absent state row.
    // No expected value is weakened on a conflict, and this process never retries.
    const postSdkRows = Object.fromEntries(agentIds.map(id => [id, captureAuthRows(plan.stateRoot,id)]));
    for (const id of agentIds)
      check('original_auth_rows_cas_restore.'+id,
        restoreAuthRowsWithCas(plan.stateRoot,id,postSdkRows[id],baselineDoc.authRows[id]));
    const restored = currentStores();
    const restoredLocal = await localStores();
    for (const id of agentIds) {
      check('rollback_full_local_sdk_store_exact.'+id,digest(restoredLocal[id])===digest(baselineDoc.localStores[id]));
      check('rollback_full_effective_sdk_store_exact.'+id,
        digest(restored[id]) === digest(baselineDoc.stores[id]));
      check('rollback_full_raw_auth_tables_exact.'+id,
        authRowsDigest(captureAuthRows(plan.stateRoot,id)) === authRowsDigest(baselineDoc.authRows[id]));
    }
    report.rollbackScope = 'Both owned agent effective SDK stores and complete original auth-table rows, preserving the profile-free tg primary row and inherited effective profiles.';
    report.rollbackAttemptedOnce = true;
    report.rollbackRetried = false;
    report.fixtureScenario = plan.fixtureScenario;
    report.actualNativeFactoryQualified = false;
  } else {
    const before = current;
    baselineDoc = { schema:'heptabao.pocket-native-two-agent-baseline.private.v1',
      stores:allCurrent, localStores:allLocal, authRows:rawBefore, fixtureScenario:plan.fixtureScenario };
    save(plan.baselineOutput, baselineDoc);
    const recovering = plan.fixtureScenario === 'missing-current-ordinal5-recovery';
    check('explicit_fixture_scenario', recovering || plan.fixtureScenario === 'full-current-baseline');
    check('current_selected_presence_matches_scenario',
      Object.hasOwn(before.profiles,plan.expectedProfileId) === !recovering);
    if (!recovering) check('source_account_identity_matches',
      before.profiles[plan.expectedProfileId].accountId === plan.expectedAccountId
      && digest(before.profiles[plan.expectedProfileId]) === plan.expectedCredentialSha256);
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
      .every(([id,v]) => digest(v) === digest(after.profiles[id]))
      && Object.keys(after.profiles).length === Object.keys(before.profiles).length + (recovering ? 1 : 0));
    check('current_full_source_profiles_restored', digest(after.profiles) === plan.expectedFullProfilesSha256);
    const allAfter = currentStores();
    report.agentStoreEffects = [];
    for (const id of agentIds) {
      check('all_current_identities_preserved.'+id, digest(allAfter[id].profiles) === plan.expectedFullProfilesSha256);
      check('current_order_unchanged.'+id, digest(allAfter[id].order??{}) === digest(baselineDoc.stores[id].order??{}));
      check('current_usage_unchanged.'+id, digest(allAfter[id].usageStats??{}) === digest(baselineDoc.stores[id].usageStats??{}));
      const order = orderApi.i({cfg,store:structuredClone(allAfter[id]),provider:'openai'});
      check('current_single_default_candidate.'+id, order.length === 1 && order[0] === plan.expectedProfileId);
      report.agentStoreEffects.push({agentId:id,
        logicalProfilesChanged:digest(allAfter[id].profiles)!==digest(baselineDoc.stores[id].profiles),
        rawAuthRowsChanged:authRowsDigest(captureAuthRows(plan.stateRoot,id))!==authRowsDigest(rawBefore[id]),
        orderPreserved:true,usagePreserved:true,profileCount:Object.keys(allAfter[id].profiles).length});
    }
    check('real_profile_insertion_when_recovering', !recovering || report.agentStoreEffects[0].logicalProfilesChanged);
    const loader = await import(pathToFileURL(path.join(plan.sdkRoot,'dist/runtime-registry-loader-Duw3fvRO.js')));
    await loader.t({scope:'all',config:cfg,activationSourceConfig:cfg,workspaceDir:plan.nativeWorkspace,
      onlyPluginIds:plan.enabledHarnessOwnersPlusOpenai});
    for (const id of agentIds) await nativeObserver.factory(id,cfg,sdk);
    sdk.clearRuntimeAuthProfileStoreSnapshots();
    const committed = currentStores();
    for (const id of agentIds) {
      check('committed_selected_profile_exact.'+id, digest(committed[id].profiles[plan.expectedProfileId])===plan.expectedCredentialSha256);
      check('committed_current_order_and_usage.'+id,
        digest(committed[id].order??{})===digest(baselineDoc.stores[id].order??{})
        && digest(committed[id].usageStats??{})===digest(baselineDoc.stores[id].usageStats??{}));
    }
    check('actual_login_and_tls_reads', tokens.length===1 && report.wire.some(x=>x.method==='GET'
      && x.path==='/v1/openclaw-auth/data/profiles/'+plan.expectedProfileKey && x.status===200));
    save(plan.selectionOutput,{schema:'heptabao.private-current-native-selection.v1',
      profileId:plan.expectedProfileId,credential:cred,credentialSha256:digest(cred),
      model:plan.model,agentIds,source:'actual_installed_authbus_then_actual_default_native_agent_factories'});
    report.actualNativeFactoryQualified = true;
    report.actualDefaultSelectionQualified = true;
    report.currentSelectedOrdinal = 5;
    report.profileCount = Object.keys(after.profiles).length;
    report.fixtureScenario = plan.fixtureScenario;
    report.logicalProfileInsertionObserved = report.agentStoreEffects.some(x=>x.logicalProfilesChanged);
    report.sdkVersion = JSON.parse(fs.readFileSync(path.join(plan.sdkRoot, 'package.json'))).version;
  }
  check('all_owned_native_processes_stopped', await nativeObserver.closeAll());
  report.native = nativeObserver.state;
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
  if (nativeObserver) {
    try { report.ownedNativeProcessesStopped = await nativeObserver.closeAll(); }
    catch { report.ownedNativeProcessesStopped = false; }
    report.native = nativeObserver.state;
  }
  baoAgent?.destroy();
  if (plan && plan.mode !== 'rollback' && baselineDoc && sdkRuntime) {
    try {
      sdkRuntime.clearRuntimeAuthProfileStoreSnapshots();
      const stores=Object.fromEntries(agentIds.map(id=>[id,sdkRuntime.loadAuthProfileStoreWithoutExternalProfiles(path.join(plan.stateRoot,'agents',id,'agent'),{allowKeychainPrompt:false})]));
      const localStores={};
      for(const id of agentIds){let observed;const value=await storeRuntime.m({agentDir:path.join(plan.stateRoot,'agents',id,'agent'),updater:store=>{observed=structuredClone(store);return false;}});
        need(value!==null&&observed!==undefined&&digest(value)===digest(observed),'rollback_checkpoint_local_store_capture');localStores[id]=observed;}
      const authRows=Object.fromEntries(agentIds.map(id=>[id,captureAuthRows(plan.stateRoot,id)]));
      save(plan.candidateOutput,{schema:'heptabao.pocket-native-rollback-candidate.private.v1',stores,localStores,authRows});
      report.candidateRecordedForRollback=true;
    } catch(error) { report.candidateRecordedForRollback=false; report.candidateCheckpointErrorSha256=hash(String(error?.message??error)); report.ok=false; }
  }
  if (plan) {
    try { save(plan.custodyOutput, { tokens }); } catch {}
  }
}
if(sensitive.some(value=>JSON.stringify(report).includes(value))){
  for(const key of Object.keys(report))delete report[key];
  Object.assign(report,{schema:'heptabao.pocket-current-native-consumer.v1',ok:false,error:'public_projection_contains_sensitive_value'});
}
process.stdout.write(JSON.stringify(report) + '\n');
process.exitCode = report.ok ? 0 : 1;
