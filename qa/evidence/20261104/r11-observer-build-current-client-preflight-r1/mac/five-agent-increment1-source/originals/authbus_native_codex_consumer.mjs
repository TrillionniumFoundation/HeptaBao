#!/usr/bin/env node
/** Exercise installed AuthBus plus the actual installed Codex registry and local native auth bridge.
 * The new private state is populated from the real HeptaBao TLS/AppRole API.
 * Kernel containment blocks external egress. Native background attempts are not claimed to be zero.
 */
import fs from 'node:fs';
import path from 'node:path';
import https from 'node:https';
import http from 'node:http';
import childProcess from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { syncBuiltinESMExports } from 'node:module';

process.umask(0o077);
const hash = value => createHash('sha256').update(value).digest('hex');
const stable = value => Array.isArray(value) ? value.map(stable) : value && typeof value === 'object'
  ? Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])])) : value;
const digest = value => hash(JSON.stringify(stable(value)));
const report = { schema: 'heptabao.actual-plugin-two-source-native-codex-consumer.v1', ok: false,
  productionChanged: false, productionTrafficCutover: false, providerResponseObtained: false, externalNetworkEgressAllowed: false,
  explicitModelRpcDispatched: false, nativeBackgroundNetworkAttemptCount: null,
  nativeBackgroundNetworkAttemptsNotMeasured: true, j3160Contacted: false,
  credentialValuesPublished: false, accountIdentitiesPublished: false,
  allAccountsQualified: false, checks: [], wire: [] };
let service, baoAgent, plan, nativeClient;
let nativeStarted = 0, nativeSpawned = 0;
let nativeControlBaseline;
const nativeStderr = [];
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

function observeOwnedNative(child) {
  const requestText = process.env.HEPTABAO_NATIVE_OBSERVER_REQUEST_FD;
  const responseText = process.env.HEPTABAO_NATIVE_OBSERVER_RESPONSE_FD;
  need(/^\d+$/.test(requestText ?? '') && /^\d+$/.test(responseText ?? ''), 'outer_observer_pipe_fds');
  const requestFd = Number(requestText), responseFd = Number(responseText);
  need(Number.isInteger(requestFd) && requestFd > 2 && Number.isInteger(responseFd) && responseFd > 2
    && requestFd !== responseFd && fs.fstatSync(requestFd).isFIFO() && fs.fstatSync(responseFd).isFIFO(),
    'outer_observer_anonymous_pipes');
  const nonce = randomBytes(32).toString('hex');
  try {
    const request = Buffer.from(JSON.stringify({ schema: 'heptabao.owned-native-request.v1',
      nonce, nodePid: process.pid, launcherPid: child.pid }) + '\n');
    need(fs.writeSync(requestFd, request) === request.length, 'outer_observer_request_complete');
    const chunks = []; let size = 0;
    while (true) {
      const chunk = Buffer.alloc(4096);
      const count = fs.readSync(responseFd, chunk, 0, chunk.length, null);
      need(count > 0, 'outer_observer_closed_without_ack');
      chunks.push(chunk.subarray(0, count)); size += count;
      need(size <= 8192, 'bounded_outer_observer_ack');
      if (chunk.subarray(0, count).includes(10)) break;
    }
    const bytes = Buffer.concat(chunks);
    need(bytes[bytes.length - 1] === 10 && bytes.indexOf(10) === bytes.length - 1, 'single_outer_observer_ack');
    const ack = JSON.parse(bytes.toString('utf8'));
    need(ack.schema === 'heptabao.owned-native-ack.v1' && ack.nonce === nonce && ack.verified === true,
      'outer_observer_verified_matching_attempt');
    const ids = ack.identities;
    check('outer_owned_lineage_before_first_native_rpc', ids?.node?.pid === process.pid
      && ids.node.ppid === process.ppid && ids.node.pgid === process.pid
      && ids.node.executable === fs.realpathSync(process.execPath)
      && ids.launcher?.pid === child.pid && ids.launcher.ppid === process.pid
      && ids.launcher.pgid === process.pid && ids.launcher.executable === ids.node.executable
      && Number.isInteger(ids.native?.pid) && ids.native.ppid === child.pid
      && ids.native.pgid === process.pid && ids.native.executable === fs.realpathSync(plan.nativeBinary)
      && Object.values(ids).every(v => v.uid === process.getuid() && Number.isInteger(v.birthSec)
        && v.birthSec > 0 && Number.isInteger(v.birthUsec) && v.birthUsec >= 0 && v.birthUsec < 1000000));
    report.outerProcessObserver = { verified: true, identities: ids, birthMicrosecondsBound: true,
      ackAuthority: 'outer_parent_only_anonymous_pipe_write_end', firstRpcStillUnsent: true };
    report.nativeSpawn.processGroup = ids.native.pgid;
  } finally {
    fs.closeSync(requestFd); fs.closeSync(responseFd);
    delete process.env.HEPTABAO_NATIVE_OBSERVER_REQUEST_FD;
    delete process.env.HEPTABAO_NATIVE_OBSERVER_RESPONSE_FD;
  }
}


async function exerciseNative({ cfg, agentDir, committed, credential, nativeApi, startOptions }) {
  check('new_native_auth_file_absent_before', !fs.existsSync(path.join(plan.nativeHome, 'auth.json')));
  const controlFiles = [process.argv[2], plan.baselineOutput, plan.rollbackCheckpointOutput,
    path.join(plan.stateRoot, 'openclaw.json')];
  check('native_control_files_scoped_to_fresh_run', controlFiles.every(file => within(plan.workRoot, file)));
  nativeControlBaseline = Object.fromEntries(controlFiles.map(file => [file, hash(privateRead(file))]));
  report.nativeControlBeforeSha256 = nativeControlBaseline;
  report.nativeRpc = { sent: [], serverRequestsRefused: [], notifications: [],
    callbackSubstitutesParameters: false, callbackSubstitutesResponses: false,
    backgroundNetworkAttemptCount: null, backgroundNetworkAttemptsNotMeasured: true,
    externalNetworkKernelDenied: true, explicitRefreshRpcSent: false, explicitModelTurnSent: false };
  let loginSeen = 0, loginSucceeded = 0, accountReadSeen = 0, initializeSeen = 0;
  const observeStarted = client => {
    need(++nativeStarted === 1, 'single_actual_native_client'); nativeClient = client;
    need(client.child && Number.isInteger(client.child.pid), 'actual_native_child_required');
    // Added before the installed runtime refresh handler. Throwing rejects the
    // local request; the original client's normal error response is retained.
    client.addRequestHandler(async request => {
      const known = ['account/chatgptAuthTokens/refresh', 'item/tool/call',
        'item/commandExecution/requestApproval', 'item/fileChange/requestApproval'];
      report.nativeRpc.serverRequestsRefused.push(known.includes(request.method) ? request.method : 'other');
      throw Object.assign(new Error('isolated_native_server_request_refused'), { safeCode: 'isolated_native_server_request_refused' });
    });
    client.addNotificationHandler(notification => {
      const allowed = ['account/updated', 'account/login/completed', 'account/rateLimits/updated'];
      report.nativeRpc.notifications.push(allowed.includes(notification.method) ? notification.method : 'other');
    });
    const originalRequest = client.request.bind(client);
    client.request = (method, params, options) => {
      if (method === 'initialize') {
        need(++initializeSeen === 1 && params?.clientInfo?.name === 'openclaw', 'single_original_native_initialize');
      } else if (method === 'account/login/start') {
        need(initializeSeen === 1 && ++loginSeen === 1 && params?.type === 'chatgptAuthTokens', 'single_actual_external_token_login');
        need(params.accessToken === credential.access && params.chatgptAccountId === credential.accountId,
          'actual_native_login_exact_selected_access_and_identity');
        report.nativeRpc.loginCredentialExact = true;
        report.nativeRpc.loginAccountSha256 = hash(params.chatgptAccountId);
        report.nativeRpc.loginAccessSha256 = hash(params.accessToken);
      } else if (method === 'account/read') {
        need(loginSucceeded === 1 && ++accountReadSeen === 1 && digest(params) === digest({ refreshToken: false }),
          'single_non_refresh_local_account_read_after_login');
      } else return deny();
      const item = { method, completed: false }; report.nativeRpc.sent.push(item);
      // Pass the original method, object identities and options to the actual
      // transport and return the same actual response, without normalization.
      return originalRequest(method, params, options).then(response => {
        item.completed = true;
        if (method === 'account/login/start') {
          need(response?.type === 'chatgptAuthTokens', 'actual_native_external_login_response'); loginSucceeded++;
        }
        return response;
      });
    };
    const originalNotify = client.notify.bind(client);
    client.notify = (method, params) => {
      need(method === 'initialized' && initializeSeen === 1, 'only_original_initialized_notification');
      return originalNotify(method, params);
    };
  };
  // Production leased/shared and isolated factories use the same pinned start
  // context + initializer + auth application. Only cache/lease lifetime differs.
  const client = await nativeApi.i({ agentDir, config: cfg,
    startOptions, timeoutMs: 15000, onStartedClient: observeStarted });
  check('actual_native_factory_initialized_and_logged_in', client === nativeClient && client.initialized === true
    && initializeSeen === 1 && loginSucceeded === 1 && nativeSpawned === 1);
  const identity = client.getRuntimeIdentity();
  report.nativeVersion = client.getServerVersion();
  report.nativeRuntimeIdentityKeys = Object.keys(identity ?? {});
  need(String(client.getServerVersion()) === '0.144.3', 'exact_managed_native_version');
  check('native_runtime_reports_exact_isolated_home', identity?.codexHome === plan.nativeHome);
  save(plan.nativeIdentityOutput, { runtimeIdentity: identity, version: client.getServerVersion() });
  const account = await client.request('account/read', { refreshToken: false }, { timeoutMs: 8000 });
  save(plan.nativeAccountOutput, account);
  check('actual_local_account_is_chatgpt', account?.account?.type === 'chatgpt' && account.requiresOpenaiAuth === true);
  // Exact 0.144.3 token_data.rs takes top-level email, then profile.email;
  // the native protocol permits a missing email. Account/token identity remains
  // mandatory and exact in the actual login RPC above.
  const accessClaims = JSON.parse(Buffer.from(credential.access.split('.')[1], 'base64url'));
  const expectedEmail = accessClaims.email ?? accessClaims['https://api.openai.com/profile']?.email ?? null;
  check('jwt_email_consistent_with_source_when_present', expectedEmail === null || expectedEmail === credential.email);
  check('actual_local_account_email_matches_native_jwt_contract', account.account.email === expectedEmail);
  report.nativeAccountEmailPresent = expectedEmail !== null;
  report.nativeAccountEmailSha256 = expectedEmail === null ? null : hash(expectedEmail);
  check('native_external_tokens_not_persisted_as_auth_json', !fs.existsSync(path.join(plan.nativeHome, 'auth.json')));
  const closed = await client.closeAndWait({ exitTimeoutMs: 3000 });
  check('actual_native_close_and_wait', closed === true); nativeClient = undefined;
  check('native_local_rpc_only', report.nativeRpc.sent.map(x => x.method).join('|') === 'initialize|account/login/start|account/read'
    && report.nativeRpc.sent.every(x => x.completed));
  report.nativeExternalRefreshRequestsRefused = report.nativeRpc.serverRequestsRefused.filter(x => x === 'account/chatgptAuthTokens/refresh').length;
  report.scope = 'Local real native credential consumption under external-network denial; native startup background attempts are not counted; no model/business availability or production gateway cutover qualification.';
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
  for (const method of ['log', 'warn', 'error', 'info', 'debug']) console[method] = () => {};
  globalThis.fetch = deny;
  http.request = deny; http.get = deny;
  for (const method of ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork']) childProcess[method] = deny;
  childProcess.execFileSync = (file, args, options) => {
    if (file !== 'mount' || !Array.isArray(args) || args.length || options !== undefined) return deny();
    const s = fs.lstatSync('/sbin/mount');
    need(process.platform === 'darwin' && s.isFile() && s.uid === 0 && (s.mode & 0o022) === 0, 'trusted_mount_tool');
    return originalExecFileSync('/sbin/mount', [], { timeout: 3000, maxBuffer: 262144,
      stdio: ['ignore', 'pipe', 'pipe'], env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin' } });
  };
  // Directly preserve the installed managed command/argv and process options.
  // Node and native inherit the same outer kernel sandbox; no nested policy,
  // transport substitution or native-specific file isolation is claimed.
  childProcess.spawn = (file, args, options) => {
    need(plan.mode !== 'rollback' && nativeSpawned === 0, 'single_owned_native_spawn');
    need(file === plan.nativeCommand && fs.realpathSync(file) === plan.nativeLauncher,
      'exact_installed_managed_launcher');
    need(Array.isArray(args) && digest(args) === digest(['app-server', '--listen', 'stdio://']),
      'exact_native_app_server_arguments');
    report.nativeSpawnEnvelope = { detached: options?.detached ?? null,
      shellMode: options?.shell === undefined ? 'undefined-no-shell' : options.shell === false ? 'false-no-shell' : 'refused',
      stdioExactPipes: digest(options?.stdio) === digest(['pipe', 'pipe', 'pipe']) };
    need(options?.detached === false && (options.shell === undefined || options.shell === false)
      && digest(options.stdio) === digest(['pipe', 'pipe', 'pipe']), 'owned_native_stdio_process_group');
    need(options.env?.CODEX_HOME === plan.nativeHome
      && options.env?.OPENCLAW_QA_PARENT_PID === String(process.pid), 'native_home_and_owned_parent');
    need(['CODEX_API_KEY', 'OPENAI_API_KEY', 'CODEX_ACCESS_TOKEN'].every(k => !options.env?.[k]),
      'no_credential_environment_substitution');
    need(hash(fs.readFileSync(plan.nativeLauncher)) === plan.sourcePins[plan.nativeLauncher]
      && hash(fs.readFileSync(plan.nativeBinary)) === plan.sourcePins[plan.nativeBinary]
      && hash(fs.readFileSync(plan.parentSandbox)) === plan.sourcePins[plan.parentSandbox],
      'native_launch_source_and_containment_pins');
    nativeSpawned++;
    const child = originalSpawn(file, args, options);
    child.stderr.on('data', data => { if (nativeStderr.reduce((n, b) => n + b.length, 0) < 1024 * 1024) nativeStderr.push(Buffer.from(data)); });
    report.nativeSpawn = { command: file, argumentsUnchanged: true, detached: false,
      privateHome: plan.nativeHome, nestedKernelSandbox: false, inheritedSharedKernelSandbox: true,
      nativeMayAccessFreshRunFiles: true, nativeMayAccessBaoLoopback: true, pid: child.pid ?? null };
    need(Number.isInteger(child.pid), 'native_process_spawned');
    try { observeOwnedNative(child); }
    catch (error) {
      // Fail before the installed transport can send initialize/login. The
      // existing outer owner also kills and waits the entire PGID on all exits.
      try { report.nativeObserverFailureChildTerminationAttempted = child.kill('SIGTERM'); } catch {}
      throw error;
    }
    return child;
  };
  // This installed QA variable affects detached process lifetime only (the
  // pinned transport's resolveCodexAppServerDetachedMode); not auth selection.
  process.env.OPENCLAW_QA_PARENT_PID = String(process.pid);
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
  let nativeApi, runtimeOptions;
  const orderApi = await import(pathToFileURL(path.join(plan.sdkRoot, 'dist/order-CeBlX0NH.js')));
  check('sdk_default_scope', path.resolve(sdk.resolveDefaultAgentDir({})) === agentDir);
  check('sdk_database_scope', path.resolve(sdk.resolveAuthStorePathForDisplay(agentDir)) === path.join(agentDir, 'openclaw-agent.sqlite'));
  const current = sdk.loadAuthProfileStoreWithoutExternalProfiles(agentDir, { allowKeychainPrompt: false });
  for (const [id, cred] of Object.entries(current.profiles)) { sensitive.push(id); sensitive.push(...secrets(cred)); }
  if (plan.mode === 'rollback') {
    const before = JSON.parse(privateRead(plan.baselineOutput));
    const candidate = JSON.parse(privateRead(plan.rollbackCheckpointOutput));
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
    report.originalOrderRestored = digest(current.order) !== digest(before.order);
  } else {
    const before = current;
    check('all_original_account_identities_present', Object.entries(plan.expectedProfiles).every(([id, v]) =>
      before.profiles[id]?.accountId === v.accountId));
    if (plan.mode === 'initial') save(plan.baselineOutput, before);
    // Explicitly carry each source's observed quota state into the private
    // migration, using the installed SDK transaction and a full-store CAS.
    let quotaApplied = false;
    const quotaState = await storeApi.m({ agentDir, updater: store => {
      if (digest(store) !== digest(before)) return false;
      store.usageStats ??= {};
      for (const [id, state] of Object.entries(plan.observedUsageByProfile))
        store.usageStats[id] = { ...store.usageStats[id], ...structuredClone(state) };
      quotaApplied = true; return true;
    }});
    check('observed_quota_carried_with_whole_store_cas', quotaState !== null && quotaApplied);
    sdk.clearRuntimeAuthProfileStoreSnapshots();
    const quotaBaseline = sdk.loadAuthProfileStoreWithoutExternalProfiles(agentDir, { allowKeychainPrompt: false });
    check('quota_carry_preserved_all_credentials', digest(quotaBaseline.profiles) === digest(before.profiles));
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
    check('both_real_profiles_exact', Object.entries(plan.expectedProfiles).every(([id, v]) =>
      digest(after.profiles[id]) === v.credentialSha256));
    check('both_account_identities_preserved', Object.entries(plan.expectedProfiles).every(([id, v]) =>
      after.profiles[id]?.accountId === v.accountId));
    check('source_quota_state_exact_after_import', Object.keys(plan.expectedProfiles).every(id =>
      digest(after.usageStats?.[id]) === digest(quotaBaseline.usageStats?.[id])));
    check('other_profiles_unchanged', Object.entries(before.profiles).filter(([id]) => !Object.hasOwn(plan.expectedProfiles, id))
      .every(([id, v]) => digest(v) === digest(after.profiles[id])) && Object.keys(after.profiles).length === Object.keys(before.profiles).length);
    // Record the actual committed post-import checkpoint before loading a
    // harness. Even a later loader/native failure can attempt exact CAS rollback.
    save(plan.rollbackCheckpointOutput, { storeSha256: digest(after), source: 'committed_installed_sdk_post_import' });
    const order = orderApi.i({ cfg, store: structuredClone(after), provider: plan.model.provider });
    check('original_relative_managed_order_preserved', digest(after.order?.openai) === digest(plan.projectedManagedOrder));
    check('actual_sdk_order_contains_both_trusted_sources', order.length === 2 && order.every(id => Object.hasOwn(plan.expectedProfiles, id)));
    report.orderSameAsEarlierPreparation = digest(order) === digest(plan.actualFinalOrder);
    check('invalid_refresh_account_not_candidate', plan.excludedProfileIds.every(id => !order.includes(id)));
    // The actual registry loader registers all enabled installed harness owners.
    // The actual selector, original default config and no runtime override decide.
    const loader = await import(pathToFileURL(path.join(plan.sdkRoot, 'dist/runtime-registry-loader-Duw3fvRO.js')));
    const selector = await import(pathToFileURL(path.join(plan.sdkRoot, 'dist/selection-JInn13lc.js')));
    const registry = await import(pathToFileURL(path.join(plan.sdkRoot, 'dist/registry-DtLZ3rba.js')));
    await loader.t({ scope: 'all', config: cfg, activationSourceConfig: cfg,
      workspaceDir: plan.workspace, onlyPluginIds: plan.harnessOwnerPluginIds });
    const selectedHarness = selector.o({ provider: plan.model.provider, modelId: plan.model.id,
      config: cfg, agentId: 'main' });
    check('actual_loader_and_selector_choose_codex', selectedHarness?.id === 'codex');
    check('selected_harness_is_actual_registered_instance', registry.r('codex')?.harness === selectedHarness);
    report.harnessSelection = { actualLoader: true, registered: true, selected: selectedHarness.id,
      defaultModelUnchanged: true, runtimeOverrideSupplied: false,
      allInstalledEnabledHarnessOwnerIds: plan.harnessOwnerPluginIds,
      productionLiveSessionOverrideObserved: false };
    nativeApi = await import(pathToFileURL(path.join(plan.codexRoot, 'dist/shared-client-4ICy3U6d.js')));
    const codexConfig = await import(pathToFileURL(path.join(plan.codexRoot, 'dist/config-CYEDnLJ2.js')));
    runtimeOptions = codexConfig.d({ pluginConfig: cfg.plugins.entries.codex.config, env: process.env }).start;
    check('original_agent_scope_and_managed_stdio_options', runtimeOptions.homeScope === 'agent'
      && runtimeOptions.transport === 'stdio' && runtimeOptions.commandSource === 'managed'
      && runtimeOptions.command === 'codex' && !runtimeOptions.env?.CODEX_HOME);
    // Neither authProfileId nor a preferred account is supplied to the native
    // selector or factory; the actual SDK applies the preserved current quotas.
    const selectedProfileId = nativeApi.y({ agentDir, config: cfg });
    check('native_default_selection_is_current_sdk_choice', selectedProfileId === order[0]
      && Object.hasOwn(plan.expectedProfiles, selectedProfileId));
    const cred = after.profiles[selectedProfileId]; sensitive.push(...secrets(cred));
    check('native_selected_credential_is_exact_trusted_generation', digest(cred) === plan.expectedProfiles[selectedProfileId].credentialSha256);
    const claims = JSON.parse(Buffer.from(cred.access.split('.')[1], 'base64url'));
    check('native_selected_jwt_account_and_future_expiry', claims['https://api.openai.com/auth']?.chatgpt_account_id === cred.accountId
      && claims.exp * 1000 > Date.now() + 600000);
    report.selectedProfileOrdinal = Object.keys(before.profiles).indexOf(selectedProfileId) + 1;
    report.selectedCredentialSha256 = digest(cred);
    // Resolution may annotate its in-memory store. Bind rollback to a fresh
    // installed-SDK read of the committed store, not those runtime annotations.
    sdk.clearRuntimeAuthProfileStoreSnapshots();
    const committed = sdk.loadAuthProfileStoreWithoutExternalProfiles(agentDir, { allowKeychainPrompt: false });
    check('committed_both_profiles_exact', Object.entries(plan.expectedProfiles).every(([id, v]) =>
      digest(committed.profiles[id]) === v.credentialSha256));
    check('committed_source_quota_not_cleared', Object.keys(plan.expectedProfiles).every(id =>
      digest(committed.usageStats?.[id]) === digest(quotaBaseline.usageStats?.[id])));
    check('committed_managed_order_exact', digest(committed.order) === digest(after.order));
    check('actual_login_and_both_tls_reads', tokens.length === 1 && Object.values(plan.expectedProfiles).every(v =>
      report.wire.some(x => x.method === 'GET' && x.path === '/v1/openclaw-auth/data/profiles/' + v.profileKey && x.status === 200)));
    save(plan.selectionOutput, { schema: 'heptabao.private-default-model-selection.v1',
      profileId: selectedProfileId, credential: cred, resolvedApiKey: cred.access,
      storeSha256: digest(committed), credentialSha256: digest(cred), model: plan.model,
      source: 'actual_installed_native_auth_selector_after_actual_authbus_cycle' });
    await exerciseNative({ cfg, agentDir, committed, credential: cred, nativeApi, startOptions: runtimeOptions });
    sdk.clearRuntimeAuthProfileStoreSnapshots();
    check('native_factory_preserved_entire_committed_store', digest(sdk.loadAuthProfileStoreWithoutExternalProfiles(agentDir,
      { allowKeychainPrompt: false })) === digest(committed));
    report.actualNativeLocalConsumptionQualified = true;
    report.productionGatewayQualified = false;
    report.profileCount = Object.keys(after.profiles).length;
    report.selectedProfileCount = 1;
    report.importedTrustedProfileCount = 2;
    report.actualOrderOrdinals = order.map(id => Object.keys(before.profiles).indexOf(id) + 1);
    report.sourceQuotaStatePreserved = true;
    report.businessAvailabilityQualified = false;
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
  if (plan?.nativeErrorOutput) { try { save(plan.nativeErrorOutput, { message: String(error?.message ?? error), stack: String(error?.stack ?? '') }); } catch {} }
  report.sourceFrame = String(error?.stack ?? '').split('\n').slice(1, 5).map(line => line.match(/([A-Za-z0-9_.-]+\.(?:js|mjs)):(\d+):(\d+)/)?.slice(1) ?? ['native']);
} finally {
  if (service) { try { await service.stop(); } catch {} }
  if (nativeClient) {
    try { report.nativeClientCloseAndWait = await nativeClient.closeAndWait({ exitTimeoutMs: 3000 }); }
    catch { report.nativeClientCloseAndWait = false; }
    if (!report.nativeClientCloseAndWait) report.ok = false;
  }
  if (plan && nativeSpawned) {
    try { save(plan.nativeDiagnosticOutput, { stderr: Buffer.concat(nativeStderr).toString('utf8') }); } catch {}
    report.nativeAuthJsonAbsentAfterClose = !fs.existsSync(path.join(plan.nativeHome, 'auth.json'));
    if (!report.nativeAuthJsonAbsentAfterClose) report.ok = false;
  }
  if (nativeControlBaseline) {
    let unchanged = false;
    try { unchanged = Object.entries(nativeControlBaseline).every(([file, expected]) => hash(privateRead(file)) === expected); } catch {}
    report.nativeControlFilesBytesUnchangedAfterClose = unchanged;
    report.checks.push({ case: 'native_control_files_exact_bytes_after_close', passed: unchanged });
    if (!unchanged) report.ok = false;
  }
  baoAgent?.destroy();
  if (plan) {
    try { save(plan.custodyOutput, { tokens }); } catch {}
  }
}
process.stdout.write(JSON.stringify(report) + '\n');
process.exitCode = report.ok ? 0 : 1;
