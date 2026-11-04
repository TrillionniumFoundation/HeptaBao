#!/usr/bin/env node
/** One real installed Codex factory for one actual Mac agent.
 * A separate five-agent worker already ran the shared AuthBus cycle. This
 * worker never repeats that cycle or supplies a preferred profile. The real
 * launchd wrapper owns its single-use anonymous-pipe process observer.
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
const report = { schema: 'heptabao.mac-five-agent-single-native-worker.r1', ok: false,
  productionChanged: false, productionTrafficCutover: false, providerResponseObtained: false, externalNetworkEgressAllowed: false,
  explicitModelRpcDispatched: false, nativeBackgroundNetworkAttemptCount: null,
  nativeBackgroundNetworkAttemptsNotMeasured: true, j3160Contacted: false,
  credentialValuesPublished: false, accountIdentitiesPublished: false,
  allAccountsQualified: false, checks: [], wire: [] };
let service, baoAgent, plan, nativeClient;
let nativeStarted = 0, nativeSpawned = 0;
let nativeControlBaseline;
let nativeUntil, nativeCloseAttempted = false;
const workerStarted = process.hrtime.bigint();
function boundedNativeMs(cap) {
  need(nativeUntil !== undefined, 'native_phase_allocation_required');
  const left = Number((nativeUntil - process.hrtime.bigint()) / 1000000n);
  need(left > 0, 'shared_phase_allocation_exhausted');
  return Math.min(cap, left);
}
async function closeNativeOnce(client) {
  need(!nativeCloseAttempted, 'native_close_not_repeated');
  nativeCloseAttempted = true;
  return client.closeAndWait({ exitTimeoutMs: boundedNativeMs(3000) });
}
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
  const dir=fs.openSync(path.dirname(file),fs.constants.O_RDONLY|fs.constants.O_DIRECTORY|fs.constants.O_NOFOLLOW);
  try { fs.fsyncSync(dir); } finally { fs.closeSync(dir); }
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
    startOptions, timeoutMs: boundedNativeMs(15000), onStartedClient: observeStarted });
  check('actual_native_factory_initialized_and_logged_in', client === nativeClient && client.initialized === true
    && initializeSeen === 1 && loginSucceeded === 1 && nativeSpawned === 1);
  const identity = client.getRuntimeIdentity();
  report.nativeVersion = client.getServerVersion();
  report.nativeRuntimeIdentityKeys = Object.keys(identity ?? {});
  need(String(client.getServerVersion()) === '0.144.3', 'exact_managed_native_version');
  check('native_runtime_reports_exact_isolated_home', identity?.codexHome === plan.nativeHome);
  save(plan.nativeIdentityOutput, { runtimeIdentity: identity, version: client.getServerVersion() });
  const account = await client.request('account/read', { refreshToken: false }, { timeoutMs: boundedNativeMs(8000) });
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
  const closed = await closeNativeOnce(client);
  check('actual_native_close_and_wait', closed === true); nativeClient = undefined;
  check('native_local_rpc_only', report.nativeRpc.sent.map(x => x.method).join('|') === 'initialize|account/login/start|account/read'
    && report.nativeRpc.sent.every(x => x.completed));
  report.nativeExternalRefreshRequestsRefused = report.nativeRpc.serverRequestsRefused.filter(x => x === 'account/chatgptAuthTokens/refresh').length;
  report.scope = 'Local real native credential consumption under external-network denial; native startup background attempts are not counted; no model/business availability or production gateway cutover qualification.';
}

try {
  plan = JSON.parse(privateRead(process.argv[2]));
  const AGENTS = ['main', 'trnm', 'hepta-ui', 'hepta', 'hepta-backend'];
  const ROOT = '/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-r10-current-consumer-r1';
  need(plan.schema === 'heptabao.mac-five-agent-worker.private.r1' && plan.mode === 'native'
    && AGENTS.includes(plan.agentId) && ['initial', 'cold-new-process'].includes(plan.phase),
    'exact_native_worker_scope');
  need(plan.workRoot === ROOT && plan.phaseRoot === path.join(ROOT, plan.phase)
    && plan.stateRoot === path.join(plan.phaseRoot, 'state')
    && fs.realpathSync(plan.stateRoot) === plan.stateRoot, 'exact_owned_state_scope');
  need(Number.isSafeInteger(plan.phaseRemainingMs) && plan.phaseRemainingMs > 0
    && plan.phaseRemainingMs <= 120000 && plan.phaseOwnerPid === process.ppid,
    'original_phase_owner_and_remaining_allocation');
  // A relative allocation is only a child-side shortening. The real wrapper
  // keeps and enforces the original monotonic phase deadline across all six
  // workers, including process startup and all observer/cleanup time.
  nativeUntil = workerStarted + BigInt(plan.phaseRemainingMs) * 1000000n;
  report.agentId = plan.agentId; report.phase = plan.phase;
  report.phaseOwnerAbsoluteDeadlineAuthoritative = true;
  report.allocatedRemainingMs = plan.phaseRemainingMs;
  check('scoped_application_roots', process.env.OPENCLAW_STATE_DIR === plan.stateRoot
    && process.env.OPENCLAW_CONFIG_PATH === path.join(plan.stateRoot, 'openclaw.json')
    && process.env.OPENCLAW_OAUTH_DIR === path.join(plan.stateRoot, 'oauth'));
  for (const key of ['baselineOutput','rollbackCheckpointOutput','selectionOutput',
    'custodyOutput','nativeDiagnosticOutput','nativeErrorOutput','nativeIdentityOutput','nativeAccountOutput'])
    need(within(plan.phaseRoot, plan[key]), 'native_private_output_scope.' + key);
  const cfg = JSON.parse(privateRead(path.join(plan.stateRoot, 'openclaw.json')));
  check('all_five_configured_agents_preserved', digest(cfg.agents.list.map(a => a.id)) === digest(AGENTS));
  const agentDir = path.join(plan.stateRoot, 'agents', plan.agentId, 'agent');
  need(plan.nativeHome === path.join(agentDir, 'codex-home')
    && within(plan.phaseRoot, plan.nativeTmp), 'per_agent_native_home_and_tmp');
  const declared = cfg.agents.list.find(a => a.id === plan.agentId);
  check('actual_configured_agent_directory', (declared.agentDir ?? path.join(plan.stateRoot,'agents',declared.id,'agent')) === agentDir);
  for (const [file, expected] of Object.entries(plan.sourcePins))
    check('source.' + path.basename(file), hash(fs.readFileSync(file)) === expected);
  const originalExecFileSync = childProcess.execFileSync;
  const originalSpawn = childProcess.spawn;
  for (const method of ['log', 'warn', 'error', 'info', 'debug']) console[method] = () => {};
  globalThis.fetch = deny;
  http.request = deny; http.get = deny; https.request = deny; https.get = deny;
  for (const method of ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork'])
    childProcess[method] = deny;
  childProcess.execFileSync = (file, args, options) => {
    if (file !== 'mount' || !Array.isArray(args) || args.length || options !== undefined) return deny();
    const s = fs.lstatSync('/sbin/mount');
    need(process.platform === 'darwin' && s.isFile() && s.uid === 0 && (s.mode & 0o022) === 0, 'trusted_mount_tool');
    return originalExecFileSync('/sbin/mount', [], { timeout: boundedNativeMs(3000), maxBuffer: 262144,
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

  syncBuiltinESMExports();
  const sdk = await import(pathToFileURL(path.join(plan.sdkRoot, 'dist/plugin-sdk/agent-runtime.js')));
  const orderApi = await import(pathToFileURL(path.join(plan.sdkRoot, 'dist/order-CeBlX0NH.js')));
  const rowApi = await import(pathToFileURL(path.join(path.dirname(process.argv[1]), 'mac_auth_rows_cas_r1.mjs')));
  const cacheApi = await import(pathToFileURL(path.join(path.dirname(process.argv[1]), 'mac_authbus_cache_cas_r1.mjs')));
  const candidate = JSON.parse(privateRead(plan.rollbackCheckpointOutput));
  const currentStores = () => {
    sdk.clearRuntimeAuthProfileStoreSnapshots();
    return Object.fromEntries(AGENTS.map(id => [id, sdk.loadAuthProfileStoreWithoutExternalProfiles(
      path.join(plan.stateRoot, 'agents', id, 'agent'), { allowKeychainPrompt: false })]));
  };
  const allBefore = currentStores();
  const rowsBefore = Object.fromEntries(AGENTS.map(id => [id, rowApi.captureAuthRows(plan.stateRoot,id)]));
  const cachesBefore = cacheApi.captureAuthBusCaches(plan.stateRoot);
  for (const id of AGENTS) {
    check('post_cycle_effective_checkpoint.'+id, digest(allBefore[id]) === digest(candidate.stores[id]));
    check('post_cycle_raw_checkpoint.'+id, rowApi.authRowsDigest(rowsBefore[id]) === rowApi.authRowsDigest(candidate.authRows[id]));
    for (const [profile,cred] of Object.entries(allBefore[id].profiles)) {
      sensitive.push(profile); sensitive.push(...secrets(cred));
    }
  }
  check('post_cycle_six_cache_checkpoint', digest(cachesBefore) === digest(candidate.authbusCaches));
  const committed = allBefore[plan.agentId];
  const order = orderApi.i({ cfg, store: structuredClone(committed), provider: plan.model.provider });
  const loader = await import(pathToFileURL(path.join(plan.sdkRoot, 'dist/runtime-registry-loader-Duw3fvRO.js')));
  const selector = await import(pathToFileURL(path.join(plan.sdkRoot, 'dist/selection-JInn13lc.js')));
  const registry = await import(pathToFileURL(path.join(plan.sdkRoot, 'dist/registry-DtLZ3rba.js')));
  await loader.t({ scope:'all', config:cfg, activationSourceConfig:cfg,
    workspaceDir:plan.workspace, onlyPluginIds:plan.harnessOwnerPluginIds });
  const selectedHarness = selector.o({ provider:plan.model.provider, modelId:plan.model.id,
    config:cfg, agentId:plan.agentId });
  check('actual_loader_and_selector_choose_codex', selectedHarness?.id === 'codex');
  check('selected_harness_is_actual_registered_instance', registry.r('codex')?.harness === selectedHarness);
  const nativeApi = await import(pathToFileURL(path.join(plan.codexRoot, 'dist/shared-client-4ICy3U6d.js')));
  const codexConfig = await import(pathToFileURL(path.join(plan.codexRoot, 'dist/config-CYEDnLJ2.js')));
  const startOptions = codexConfig.d({ pluginConfig:cfg.plugins.entries.codex.config, env:process.env }).start;
  check('original_agent_scope_and_managed_stdio_options', startOptions.homeScope === 'agent'
    && startOptions.transport === 'stdio' && startOptions.commandSource === 'managed'
    && startOptions.command === 'codex' && !startOptions.env?.CODEX_HOME);
  // Do not force either trusted shared ID. The actual five-agent SDK preserves
  // its complete original order/usage and can select any current eligible ID.
  const selectedProfileId = nativeApi.y({ agentDir, config:cfg });
  check('native_default_is_actual_sdk_first_candidate', order.length > 0
    && selectedProfileId === order[0] && Object.hasOwn(committed.profiles,selectedProfileId));
  const credential = committed.profiles[selectedProfileId];
  sensitive.push(...secrets(credential));
  check('selected_actual_oauth_shape', credential?.provider === plan.model.provider
    && credential?.type === 'oauth' && typeof credential.access === 'string'
    && typeof credential.accountId === 'string');
  const claims = JSON.parse(Buffer.from(credential.access.split('.')[1], 'base64url'));
  check('actual_selected_jwt_identity', claims['https://api.openai.com/auth']?.chatgpt_account_id === credential.accountId);
  const profileKeys = Object.keys(committed.profiles);
  report.selectedProfileOrdinal = profileKeys.indexOf(selectedProfileId) + 1;
  report.selectedCredentialSha256 = digest(credential);
  report.actualOrderOrdinals = order.map(id => profileKeys.indexOf(id) + 1);
  report.profileCount = profileKeys.length;
  report.selectedCredentialExpiryObserved = typeof credential.expires === 'number';
  report.selectionForced = false;
  report.sharedManifestOrInboxCycleExecutedHere = false;
  save(plan.selectionOutput,{schema:'heptabao.mac-current-native-selection.private.r1',
    agentId:plan.agentId,profileId:selectedProfileId,credential,credentialSha256:digest(credential),
    storeSha256:digest(committed),model:plan.model,source:'actual_installed_selector_after_five_agent_cycle'});
  await exerciseNative({cfg,agentDir,committed,credential,nativeApi,startOptions});
  const allAfter = currentStores();
  for (const id of AGENTS) {
    check('native_preserved_whole_effective_store.'+id, digest(allAfter[id]) === digest(allBefore[id]));
    check('native_preserved_whole_raw_store.'+id, rowApi.authRowsDigest(rowApi.captureAuthRows(plan.stateRoot,id)) === rowApi.authRowsDigest(rowsBefore[id]));
  }
  check('native_preserved_six_caches', digest(cacheApi.captureAuthBusCaches(plan.stateRoot)) === digest(cachesBefore));
  check('single_actual_native_factory', nativeStarted === 1 && nativeSpawned === 1);
  check('no_explicit_network_or_other_process', blockedOperations === 0 && report.wire.length === 0);
  check('source_pins_unchanged', Object.entries(plan.sourcePins).every(([file,pin])=>hash(fs.readFileSync(file))===pin));
  check('report_contains_no_credential_values', sensitive.every(value=>!JSON.stringify(report).includes(value)));
  boundedNativeMs(1);
  report.ok = true;
} catch (error) {
  report.error = error?.safeCode ?? 'mac_single_native_worker_failed';
  report.errorClass = error?.constructor?.name ?? 'unknown';
  report.errorCodeSha256 = hash(String(error?.message ?? error));
  report.sourceFrame = String(error?.stack ?? '').split('\n').slice(1,5)
    .map(line=>line.match(/([A-Za-z0-9_.-]+\.(?:js|mjs)):(\d+):(\d+)/)?.slice(1)??['native']);
} finally {
  if (nativeClient && !nativeCloseAttempted) {
    try { report.nativeClientCloseAndWait = await closeNativeOnce(nativeClient); }
    catch { report.nativeClientCloseAndWait = false; }
    if (!report.nativeClientCloseAndWait) report.ok = false;
  }
  if (plan && nativeSpawned) {
    try { save(plan.nativeDiagnosticOutput,{stderr:Buffer.concat(nativeStderr).toString('utf8')}); }
    catch { report.ok=false; }
    report.nativeAuthJsonAbsentAfterClose = !fs.existsSync(path.join(plan.nativeHome,'auth.json'));
    if (!report.nativeAuthJsonAbsentAfterClose) report.ok=false;
  }
  if (nativeControlBaseline) {
    try { report.nativeControlFilesBytesUnchangedAfterClose =
      Object.entries(nativeControlBaseline).every(([file,pin])=>hash(privateRead(file))===pin); }
    catch { report.nativeControlFilesBytesUnchangedAfterClose=false; }
    if (!report.nativeControlFilesBytesUnchangedAfterClose) report.ok=false;
  }
  try { if (plan) save(plan.custodyOutput,{tokens:[]}); } catch { report.ok=false; }
}
if (sensitive.some(value=>JSON.stringify(report).includes(value))) {
  for (const key of Object.keys(report)) delete report[key];
  Object.assign(report,{schema:'heptabao.mac-five-agent-single-native-worker.r1',ok:false,
    error:'public_projection_contains_sensitive_value'});
}
process.stdout.write(JSON.stringify(report)+'\n');
process.exitCode=report.ok?0:1;
