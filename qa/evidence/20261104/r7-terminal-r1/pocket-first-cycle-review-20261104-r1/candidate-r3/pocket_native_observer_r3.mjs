import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';

const hash = value => createHash('sha256').update(value).digest('hex');
const stable = value => Array.isArray(value) ? value.map(stable) : value && typeof value === 'object'
  ? Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])])) : value;
const digest = value => hash(JSON.stringify(stable(value)));
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

export function createPocketNativeObserver(plan, rawSpawn, check) {
  const state = {
    schema: 'heptabao.pocket-current-agent-native-observer.v1',
    homeScope: 'agent', runtimeOverrideApplied: false, authProfileForced: false,
    authProfileStoreOverrideApplied: false, defaultModelChanged: false,
    providerReachabilityQualified: false, providerModelRequestCount: 0,
    nativeBackendAttemptsNotCounted: true, kernelExternalNetworkDenied: true,
    rpc: [], serverRequests: [], factories: [], children: []
  };
  const owned = [];
  let activeAgentDir = null;
  const fail = code => { throw Object.assign(new Error(code), { safeCode: code }); };
  const inside = (root, file) => { const r = path.relative(root, file);
    return r !== '' && r !== '..' && !r.startsWith('../') && !path.isAbsolute(r); };
  function alive(pid) {
    try { process.kill(-pid, 0); return true; }
    catch (error) { if (error.code === 'ESRCH') return false; throw error; }
  }
  async function cleanup(record) {
    if (record.child.pid && alive(record.child.pid)) {
      try { process.kill(-record.child.pid, 'SIGKILL'); }
      catch (error) { if (error.code !== 'ESRCH') throw error; }
    }
    await Promise.race([record.closed, delay(2000)]);
    for (let i = 0; i < 20 && record.child.pid && alive(record.child.pid); i++) await delay(20);
    record.public.stopped = record.child.exitCode !== null || record.child.signalCode !== null;
    record.public.processGroupGone = !!record.child.pid && !alive(record.child.pid);
    return record.public.stopped && record.public.processGroupGone;
  }
  function spawn(command, argv, options = {}) {
    if (!activeAgentDir || command !== plan.nativeManagedCommand
      || JSON.stringify(argv) !== JSON.stringify(['app-server', '--listen', 'stdio://']))
      return fail('native_spawn_outside_exact_managed_allowlist');
    const env = options.env ?? process.env;
    const permittedKeys = new Set(['PATH','HOME','TMPDIR','CODEX_HOME','OPENCLAW_STATE_DIR',
      'OPENCLAW_CONFIG_PATH','OPENCLAW_OAUTH_DIR','OPENCLAW_HOME']);
    if (env.CODEX_HOME !== path.join(activeAgentDir, 'codex-home')
      || !inside(plan.stateRoot, env.CODEX_HOME)
      || env.HOME !== plan.sourceUserHome
      || Object.keys(env).some(key => !permittedKeys.has(key))
      || options.detached !== true
      || (options.shell !== undefined && options.shell !== false)
      || JSON.stringify(options.stdio) !== JSON.stringify(['pipe','pipe','pipe']))
      return fail('native_spawn_environment_or_group');
    const child = rawSpawn(command, argv, { ...options, cwd: plan.nativeWorkspace });
    const pub = { commandSha256: hash(command), agentDirSha256: hash(activeAgentDir),
      pid: child.pid ?? null, stopped: false, processGroupGone: false };
    const record = { child, public: pub, closed: new Promise(resolve => child.once('close', resolve)) };
    child.on('error', () => {});
    owned.push(record); state.children.push(pub);
    return child;
  }
  async function factory(agentId, cfg, sdk) {
    const configured = cfg.agents.list.find(agent => agent.id === agentId);
    const agentDir = configured?.agentDir;
    check('native_agent_dir_bound.' + agentId, typeof agentDir === 'string'
      && agentDir === path.join(plan.stateRoot, 'agents', agentId, 'agent'));
    const native = await import(pathToFileURL(path.join(plan.nativePluginRoot, 'dist/shared-client-4ICy3U6d.js')));
    const configApi = await import(pathToFileURL(path.join(plan.nativePluginRoot, 'dist/config-CYEDnLJ2.js')));
    const authApi = await import(pathToFileURL(path.join(plan.sdkRoot, 'dist/auth-DoAD_162.js')));
    const selector = await import(pathToFileURL(path.join(plan.sdkRoot, 'dist/selection-JInn13lc.js')));
    const registry = await import(pathToFileURL(path.join(plan.sdkRoot, 'dist/registry-DtLZ3rba.js')));
    const policyApi = await import(pathToFileURL(path.join(plan.sdkRoot, 'dist/harness-runtimes-CA3PNIDt.js')));
    const refValue = configured.model ?? cfg.agents.defaults.model;
    const ref = typeof refValue === 'string' ? refValue : refValue.primary;
    check('native_current_model_kept.' + agentId, ref === 'openai/gpt-5.6-sol');
    const provider = ref.slice(0, ref.indexOf('/')), modelId = ref.slice(ref.indexOf('/') + 1);
    const policy = policyApi.n({ config: cfg, provider, modelId, agentId });
    const harness = selector.o({ provider, modelId, config: cfg, agentId });
    check('actual_registered_native_dispatch.' + agentId, policy.runtime === 'codex'
      && policy.runtimeSource === 'model' && harness?.id === 'codex'
      && registry.r('codex')?.harness === harness);
    const authPlan = authApi.t({ config: cfg, provider, harnessId: harness.id, harnessRuntime: policy.runtime });
    check('actual_harness_auth_provider.' + agentId, authPlan.harnessAuthProvider === 'openai'
      && !authPlan.forwardedAuthProfileId);
    const store = sdk.loadAuthProfileStoreWithoutExternalProfiles(agentDir, { allowKeychainPrompt: false });
    const selected = await native.y({ agentDir, config: cfg });
    check('actual_native_default_profile.' + agentId, selected === plan.expectedProfileId);
    const credential = store.profiles[selected];
    check('native_selected_credential_exact.' + agentId, digest(credential) === plan.expectedCredentialSha256
      && credential.accountId === plan.expectedAccountId);
    const runtime = configApi.d({ pluginConfig: cfg.plugins.entries.codex.config, config: cfg, agentDir, env: process.env });
    check('native_current_agent_managed_start.' + agentId, runtime.start.homeScope === 'agent'
      && runtime.start.transport === 'stdio' && runtime.start.commandSource === 'managed'
      && runtime.start.command === 'codex'
      && JSON.stringify(runtime.start.args) === JSON.stringify(['app-server','--listen','stdio://']));
    const firstOwned = owned.length, firstRpc = state.rpc.length;
    let client, closeResult = false;
    activeAgentDir = agentDir;
    const started = Date.now();
    try {
      client = await native.i({ startOptions: runtime.start, config: cfg, agentDir, timeoutMs: 10000,
        onStartedClient(value) {
          client = value;
          // Register first, before the installed runtime's OAuth refresh handler.
          value.addRequestHandler(async request => {
            state.serverRequests.push({ agentId, method: request?.method === 'account/chatgptAuthTokens/refresh'
              ? 'account/chatgptAuthTokens/refresh' : 'other_server_request',
              methodSha256: hash(String(request?.method)), deniedBeforeSdkHandler: true });
            throw Object.assign(new Error('native_server_request_not_authorized'),
              { safeCode: 'native_server_request_not_authorized' });
          });
          const request = value.request.bind(value), notify = value.notify.bind(value);
          value.request = (method, params, options) => {
            if (!['initialize','account/login/start'].includes(method))
              return fail('native_rpc_outside_initialize_and_current_token_login');
            const previous = state.rpc.slice(firstRpc);
            if (method === 'initialize' && previous.length !== 0) return fail('native_duplicate_initialize');
            if (method === 'account/login/start') {
              if (previous.length !== 1 || previous[0].method !== 'initialize'
                || params?.type !== 'chatgptAuthTokens'
                || params.accessToken !== credential.access
                || params.chatgptAccountId !== credential.accountId
                || digest(Object.keys(params).sort()) !== digest(['type','accessToken','chatgptAccountId','chatgptPlanType'].sort())
                || params.chatgptPlanType !== ((credential.chatgptPlanType ?? credential.planType)?.trim?.() || null))
                return fail('native_login_not_exact_current_selected_credential');
            }
            const row = { agentId, method, response: 'pending',
              currentCredentialExact: method === 'account/login/start' };
            state.rpc.push(row);
            const originalTimeout = options?.timeoutMs;
            const cappedTimeout = typeof originalTimeout === 'number' && Number.isFinite(originalTimeout) && originalTimeout > 0
              ? Math.min(originalTimeout, 10000) : 10000;
            return request(method, params, { ...(options ?? {}), timeoutMs: cappedTimeout }).then(result => {
              if(method==='account/login/start'){
                row.responseType = result?.type === 'chatgptAuthTokens' ? 'chatgptAuthTokens' : 'unexpected_type';
                row.responseTypeSha256 = hash(String(result?.type));
                check('native_login_actual_response_type.'+agentId,result?.type==='chatgptAuthTokens');
              }
              row.response = 'success'; return result;
            }, error => { row.response = 'error'; row.errorSha256 = hash(String(error?.message ?? error)); throw error; });
          };
          value.notify = (method, params) => {
            if (method !== 'initialized') return fail('native_notification_outside_initialized');
            return notify(method, params);
          };
        }
      });
      const identity = client.getRuntimeIdentity(), rpc = state.rpc.slice(firstRpc);
      check('native_real_managed_version.' + agentId, client.getServerVersion() === plan.nativeVersion);
      check('native_effective_home_is_owned_agent.' + agentId, identity?.codexHome === path.join(agentDir, 'codex-home'));
      check('native_real_login_response.' + agentId, rpc.length === 2
        && rpc[0].method === 'initialize' && rpc[1].method === 'account/login/start'
        && rpc.every(row => row.response === 'success'));
      check('native_no_server_refresh_or_tool_request.' + agentId,
        state.serverRequests.every(row => row.agentId !== agentId));
      state.factories.push({ agentId, initialized: true, serverVersion: client.getServerVersion(),
        effectiveCodexHome: identity.codexHome, nativeCurrentCredentialConsumed: true,
        selectedProfileIdSha256: hash(selected), selectedAccountSha256: hash(credential.accountId),
        selectedAccessSha256: hash(credential.access), elapsedMs: Date.now() - started,
        providerAvailabilityQualified: false, modelRequestDispatched: false });
    } finally {
      let closeError = null;
      try { if (client) closeResult = await client.closeAndWait({ forceKillDelayMs: 500, exitTimeoutMs: 2000 }); }
      catch (error) { closeError = hash(String(error?.message ?? error)); }
      const records = owned.slice(firstOwned), stopped = [];
      for (const record of records) {
        try { stopped.push(await cleanup(record)); }
        catch (error) { record.public.cleanupErrorSha256 = hash(String(error?.message ?? error)); stopped.push(false); }
      }
      activeAgentDir = null;
      if (closeError) state.closeErrorSha256 = closeError;
      check('native_owned_cleanup.' + agentId, records.length === 1 && closeResult && stopped.every(Boolean));
    }
  }
  async function closeAll() {
    const stopped = [];
    for (const record of owned) {
      try { stopped.push(await cleanup(record)); }
      catch (error) { record.public.cleanupErrorSha256 = hash(String(error?.message ?? error)); stopped.push(false); }
    }
    return stopped.every(Boolean);
  }
  return { state, spawn, factory, closeAll };
}
