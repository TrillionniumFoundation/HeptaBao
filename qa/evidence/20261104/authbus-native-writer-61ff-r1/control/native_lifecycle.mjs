import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { syncBuiltinESMExports } from 'node:module';

const hash = v => createHash('sha256').update(v).digest('hex');
const stable = v => Array.isArray(v) ? v.map(stable) : v && typeof v === 'object'
  ? Object.fromEntries(Object.keys(v).sort().map(k => [k, stable(v[k])])) : v;
const digest = v => hash(JSON.stringify(stable(v)));
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
function need(v, code) { if (!v) throw Object.assign(new Error(code), { safeCode: code }); }
function identity(pid) {
  try {
    const raw = fs.readFileSync('/proc/' + pid + '/stat', 'utf8');
    const end = raw.lastIndexOf(') '); need(end > 0, 'owned_proc_stat_shape');
    const f = raw.slice(end + 2).trim().split(/\s+/);
    return { pid: Number(pid), state: f[0], ppid: Number(f[1]), pgid: Number(f[2]),
      session: Number(f[3]), startTicks: f[19], executable: fs.realpathSync('/proc/' + pid + '/exe') };
  } catch (e) { if (e.code === 'ENOENT' || e.code === 'ESRCH') return null; throw e; }
}
function sameProcess(saved, current) {
  return !!saved && !!current && saved.pid === current.pid && saved.startTicks === current.startTicks
    && saved.executable === current.executable;
}
async function waitFor(predicate, ms, code) {
  const end = Date.now() + ms;
  while (Date.now() < end) { const value = predicate(); if (value) return value; await delay(20); }
  throw Object.assign(new Error(code), { safeCode: code });
}
function privateBytes(file) {
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const s = fs.fstatSync(fd);
    need(s.isFile() && s.uid === process.getuid() && (s.mode & 0o077) === 0 && s.nlink === 1
      && s.size <= 2097152, 'private_native_input_custody');
    const b = fs.readFileSync(fd), t = fs.fstatSync(fd), u = fs.lstatSync(file);
    need([t,u].every(x => x.dev === s.dev && x.ino === s.ino && x.size === s.size
      && x.mtimeMs === s.mtimeMs && x.ctimeMs === s.ctimeMs), 'private_native_input_stable');
    return b;
  } finally { fs.closeSync(fd); }
}
function savePrivate(file, value) {
  const b = Buffer.from(JSON.stringify(value));
  const fd = fs.openSync(file, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL
    | fs.constants.O_NOFOLLOW, 0o600);
  try { fs.writeFileSync(fd, b); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  return hash(b);
}

export async function createNativeLifecycle({ plan, cfg, agentDir, before, childProcess, originalSpawn, check, sensitive }) {
  const n = plan.native;
  need(n && ['active-lease','pending-initialize','pending-before-client','abnormal-wrapper'].includes(n.scenario),
    'native_scenario_scope');
  const report = { schema:'heptabao.actual-native-shared-factory-retirement.v1',
    scenario:n.scenario, patchedExpected:n.patched, actualFactory:true,
    providerCalled:false, modelCalled:false, explicitRefreshRpcSent:false, externalTokenLoginSent:false,
    productionGatewaySelectionQualified:false, backgroundNetworkAttemptsNotMeasured:true,
    externalNetworkKernelDenied:true, commandChanged:false, modelConfigurationChanged:false,
    nativeSourceAdoptedByAuthBus:false, events:[], nativeCheckpoints:[], rpc:[],
    serverRequestsRefused:[], transports:[], generationsUnchanged:true,
    sharedEntryRemoved:false, secondProcessSpawned:false, secondFactoryInitialized:false,
    twoReadyLeasesObserved:false, singleWriterInvariantPassed:null,
    harnessCleanupUsedAsRetirementProof:false, cleanup:{ attempted:false, allOwnedStopped:false } };
  const clock = () => Number(process.hrtime.bigint() / 1000000n);
  function event(kind, detail={}) { report.events.push({ sequence:report.events.length + 1,
    monotonicMs:clock(), kind, ...detail }); }
  need(digest(cfg.plugins.entries.codex) === n.sourceCodexConfigurationSha256, 'original_codex_configuration_preserved');
  const nativeAuth = path.join(n.nativeHome, 'auth.json'), nativeConfig = path.join(n.nativeHome, 'config.toml');
  need(process.env.HOME === n.home && process.env.CODEX_HOME === n.nativeHome
    && n.nativeHome.startsWith(plan.workRoot + '/'), 'native_private_homes');
  const auth = JSON.parse(privateBytes(nativeAuth)), tokens = auth.tokens;
  const sourceEntries = Object.entries(before.profiles), sourceNative = sourceEntries[2]?.[1];
  need(sourceEntries.length === 3 && auth.auth_mode === 'chatgpt' && sourceNative?.type === 'oauth'
    && tokens?.access_token === sourceNative.access && tokens?.refresh_token === sourceNative.refresh
    && tokens?.account_id === sourceNative.accountId, 'native_original4_private_copy_exact');
  sensitive.push(tokens.access_token, tokens.refresh_token, tokens.account_id);
  if (tokens.id_token) sensitive.push(tokens.id_token);
  const claims = token => JSON.parse(Buffer.from(token.split('.')[1], 'base64url'));
  const accessClaims = claims(tokens.access_token);
  need(accessClaims['https://api.openai.com/auth']?.chatgpt_account_id === tokens.account_id,
    'native_original4_access_identity');
  const emailCandidates = new Set([sourceNative.email, claims(tokens.id_token ?? tokens.access_token).email,
    accessClaims.email, accessClaims['https://api.openai.com/profile']?.email].filter(v => typeof v === 'string' && v));
  need(emailCandidates.size === 1, 'native_original4_email_identity_unambiguous');
  const expectedEmail = [...emailCandidates][0]; sensitive.push(expectedEmail);
  const expectedGeneration = digest({access:tokens.access_token,refresh:tokens.refresh_token,accountId:tokens.account_id});
  need(expectedGeneration === n.nativeGenerationSha256, 'native_original4_generation_pin');
  const expectedAuth = n.nativeAuthSha256, expectedConfig = n.nativeConfigSha256;
  let watchFailure = false, watcher;
  function checkpoint(tag) {
    const a = privateBytes(nativeAuth), c = privateBytes(nativeConfig);
    const parsed = JSON.parse(a), t = parsed.tokens;
    const generation = digest({access:t?.access_token,refresh:t?.refresh_token,accountId:t?.account_id});
    const exact = hash(a) === expectedAuth && hash(c) === expectedConfig && generation === expectedGeneration;
    report.nativeCheckpoints.push({tag,authSha256:hash(a),configSha256:hash(c),generationSha256:generation,exact});
    if (!exact) { watchFailure = true; report.generationsUnchanged = false; }
    need(exact && !watchFailure, 'native_generation_or_config_changed_at_' + tag);
  }
  checkpoint('before_factory_import');
  function startWatcher() { watcher = fs.watch(n.nativeHome, (kind, name) => {
    if (name && !['auth.json','config.toml'].includes(String(name))) return;
    try { checkpoint('filesystem_event_' + report.nativeCheckpoints.length); }
    catch { watchFailure = true; report.generationsUnchanged = false; }
  }); }
  const factory = await import(pathToFileURL(n.factoryEntry));
  const configModule = await import(pathToFileURL(n.configEntry));
  const recycler = await import(pathToFileURL(path.join(path.dirname(plan.pluginEntry), 'codex-client-recycler.js')));
  const runtime = configModule.d({ pluginConfig:cfg.plugins.entries.codex.config, env:process.env,
    modelProvider:'codex', model:'gpt-6.1-sol', config:cfg, agentDir }).start;
  need(runtime.homeScope === 'user' && runtime.transport === 'stdio' && runtime.commandSource === 'config'
    && runtime.command === n.command && JSON.stringify(runtime.args) === JSON.stringify(['app-server','--listen','stdio://']),
    'unchanged_real_native_runtime_start_options');
  report.factorySha256 = hash(fs.readFileSync(n.factoryEntry)); report.command = n.command;
  report.runtimeOptionsSha256 = digest(runtime); report.startOptionsSource = 'actual_pinned_config_resolver';
  report.wrapperSha256 = n.wrapperSha256; report.nativeBinarySha256 = n.nativeBinarySha256;
  report.nativeCredentialSha256 = digest(sourceNative); report.nativeGenerationSha256 = expectedGeneration;
  const STATE = Symbol.for('openclaw.codexAppServerClientState');
  let startedResolve; const started = new Promise(resolve => { startedResolve = resolve; });
  let gateResolve; const gate = new Promise(resolve => { gateResolve = resolve; });
  let gateReleased = false, oldPromise, newerPromise, newerOutcome, oldKey, oldEntry, first, second;
  const tracked = [], children = [];
  let callbackRetirement = null, cleanupStarted = false;
  function living(saved) { return sameProcess(saved, identity(saved?.pid)); }
  function nativeFor(wrapperPid) {
    const candidates = [];
    for (const name of fs.readdirSync('/proc')) {
      if (!/^[0-9]+$/.test(name)) continue;
      const p = identity(Number(name));
      if (p && p.ppid === wrapperPid && p.executable === n.nativeBinary) candidates.push(p);
    }
    need(candidates.length <= 1, 'unique_owned_native_for_wrapper');
    return candidates[0] ?? null;
  }
  function exactSignal(saved, signal, label) {
    need(living(saved), 'signal_requires_same_owned_start_identity');
    event(label, {pid:saved.pid,startTicks:saved.startTicks,signal});
    process.kill(saved.pid, signal);
  }
  childProcess.spawn = (command, args, options) => {
    need(command === n.command && JSON.stringify(args) === JSON.stringify(runtime.args)
      && options?.shell === false && options.detached === false && options.env?.HOME === n.home
      && options.env?.CODEX_HOME === n.nativeHome && !options.env.OPENAI_API_KEY && !options.env.CODEX_API_KEY,
      'only_exact_original_native_spawn');
    need(children.length < 2, 'bounded_two_actual_native_starts');
    checkpoint('before_spawn_' + (children.length + 1));
    const priorNativeAlive = tracked.some(x => x.native && living(x.native));
    event('native_wrapper_spawn_requested', {ordinal:children.length + 1,priorNativeAlive,
      priorWrapperAlive:tracked.some(x => x.wrapper && living(x.wrapper))});
    // Observe the original decision; an unsafe second spawn is not blocked here.
    const child = originalSpawn(command, args, options); children.push(child);
    if (children.length === 2) { report.secondProcessSpawned = true;
      report.secondSpawnPriorNativeAlive = priorNativeAlive; }
    if (children.length === 1 && n.scenario === 'pending-before-client') {
      const state = globalThis[STATE], pairs = [...state.clients.entries()];
      need(pairs.length === 1 && pairs[0][1].client === undefined
        && pairs[0][1].pendingAcquires === 1, 'real_spawn_before_onStarted_pending_entry');
      oldKey = pairs[0][0]; oldEntry = pairs[0][1];
      callbackRetirement = recycler.retireSharedCodexAppServerClients();
      event('actual_recycler_at_spawn_before_onStarted', {retired:callbackRetirement.retired,
        deferred:callbackRetirement.deferred,clientAbsent:true,pendingAcquires:oldEntry.pendingAcquires});
    }
    child.once('exit', (code, signal) => event('wrapper_exit', {ordinal:children.indexOf(child)+1,
      pid:child.pid,code,signal,cleanupStarted}));
    return child;
  };
  syncBuiltinESMExports();
  function observe(client) {
    const ordinal = tracked.length + 1;
    need(ordinal <= 2 && client.child && children[ordinal-1] === client.child,
      'real_started_client_and_observed_spawn_identity');
    const rec = {client,ordinal,wrapper:identity(client.child.pid),native:null,lease:false,
      initializeDispatched:false,initializeCompleted:false};
    need(rec.wrapper && rec.wrapper.executable === n.nodeRealpath, 'actual_wrapper_node_identity');
    tracked.push(rec);
    event('factory_onStarted', {ordinal,wrapper:rec.wrapper});
    client.addRequestHandler(async request => {
      report.serverRequestsRefused.push({ordinal,method:request.method === 'account/chatgptAuthTokens/refresh'
        ? request.method : 'other'});
      throw Object.assign(new Error('isolated_native_server_request_refused'),{safeCode:'isolated_native_server_request_refused'});
    });
    const originalRequest = client.request.bind(client);
    client.request = (method, params, options) => {
      if (method === 'initialize') need(!rec.initializeDispatched && params?.clientInfo?.name === 'openclaw',
        'original_initialize_once');
      else need(method === 'account/read' && digest(params) === digest({refreshToken:false}),
        'only_non_refresh_account_read_after_initialize');
      const item = {ordinal,method,completed:false}; report.rpc.push(item);
      const dispatch = () => {
        if (method === 'initialize') { rec.initializeDispatched = true; event('initialize_dispatched',{ordinal}); }
        // Preserve the actual argument objects and actual native response.
        return originalRequest(method,params,options).then(response => {
          item.completed = true;
          if (method === 'initialize') { rec.initializeCompleted = true; event('initialize_completed',{ordinal}); }
          return response;
        });
      };
      if (ordinal === 1 && method === 'initialize' && n.scenario.startsWith('pending-')) {
        event('original_initialize_held_before_dispatch',{ordinal});
        return gate.then(dispatch);
      }
      return dispatch();
    };
    const originalNotify = client.notify.bind(client);
    client.notify = (method,params) => {
      need(method === 'initialized' && rec.initializeCompleted, 'only_original_initialized_notification');
      return originalNotify(method,params);
    };
    if (ordinal === 1) { first=rec; startedResolve(rec); } else second=rec;
  }
  async function attachNative(rec) {
    rec.native = await waitFor(() => nativeFor(rec.wrapper.pid),5000,'real_native_child_identity_timeout');
    need(rec.native.pgid === process.pid && rec.wrapper.pgid === process.pid,
      'qa_original_transport_owned_process_group');
    report.transports.push({ordinal:rec.ordinal,wrapper:rec.wrapper,native:rec.native});
    event('native_writer_identity',{ordinal:rec.ordinal,native:rec.native});
  }
  async function account(rec, label) {
    need(rec.client.initialized && rec.client.getServerVersion() === '0.159.2'
      && rec.client.getRuntimeIdentity()?.codexHome === n.nativeHome, 'actual_native_version_and_home');
    const response = await rec.client.request('account/read',{refreshToken:false},{timeoutMs:8000});
    const bytesHash = savePrivate(path.join(n.outputDir,label+'.account.private.json'),response);
    need(response?.account?.type === 'chatgpt' && response.account.email === expectedEmail,
      'actual_native_original4_account_identity');
    checkpoint('after_account_' + label);
    event('actual_account_read',{ordinal:rec.ordinal,responseSha256:bytesHash,
      accountEmailSha256:hash(expectedEmail),refreshToken:false});
  }
  function release(rec, label) {
    need(rec.lease && factory.o(rec.client) === true, 'original_factory_lease_release');
    rec.lease = false; event(label,{ordinal:rec.ordinal});
  }
  const options = () => ({agentDir,config:cfg,startOptions:runtime,timeoutMs:15000,onStartedClient:observe});
  async function begin() {
    process.env.OPENCLAW_QA_PARENT_PID = String(process.pid);
    // The existing factory uses this supported lifetime flag only; no auth override.
    oldPromise = factory.a(options()); oldPromise.catch(()=>{});
    await started; await attachNative(first);
    if (!oldEntry) {
      const entries=[...globalThis[STATE].clients.entries()];
      need(entries.length===1&&entries[0][1].client===first.client,'original_factory_shared_entry');
      oldKey=entries[0][0];oldEntry=entries[0][1];
    }
    report.sharedKeySha256=hash(oldKey);
    if (!n.scenario.startsWith('pending-')) {
      need(await oldPromise===first.client,'old_actual_factory_lease');
      first.lease=true;await account(first,'old-before-import');
      need(oldEntry.activeLeases===1&&oldEntry.pendingAcquires===0,'old_real_active_lease_counts');
    } else need(oldEntry.activeLeases===0&&oldEntry.pendingAcquires===1&&!first.client.initialized,
      'old_real_pending_initialize_counts');
    checkpoint('before_actual_managed_import');
    event('old_factory_boundary',{activeLeases:oldEntry.activeLeases,pendingAcquires:oldEntry.pendingAcquires,
      initialized:first.client.initialized,writerAlive:living(first.native)});
  }
  async function finish(status) {
    checkpoint('after_actual_managed_import');
    report.pluginRuntimeRecycle = status.codexAppServerRecycle ?? null;
    report.earlyRecycler = callbackRetirement;
    report.sharedEntryRemoved = globalThis[STATE].clients.get(oldKey)!==oldEntry;
    need(report.sharedEntryRemoved&&oldEntry.closeWhenIdle===true,'actual_import_or_early_recycler_removed_old_entry');
    need(living(first.wrapper)&&living(first.native),'old_writer_still_live_after_deferred_retire');
    if(n.scenario!=='pending-before-client')
      need(status.codexAppServerRecycle?.retired===1&&status.codexAppServerRecycle?.deferred===1,
        'actual_plugin_import_deferred_exact_old_client');
    else need(callbackRetirement?.retired===1&&callbackRetirement?.deferred===1,
      'actual_early_recycler_deferred_clientless_startup');
    event('before_concurrent_acquire',{oldActiveLeases:oldEntry.activeLeases,oldPendingAcquires:oldEntry.pendingAcquires,
      oldInitialized:first.client.initialized,oldWriterAlive:living(first.native),
      retirementBarrierPresent:globalThis[STATE].retiring?.has(oldKey)??false});
    newerPromise=factory.a(options()).then(client=>{second.lease=true;newerOutcome={ok:true,client};return client;},
      error=>{newerOutcome={ok:false,code:String(error.message)};throw error;});
    newerPromise.catch(()=>{});
    if(!n.patched) {
      need(await newerPromise===second.client,'baseline_second_actual_factory_ready');
      await attachNative(second);await account(second,'new-while-old-held');
      report.secondFactoryInitialized=true;
      need(living(first.native),'baseline_old_native_still_live_with_second_ready');
      if(n.scenario.startsWith('pending-')) {
        report.secondReadyWhileOriginalStartupPending=!first.client.initialized&&oldEntry.pendingAcquires===1;
        need(report.secondReadyWhileOriginalStartupPending,'baseline_pending_startup_overlap');
        gateReleased=true;gateResolve();
        need(await oldPromise===first.client,'baseline_pending_old_actual_factory_ready');
        first.lease=true;
      }
      await account(first,'old-with-new-ready');
      report.twoReadyLeasesObserved=first.lease&&second.lease&&first.client.initialized&&second.client.initialized
        &&living(first.native)&&living(second.native);
      need(report.twoReadyLeasesObserved,'baseline_two_actual_ready_leases');
      report.singleWriterInvariantPassed=false;
      event('regression_actual_two_ready_leases',{oldNative:first.native.pid,newNative:second.native.pid,
        oldActiveLeases:oldEntry.activeLeases});
      release(first,'old_original_lease_released');
      await waitFor(()=>!living(first.native)&&!living(first.wrapper),5000,'baseline_old_recycler_exit_timeout');
      event('old_actual_writer_and_wrapper_gone_before_cleanup',{nativePid:first.native.pid,wrapperPid:first.wrapper.pid});
    } else {
      await delay(400);
      need(children.length===1&&newerOutcome===undefined,'patched_new_acquire_waits_without_second_spawn');
      const barrier=globalThis[STATE].retiring?.get(oldKey);
      need(barrier&&oldEntry.writerExitBarrier===barrier,'patched_entry_exact_retirement_barrier');
      if(n.scenario.startsWith('pending-')) {
        gateReleased=true;gateResolve();
        need(await oldPromise===first.client,'patched_pending_old_actual_factory_ready');
        first.lease=true;await account(first,'old-after-pending-initialize');
        need(children.length===1&&newerOutcome===undefined,'patched_no_spawn_after_startup_before_release');
      }
      if(n.scenario==='abnormal-wrapper') {
        exactSignal(first.native,'SIGSTOP','fault_native_stop');
        await waitFor(()=>identity(first.native.pid)?.state==='T',1000,'fault_native_stop_not_observed');
        exactSignal(first.wrapper,'SIGKILL','fault_wrapper_kill_only');
        await waitFor(()=>first.client.child.signalCode==='SIGKILL',1000,'fault_wrapper_exit_not_observed');
        need(living(first.native),'fault_native_survives_wrapper_exit');
        release(first,'fault_old_lease_released');
        await waitFor(()=>newerOutcome!==undefined,15000,'fault_acquire_resolution_timeout');
        need(newerOutcome.ok===false&&children.length===1&&globalThis[STATE].retiring.get(oldKey)===barrier,
          'abnormal_wrapper_is_unknown_and_barrier_retained');
        report.singleWriterInvariantPassed=true;
        report.abnormalWrapper={signal:'SIGKILL',nativeStillAlive:living(first.native),newAcquireRejected:true,
          barrierRetained:true,retirementExitConfirmed:false};
        event('abnormal_writer_exit_unknown_fail_closed',{nativeAlive:living(first.native)});
      } else {
        release(first,'old_original_lease_released');
        need(await newerPromise===second.client,'patched_second_actual_factory_ready_after_retire');
        await attachNative(second);
        need(!living(first.wrapper)&&!living(first.native)&&report.secondSpawnPriorNativeAlive===false,
          'patched_actual_writer_gone_before_second_spawn');
        need(first.client.child.exitCode===0&&first.client.child.signalCode===null,
          'patched_normal_wrapper_zero_exit_proven');
        need(!globalThis[STATE].retiring.has(oldKey),'patched_confirmed_barrier_removed');
        await account(second,'new-after-old-exit');
        report.secondFactoryInitialized=true;
        report.singleWriterInvariantPassed=true;
        report.normalRetirement={wrapperExitCode:0,wrapperSignal:null,nativeGone:true,
          factoryBarrierConfirmed:true,harnessCleanupStarted:false};
        event('normal_factory_retirement_confirmed',{oldNativePid:first.native.pid,newNativePid:second.native.pid});
      }
    }
    checkpoint('after_native_retirement_scenario');
    report.evidenceCompleted=true;
    return report;
  }
  async function cleanup() {
    cleanupStarted=true;report.cleanup.attempted=true;event('owned_harness_cleanup_started');
    if(!gateReleased){gateReleased=true;gateResolve();}
    if(first&&n.scenario==='abnormal-wrapper'&&living(first.native)&&identity(first.native.pid)?.state==='T')
      exactSignal(first.native,'SIGCONT','cleanup_native_resume');
    for(const rec of tracked){
      if(rec.lease){try{release(rec,'cleanup_original_lease_release');}catch{}}
      try{factory.s(rec.client);}catch{}
      try{await rec.client.closeAndWait({forceKillDelayMs:1000,exitTimeoutMs:2000});}catch{}
    }
    for(const rec of tracked)for(const saved of [rec.native,rec.wrapper]){
      if(saved&&living(saved)){exactSignal(saved,'SIGTERM','cleanup_exact_owned_sigterm');}
    }
    await delay(100);
    for(const rec of tracked)for(const saved of [rec.native,rec.wrapper]){
      if(saved&&living(saved)){exactSignal(saved,'SIGKILL','cleanup_exact_owned_sigkill');}
    }
    await waitFor(()=>tracked.every(rec=>!living(rec.native)&&!living(rec.wrapper)),3000,'owned_native_cleanup_timeout');
    report.cleanup.everySpawnTracked=children.length===tracked.length;
    report.cleanup.allOwnedStopped=report.cleanup.everySpawnTracked&&tracked.every(rec=>!living(rec.native)&&!living(rec.wrapper));
    report.cleanup.identities=tracked.map(rec=>({ordinal:rec.ordinal,wrapperGone:!living(rec.wrapper),nativeGone:!living(rec.native)}));
    checkpoint('after_owned_cleanup');watcher?.close();
    report.generationsUnchanged=!watchFailure&&report.nativeCheckpoints.every(x=>x.exact);
    need(report.cleanup.allOwnedStopped&&report.generationsUnchanged,'native_owned_cleanup_and_generation');
    return report;
  }
  startWatcher();
  return {begin,finish,cleanup,report};
}
