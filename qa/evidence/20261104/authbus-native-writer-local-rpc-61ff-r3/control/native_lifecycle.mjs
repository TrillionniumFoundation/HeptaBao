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
async function untilDeadline(promise, deadline, code) {
  const remaining = deadline - Number(process.hrtime.bigint() / 1000000n);
  need(remaining > 0, code);
  let timer;
  try {
    return await Promise.race([promise, new Promise((_, reject) => {
      timer = setTimeout(() => reject(Object.assign(new Error(code), {safeCode:code})), remaining);
    })]);
  } finally { clearTimeout(timer); }
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

export async function createNativeLifecycle({ plan, cfg, agentDir, before, childProcess, originalSpawn, check, sensitive, journal }) {
  const n = plan.native;
  need(n && ['active-lease','pending-initialize','pending-before-client','abnormal-wrapper'].includes(n.scenario),
    'native_scenario_scope');
  const report = { schema:'heptabao.actual-native-shared-factory-retirement-local-rpc.v2',
    scenario:n.scenario, patchedExpected:n.patched, actualFactory:true,
    readinessProbe:{method:'thread/loaded/list',params:{limit:1},timeoutMs:8000,
      meaning:'initialized_native_rpc_channel_in_same_writable_credentials_directory',
      provesAccountIdentity:false,provesProviderAvailability:false},
    nativeAccountReadQualified:false,accountReadAttempted:false,
    preservedAccountReadFailure:{job:'1a1a7e670f5-fc05-2cd4',timeoutMs:8000,
      coreSha256:'7d81725c63acda7c8da77107f8fe4dfc0766f4a97980fc8860a4e16be5fb65fb'},
    credentialOverwriteObserved:false,credentialMutationExercised:false,
    twoInitializedNativeRpcChannelsObserved:false,
    providerCalled:false, modelCalled:false, explicitRefreshRpcSent:false, externalTokenLoginSent:false,
    productionGatewaySelectionQualified:false, backgroundNetworkAttemptsNotMeasured:true,
    externalNetworkKernelDenied:true, commandChanged:false, modelConfigurationChanged:false,
    nativeSourceAdoptedByAuthBus:false, events:[], nativeCheckpoints:[], rpc:[],
    serverRequestsRefused:[], transports:[], generationsUnchanged:true,
    sharedEntryRemoved:false, secondProcessSpawned:false, secondFactoryInitialized:false,
    twoReadyLeasesObserved:false, singleWriterInvariantPassed:null,
    harnessCleanupUsedAsRetirementProof:false, cleanup:{ attempted:false, allOwnedStopped:false } };
  const clock = () => Number(process.hrtime.bigint() / 1000000n);
  function event(kind, detail={}) {
    const record = {sequence:report.events.length + 1,monotonicMs:clock(),kind,...detail};
    report.events.push(record); journal('native_event', {event:record});
  }
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
  event('before_original_factory_import');
  const factory = await import(pathToFileURL(n.factoryEntry));
  event('after_original_factory_import');
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
  const tracked = [], children = [], ownedSpawns = [], acquires = [], sharedStartups = [];
  let sharedEntryCaptureFailed = false;
  const lifecycleAbort = new AbortController();
  let callbackRetirement = null, cleanupStarted = false, closed = false;
  function acquire(label) {
    const state = {label,settled:false,client:null,released:false,promise:null,sharedStartup:null,
      initialBarrier:n.patched&&label==='new'?globalThis[STATE]?.retiring?.get(oldKey):null};
    acquires.push(state);
    let promise;
    try { promise = factory.a(options()); } catch (error) { promise = Promise.reject(error); }
    state.promise = promise;
    promise.then(client => {
      state.settled = true; state.client = client;
      if (closed) {
        state.released = factory.o(client) === true;
        event('late_owned_lease_released_after_close',{label,released:state.released});
        try { factory.s(client); } catch {}
      }
    }, error => {
      state.settled = true;
      const stage = label + (tracked.some(r => r.ordinal === (label === 'old' ? 1 : 2))
        ? '.acquire.after_onStarted' : '.acquire.before_onStarted');
      const errorClass = ['Error','TypeError','RangeError','SyntaxError','AbortError'].includes(error?.name)
        ? error.name : 'unknown';
      let privateReasonSha256 = null;
      try { privateReasonSha256 = savePrivate(path.join(n.outputDir,label+'-factory-rejection.private.json'),
        {stage,name:String(error?.name??''),message:String(error?.message??error),stack:String(error?.stack??''),
         code:String(error?.code??''),safeCode:String(error?.safeCode??'')}); } catch {}
      report.acquireFailures ??= []; report.acquireFailures.push({stage,errorClass,privateReasonSha256});
      event('actual_factory_acquire_rejected',{stage,errorClass,privateReasonSha256});
    }).catch(() => {});
    promise.catch(() => {}); return promise;
  }
  function captureSharedPromise(record) {
    const promise=record.entry.promise;
    if(!promise)return;
    if(record.promise&&record.promise!==promise){record.replaced=true;return;}
    if(record.promise)return;
    if(typeof promise.then!=='function'){record.observationFailed=true;return;}
    record.promise=promise;
    event('actual_shared_startup_promise_captured',{ordinal:record.ordinal,entryKeySha256:record.keySha256});
    const settled=outcome=>{
      record.settled=true;record.outcome=outcome;
      event('actual_shared_startup_settled',{ordinal:record.ordinal,outcome});
    };
    promise.then(()=>settled('fulfilled'),()=>settled('rejected')).catch(()=>{record.observationFailed=true;});
  }
  function sharedStartupBeforeActualSpawn() {
    const state=globalThis[STATE], pairs=state?.clients instanceof Map?[...state.clients.entries()]:[];
    const valid=pairs.length===1&&pairs[0][1]?.client===undefined
      &&pairs[0][1]?.pendingAcquires===1;
    if(!valid)sharedEntryCaptureFailed=true;
    need(valid,'exact_actual_spawn_shared_entry');
    const [key,entry]=pairs[0], owner=acquires.find(a=>!a.sharedStartup&&!a.settled);
    if(!owner)sharedEntryCaptureFailed=true;
    need(owner,'exact_actual_spawn_acquire_owner');
    let record=sharedStartups.find(r=>r.entry===entry);
    if(!record){record={ordinal:sharedStartups.length+1,entry,keySha256:hash(key),
      promise:null,settled:false,replaced:false,observationFailed:false,outcome:null};
      sharedStartups.push(record);}
    owner.sharedStartup=record;
    captureSharedPromise(record);
    // Original factory assigns entry.promise after its synchronous spawn stack.
    // Keep the exact object even if the callback retires it before that write.
    queueMicrotask(()=>{try{captureSharedPromise(record);}catch{record.observationFailed=true;}});
    event('actual_shared_entry_retained_before_spawn',{ordinal:record.ordinal,
      entryKeySha256:record.keySha256,promiseAlreadyPublished:record.promise!==null});
    return record;
  }
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
    need(!closed && !cleanupStarted, 'native_spawn_after_lifecycle_close_refused');
    const predicates = {commandExact:command===n.command,argsExact:JSON.stringify(args)===JSON.stringify(runtime.args),
      // The pinned Linux direct adapter preserves shell: undefined; it never selects a shell.
      shellExactlyUndefined:options?.shell===undefined,detachedFalse:options?.detached===false,
      homeExact:options?.env?.HOME===n.home,codexHomeExact:options?.env?.CODEX_HOME===n.nativeHome,
      noOpenaiApiKey:!options?.env?.OPENAI_API_KEY,noCodexApiKey:!options?.env?.CODEX_API_KEY};
    event('original_spawn_predicates',predicates);
    need(Object.values(predicates).every(value=>value===true),'only_exact_original_native_spawn');
    need(children.length < 2, 'bounded_two_actual_native_starts');
    checkpoint('before_spawn_' + (children.length + 1));
    const priorNativeAlive = tracked.some(x => x.native && living(x.native));
    event('native_wrapper_spawn_requested', {ordinal:children.length + 1,priorNativeAlive,
      priorWrapperAlive:tracked.some(x => x.wrapper && living(x.wrapper))});
    // Observe the original decision; an unsafe second spawn is not blocked here.
    const sharedStartup=sharedStartupBeforeActualSpawn();
    const child = originalSpawn(command, args, options); children.push(child);
    // Register the actual child before any onStarted assertion can fail.
    const owned = {child,ordinal:children.length,initialWrapper:identity(child.pid),native:null,sharedStartup};
    ownedSpawns.push(owned);
    event('actual_wrapper_spawn_returned',{ordinal:owned.ordinal,pid:child.pid??null,
      initialWrapper:owned.initialWrapper});
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
      else need(method === 'thread/loaded/list' && digest(params) === digest({limit:1}),
        'only_local_loaded_thread_list_after_initialize');
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
  async function attachNative(rec, deadline) {
    rec.native = await waitFor(() => nativeFor(rec.wrapper.pid),Math.min(5000, Math.max(1, (deadline ?? clock()+5000)-clock())),'real_native_child_identity_timeout');
    ownedSpawns.find(own=>own.child===rec.client.child).native = rec.native;
    need(rec.native.pgid === process.pid && rec.wrapper.pgid === process.pid,
      'qa_original_transport_owned_process_group');
    report.transports.push({ordinal:rec.ordinal,wrapper:rec.wrapper,native:rec.native});
    event('native_writer_identity',{ordinal:rec.ordinal,native:rec.native});
  }
  async function localRpc(rec, label) {
    need(rec.client.initialized && rec.client.getServerVersion() === '0.159.2'
      && rec.client.getRuntimeIdentity()?.codexHome === n.nativeHome, 'actual_native_version_and_home');
    const response = await rec.client.request('thread/loaded/list',{limit:1},{timeoutMs:8000});
    const bytesHash = savePrivate(path.join(n.outputDir,label+'.loaded-threads.private.json'),response);
    need(response && Array.isArray(response.data) && response.data.length === 0
      && response.nextCursor === null, 'actual_native_fresh_home_loaded_threads_empty');
    rec.localRpcCompleted = true;
    checkpoint('after_local_rpc_' + label);
    event('actual_local_loaded_threads_read',{ordinal:rec.ordinal,responseSha256:bytesHash,
      loadedThreadCount:0,nextCursorNull:true,provesAccountIdentity:false});
  }
  function release(rec, label) {
    need(rec.lease && factory.o(rec.client) === true, 'original_factory_lease_release');
    rec.lease = false;
    const acquired = acquires.find(a=>a.client===rec.client&&!a.released);
    need(acquired,'owned_lease_release_record'); acquired.released = true;
    event(label,{ordinal:rec.ordinal});
  }
  const options = () => ({agentDir,config:cfg,startOptions:runtime,timeoutMs:15000,
    abandonSignal:lifecycleAbort.signal,onStartedClient:observe});
  async function begin() {
    process.env.OPENCLAW_QA_PARENT_PID = String(process.pid);
    // The existing factory uses this supported lifetime flag only; no auth override.
    const deadline = clock()+15000;
    event('old_acquire_started',{absoluteDeadlineMonotonicMs:deadline});
    oldPromise = acquire('old');
    const beforeStartedFailure = oldPromise.then(() => {
      need(first,'factory_completed_without_onStarted'); return first;
    });
    beforeStartedFailure.catch(()=>{});
    await untilDeadline(Promise.race([started,beforeStartedFailure]),deadline,'old_factory_before_onStarted_timeout');
    await attachNative(first,deadline);
    if (!oldEntry) {
      const entries=[...globalThis[STATE].clients.entries()];
      need(entries.length===1&&entries[0][1].client===first.client,'original_factory_shared_entry');
      oldKey=entries[0][0];oldEntry=entries[0][1];
    }
    report.sharedKeySha256=hash(oldKey);
    if (!n.scenario.startsWith('pending-')) {
      need(await untilDeadline(oldPromise,deadline,'old_factory_initialize_timeout')===first.client,'old_actual_factory_lease');
      first.lease=true;await localRpc(first,'old-before-import');
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
    newerPromise=acquire('new').then(client=>{need(!closed,'new_lease_after_lifecycle_close');second.lease=true;newerOutcome={ok:true,client};return client;},
      error=>{newerOutcome={ok:false,code:String(error.message)};throw error;});
    newerPromise.catch(()=>{});
    if(!n.patched) {
      need(await newerPromise===second.client,'baseline_second_actual_factory_ready');
      await attachNative(second);await localRpc(second,'new-while-old-held');
      report.secondFactoryInitialized=true;
      need(living(first.native),'baseline_old_native_still_live_with_second_ready');
      if(n.scenario.startsWith('pending-')) {
        report.secondReadyWhileOriginalStartupPending=!first.client.initialized&&oldEntry.pendingAcquires===1;
        need(report.secondReadyWhileOriginalStartupPending,'baseline_pending_startup_overlap');
        gateReleased=true;gateResolve();
        need(await oldPromise===first.client,'baseline_pending_old_actual_factory_ready');
        first.lease=true;
      }
      await localRpc(first,'old-with-new-ready');
      report.twoReadyLeasesObserved=first.lease&&second.lease&&first.client.initialized&&second.client.initialized
        &&first.localRpcCompleted===true&&second.localRpcCompleted===true
        &&living(first.native)&&living(second.native);
      need(report.twoReadyLeasesObserved,'baseline_two_actual_ready_leases');
      report.twoInitializedNativeRpcChannelsObserved=true;
      report.singleWriterInvariantPassed=false;
      event('regression_two_initialized_native_rpc_channels',{oldNative:first.native.pid,newNative:second.native.pid,
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
        first.lease=true;await localRpc(first,'old-after-pending-initialize');
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
        await localRpc(second,'new-after-old-exit');
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
    cleanupStarted=true;closed=true;report.cleanup.attempted=true;
    const deadline=clock()+5000;
    try {
    lifecycleAbort.abort();event('owned_harness_cleanup_started',{closed:true});
    if(!gateReleased){gateReleased=true;gateResolve();}
    if(first&&n.scenario==='abnormal-wrapper'&&living(first.native)&&identity(first.native.pid)?.state==='T')
      exactSignal(first.native,'SIGCONT','cleanup_native_resume');
    for(const rec of tracked){
      if(rec.lease){try{release(rec,'cleanup_original_lease_release');}catch{}}
      try{factory.s(rec.client);}catch{}
      try{await rec.client.closeAndWait({forceKillDelayMs:1000,exitTimeoutMs:Math.max(1,Math.min(2000,deadline-clock()))});}catch{}
    }
    const ownedIdentities=[];
    for(const own of ownedSpawns) {
      const rec=tracked.find(r=>r.client.child===own.child), current=identity(own.child.pid), initial=own.initialWrapper;
      let wrapper=rec?.wrapper??null;
      // An exact child may exec /usr/bin/env -> the pinned Node wrapper. Keep
      // PID/startTicks/parent/group/session ownership while observing that exec.
      if(!wrapper&&initial&&current&&initial.pid===current.pid&&initial.startTicks===current.startTicks
        &&current.ppid===process.pid&&current.pgid===process.pid&&current.session===process.pid
        &&[n.nodeRealpath,'/usr/bin/env'].includes(current.executable)) wrapper=current;
      let native=rec?.native??own.native;
      if(!native&&wrapper&&living(wrapper))native=nativeFor(wrapper.pid);
      if(native)need(native.pgid===process.pid,'unobserved_native_owned_group');
      own.cleanupWrapper=wrapper;own.native=native;
      if(native)ownedIdentities.push(native);if(wrapper)ownedIdentities.push(wrapper);
    }
    for(const saved of ownedIdentities)if(living(saved))exactSignal(saved,'SIGTERM','cleanup_exact_owned_sigterm');
    await delay(Math.min(100,Math.max(0,deadline-clock())));
    for(const saved of ownedIdentities)if(living(saved))exactSignal(saved,'SIGKILL','cleanup_exact_owned_sigkill');
    for(const record of sharedStartups){try{captureSharedPromise(record);}catch{record.observationFailed=true;}}
    const originals=sharedStartups.filter(r=>r.promise).map(r=>r.promise);
    try{await untilDeadline(Promise.allSettled([...acquires.map(a=>a.promise),...originals]),
      deadline,'owned_acquire_and_shared_startup_settlement_timeout');}catch{}
    try{await waitFor(()=>ownedIdentities.every(saved=>!living(saved)),Math.max(1,deadline-clock()),'owned_native_cleanup_timeout');}catch{}
    report.cleanup.closed=true;report.cleanup.actualSpawnCount=children.length;
    report.cleanup.ownerRegistryCount=ownedSpawns.length;
    report.cleanup.acquirePromisesSettled=acquires.every(a=>a.settled);
    const validStartup=r=>r&&r.promise&&r.settled&&!r.replaced&&!r.observationFailed
      &&r.entry.promise===r.promise;
    report.cleanup.sharedStartupCoverage=acquires.map(a=>{
      const barrierOnly=!a.sharedStartup&&a.initialBarrier&&a.initialBarrier.entry===oldEntry
        &&globalThis[STATE].retiring?.get(oldKey)===a.initialBarrier
        &&a.initialBarrier.confirmed===false&&a.settled&&a.client===null;
      return {label:a.label,originalStartupCaptured:!!a.sharedStartup,
        originalStartupSettled:!!validStartup(a.sharedStartup),retainedBarrierOnly:!!barrierOnly,
        covered:!!validStartup(a.sharedStartup)||!!barrierOnly};
    });
    report.cleanup.startupPromisesSettled=!sharedEntryCaptureFailed
      &&report.cleanup.sharedStartupCoverage.every(x=>x.covered)
      &&sharedStartups.every(validStartup)
      &&ownedSpawns.every(own=>sharedStartups.includes(own.sharedStartup));
    report.cleanup.sharedStartupPromises=sharedStartups.map(r=>({ordinal:r.ordinal,
      entryKeySha256:r.keySha256,promiseCaptured:!!r.promise,settled:r.settled,
      outcome:r.outcome,replaced:r.replaced,observationFailed:r.observationFailed}));
    report.cleanup.allOwnedLeasesReleased=acquires.every(a=>a.client===null||a.released);
    report.cleanup.everySpawnTracked=children.length===tracked.length&&ownedSpawns.length===children.length;
    report.cleanup.allOwnedStopped=report.cleanup.acquirePromisesSettled&&report.cleanup.startupPromisesSettled&&report.cleanup.allOwnedLeasesReleased&&report.cleanup.everySpawnTracked
      &&tracked.every(rec=>rec.wrapper&&rec.native&&!living(rec.native)&&!living(rec.wrapper));
    report.cleanup.identities=ownedSpawns.map(own=>({ordinal:own.ordinal,
      wrapperObserved:!!own.cleanupWrapper,nativeObserved:!!own.native,
      wrapperGone:!!own.cleanupWrapper&&!living(own.cleanupWrapper),
      nativeGone:!!own.native&&!living(own.native),
      exitCode:own.child.exitCode,signalCode:own.child.signalCode}));
    checkpoint('after_owned_cleanup');
    report.generationsUnchanged=!watchFailure&&report.nativeCheckpoints.every(x=>x.exact);
    event('owned_harness_cleanup_completed',{acquirePromisesSettled:report.cleanup.acquirePromisesSettled,
      startupPromisesSettled:report.cleanup.startupPromisesSettled,
      actualSpawnCount:children.length,allOwnedStopped:report.cleanup.allOwnedStopped});
    need(report.cleanup.allOwnedStopped&&report.generationsUnchanged,'native_owned_cleanup_and_generation');
    return report;
    } finally { watcher?.close(); }
  }
  startWatcher();
  return {begin,finish,cleanup,report};
}
