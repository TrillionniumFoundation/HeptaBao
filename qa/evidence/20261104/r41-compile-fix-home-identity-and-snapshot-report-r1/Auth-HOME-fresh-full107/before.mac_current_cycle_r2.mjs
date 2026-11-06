#!/usr/bin/env node
/** One Mac AuthBus cycle over five actual stores, or its exact once inverse.
 * Preserve original flags, profile3, order/usage and trnm's inherited state.
 * Native consumers run in separate one-factory workers under the same phase
 * owner. Effective state is derived evidence and is never a rollback write.
 */
import fs from 'node:fs';
import { captureAuthRows, restoreAuthRowsWithCas, authRowsDigest } from './mac_auth_rows_cas_r1.mjs';
import { captureAuthBusCaches, cacheContentDigest, restoreAuthBusCachesWithCas } from './mac_authbus_cache_cas_r1.mjs';
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
const report = { schema: 'heptabao.mac-five-agent-authbus-cycle-and-inverse.r1', ok: false,
  productionChanged: false, productionTrafficCutover: false, providerNetworkEgress: false,
  refreshNetworkEgress: false, modelCalled: false, j3160Contacted: false,
  nativeBackendAttemptsNotCounted: true, providerAvailabilityQualified: false,
  credentialValuesPublished: false, accountIdentitiesPublished: false,
  allAccountsQualified: false, checks: [], wire: [] };
let service, baoAgent, plan, sdkRuntime, storeRuntime, baselineDoc;
let serviceStopAttempted = false, serviceStopped = true;
let inverseMutationAttempted = false, inverseCompleted = false;
const workerStarted = process.hrtime.bigint();
let workerUntil;
function remainingMs(cap) {
  const left=Number((workerUntil-process.hrtime.bigint())/1000000n);
  need(left>0,'shared_phase_allocation_exhausted');
  return Math.min(cap,left);
}
async function stopServiceOnce() {
  need(service && !serviceStopAttempted,'service_stop_once');
  serviceStopAttempted=true;
  await service.stop(); serviceStopped=true; service=null;
}
const agentIds = ['main','trnm','hepta-ui','hepta','hepta-backend'];
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

try {
  plan = JSON.parse(privateRead(process.argv[2]));
  const ROOT='/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-4e808-current-owner-bind-r1';
  need(plan.schema==='heptabao.mac-five-agent-worker.private.r1'
    && ['cycle','rollback'].includes(plan.mode) && ['initial','cold-new-process'].includes(plan.phase),
    'fixed_cycle_or_inverse_phase');
  need(plan.workRoot===ROOT && plan.phaseRoot===path.join(ROOT,plan.phase)
    && plan.stateRoot===path.join(plan.phaseRoot,'state')
    && fs.realpathSync(plan.stateRoot)===plan.stateRoot,'fixed_owned_five_agent_state');
  need(Number.isSafeInteger(plan.phaseRemainingMs) && plan.phaseRemainingMs>0
    && plan.phaseRemainingMs<=120000 && plan.phaseOwnerPid===process.ppid,
    'real_phase_owner_and_shared_remaining_allocation');
  workerUntil=workerStarted+BigInt(plan.phaseRemainingMs)*1000000n;
  report.mode=plan.mode;report.phase=plan.phase;
  report.phaseOwnerAbsoluteDeadlineAuthoritative=true;
  report.allocatedRemainingMs=plan.phaseRemainingMs;
  check('scoped_application_roots',process.env.OPENCLAW_STATE_DIR===plan.stateRoot
    && process.env.OPENCLAW_CONFIG_PATH===path.join(plan.stateRoot,'openclaw.json')
    && process.env.OPENCLAW_OAUTH_DIR===path.join(plan.stateRoot,'oauth'));
  for(const key of ['baselineOutput','candidateOutput','custodyOutput','rollbackOnce'])
    need(within(plan.phaseRoot,plan[key]),'private_phase_output_scope.'+key);
  need(within(ROOT,plan.pluginEntry),'owned_plugin_copy_scope');
  const cfg=JSON.parse(privateRead(path.join(plan.stateRoot,'openclaw.json')));
  check('all_five_actual_configured_agents',digest(cfg.agents.list.map(x=>x.id))===digest(agentIds));
  const agentDir=path.join(plan.stateRoot,'agents/main/agent');
  const target=new URL(plan.pluginConfig.address);
  check('one_owned_loopback_https',target.protocol==='https:' && target.hostname==='127.0.0.1' && !!target.port);
  const withoutConnection=value=>Object.fromEntries(Object.entries(value).filter(([key])=>
    !['address','caFile','roleIdFile','secretIdFile'].includes(key)));
  check('complete_original_authbus_flags_preserved',digest(withoutConnection(plan.pluginConfig))
    ===digest(withoutConnection(plan.originalPluginConfig)));
  check('actual_mac_publish_and_order_flags',plan.pluginConfig.hostId==='mac'
    && plan.pluginConfig.leader===false && plan.pluginConfig.publishNew===true
    && plan.pluginConfig.manageOrder===true);
  check('owned_config_only_connection_difference',digest(cfg.plugins.entries['openclaw-authbus'].config)
    ===digest(plan.pluginConfig));
  for(const [file,pin]of Object.entries(plan.sourcePins))
    check('source.'+path.basename(file),hash(fs.readFileSync(file))===pin);
  const originalHttpsRequest=https.request;
  const originalExecFileSync=childProcess.execFileSync;
  for(const method of ['log','warn','error','info','debug'])console[method]=()=>{};
  globalThis.fetch=deny;http.request=deny;http.get=deny;https.get=deny;
  for(const method of ['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork'])
    childProcess[method]=deny;
  childProcess.execFileSync=(file,args,options)=>{
    if(file!=='mount'||!Array.isArray(args)||args.length||options!==undefined)return deny();
    const s=fs.lstatSync('/sbin/mount');
    need(process.platform==='darwin'&&s.isFile()&&s.uid===0&&(s.mode&0o022)===0,'trusted_mount_tool');
    return originalExecFileSync('/sbin/mount',[],{timeout:remainingMs(3000),maxBuffer:262144,
      stdio:['ignore','pipe','pipe'],env:{PATH:'/usr/bin:/bin:/usr/sbin:/sbin'}});
  };
  baoAgent=new https.Agent({keepAlive:false,maxCachedSessions:0});
  https.request=(options,callback)=>{
    need(plan.mode==='cycle','inverse_has_no_network');
    need(options&&typeof options==='object'&&!(options instanceof URL),'https_shape');
    need((options.hostname||options.host)===target.hostname
      &&String(options.port||443)===target.port&&options.rejectUnauthorized===true,'https_endpoint_or_trust');
    const route=options.path;
    const allowed=options.method==='POST'&&route==='/v1/auth/approle/login'
      ||options.method==='GET'&&route.startsWith('/v1/openclaw-auth/data/')
      ||options.method==='POST'&&route.startsWith('/v1/openclaw-auth/data/inbox/'+plan.pluginConfig.hostId+'/');
    need(allowed,'https_operation_scope');
    remainingMs(1);
    const item={method:options.method,path:route,dispatched:true,complete:false};
    report.wire.push(item);
    const req=originalHttpsRequest({...options,agent:baoAgent},response=>{
      item.status=response.statusCode;item.tlsVerified=response.socket.authorized===true;
      const cert=response.socket.getPeerCertificate?.();item.peerSha256=cert?.raw?hash(cert.raw):null;
      need(item.tlsVerified&&item.peerSha256===plan.serverCertificateSha256,'https_peer_pin');
      let size=0;const chunks=[];
      response.on('data',part=>{size+=part.length;if(size<=1048576)chunks.push(part);});
      response.on('aborted',()=>{item.aborted=true;});
      response.on('error',()=>{item.responseError=true;});
      response.on('end',()=>{
        item.complete=response.complete===true&&size<=1048576;
        item.responseBytes=size;
        if(!item.complete)return;
        if(route==='/v1/auth/approle/login'){
          try{
            const value=JSON.parse(Buffer.concat(chunks));
            if(response.statusCode===200&&typeof value.auth?.client_token==='string'){
              tokens.push(value.auth.client_token);sensitive.push(value.auth.client_token);
            }else item.complete=false;
          }catch{item.complete=false;}
        }
      });
      callback(response);
    });
    req.on('error',()=>{item.requestError=true;});
    return req;
  };
  syncBuiltinESMExports();
  const rawBefore=Object.fromEntries(agentIds.map(id=>[id,captureAuthRows(plan.stateRoot,id)]));
  const cachesBefore=captureAuthBusCaches(plan.stateRoot);
  const sdk=await import(pathToFileURL(path.join(plan.sdkRoot,'dist/plugin-sdk/agent-runtime.js')));
  const storeApi=await import(pathToFileURL(path.join(plan.sdkRoot,'dist/store-DH33UrUj.js')));
  sdkRuntime=sdk;storeRuntime=storeApi;
  const orderApi=await import(pathToFileURL(path.join(plan.sdkRoot,'dist/order-CeBlX0NH.js')));
  check('sdk_default_scope',path.resolve(sdk.resolveDefaultAgentDir({}))===agentDir);
  const currentStores=()=>{
    sdk.clearRuntimeAuthProfileStoreSnapshots();
    return Object.fromEntries(agentIds.map(id=>[id,sdk.loadAuthProfileStoreWithoutExternalProfiles(
      path.join(plan.stateRoot,'agents',id,'agent'),{allowKeychainPrompt:false})]));
  };
  const localStores=async()=>{
    const result={};
    for(const id of agentIds){
      let observed;
      const value=await storeApi.m({agentDir:path.join(plan.stateRoot,'agents',id,'agent'),updater:store=>{
        observed=structuredClone(store);return false;
      }});
      check('actual_sdk_local_observation.'+id,value!==null&&observed!==undefined&&digest(value)===digest(observed));
      result[id]=observed;
    }
    return result;
  };
  const allCurrent=currentStores(),allLocal=await localStores();
  for(const id of agentIds){
    check('read_only_sdk_observation_preserved_raw.'+id,
      authRowsDigest(captureAuthRows(plan.stateRoot,id))===authRowsDigest(rawBefore[id]));
    for(const [profile,cred]of Object.entries(allCurrent[id].profiles)){
      sensitive.push(profile);sensitive.push(...secrets(cred));
    }
  }
  if(plan.mode==='rollback'){
    // Durable create-only consumption precedes every mutation and every CAS.
    // A conflict consumes this operation; no later worker may retry it.
    save(plan.rollbackOnce,{schema:'heptabao.mac-inverse-once.r1',phase:plan.phase,
      pid:process.pid,baselineSha256:hash(privateRead(plan.baselineOutput)),
      candidateSha256:hash(privateRead(plan.candidateOutput))});
    baselineDoc=JSON.parse(privateRead(plan.baselineOutput));
    const candidate=JSON.parse(privateRead(plan.candidateOutput));
    check('five_agent_baseline_and_candidate_scope',
      digest(Object.keys(baselineDoc.stores).sort())===digest([...agentIds].sort())
      &&digest(Object.keys(candidate.stores).sort())===digest([...agentIds].sort()));
    check('inverse_complete_six_cache_candidate',digest(cachesBefore)===digest(candidate.authbusCaches));
    for(const id of agentIds){
      check('inverse_effective_read_candidate.'+id,digest(allCurrent[id])===digest(candidate.stores[id]));
      check('inverse_local_write_candidate.'+id,digest(allLocal[id])===digest(candidate.localStores[id]));
      check('inverse_raw_candidate.'+id,authRowsDigest(rawBefore[id])===authRowsDigest(candidate.authRows[id]));
    }
    inverseMutationAttempted=true;
    for(const id of agentIds){
      let applied=false;
      const value=await storeApi.m({agentDir:path.join(plan.stateRoot,'agents',id,'agent'),updater:store=>{
        if(digest(store)!==digest(candidate.localStores[id]))return false;
        for(const key of Object.keys(store))delete store[key];
        // ONLY the actually captured local store is written. Derived effective
        // inheritance is never a write input, including trnm's empty primary.
        Object.assign(store,structuredClone(baselineDoc.localStores[id]));applied=true;return true;
      }});
      check('installed_sdk_local_cas_inverse.'+id,value!==null&&applied);
    }
    const postSdkRows=Object.fromEntries(agentIds.map(id=>[id,captureAuthRows(plan.stateRoot,id)]));
    for(const id of agentIds)check('original_raw_rows_and_stamps_inverse.'+id,
      restoreAuthRowsWithCas(plan.stateRoot,id,postSdkRows[id],baselineDoc.authRows[id]));
    // Recompute effective stores ONLY after every real local/raw row is back.
    const restored=currentStores(),restoredLocal=await localStores();
    for(const id of agentIds){
      check('restored_local_exact.'+id,digest(restoredLocal[id])===digest(baselineDoc.localStores[id]));
      check('derived_effective_recomputed_exact.'+id,digest(restored[id])===digest(baselineDoc.stores[id]));
      check('restored_raw_still_exact_after_reads.'+id,
        authRowsDigest(captureAuthRows(plan.stateRoot,id))===authRowsDigest(baselineDoc.authRows[id]));
    }
    check('six_cache_exact_candidate_cas_inverse',
      restoreAuthBusCachesWithCas(plan.stateRoot,candidate.authbusCaches,baselineDoc.authbusCaches));
    check('six_original_cache_bytes_modes_absences',
      cacheContentDigest(captureAuthBusCaches(plan.stateRoot))===cacheContentDigest(baselineDoc.authbusCaches));
    inverseCompleted=true;
    report.inverseWritesOnlyLocalAndRaw=true;
    report.effectiveStoresOnlyRecomputedAndVerified=true;
    report.rollbackAttemptedOnce=true;report.rollbackRetried=false;
  }else{
    baselineDoc={schema:'heptabao.mac-five-agent-baseline.private.r1',
      stores:allCurrent,localStores:allLocal,authRows:rawBefore,authbusCaches:cachesBefore,phase:plan.phase};
    check('six_original_cache_bytes_materialized',
      cacheContentDigest(cachesBefore)===plan.originalCacheContentSha256);
    for(const id of agentIds)check('actual_captured_primary_rows_materialized.'+id,
      authRowsDigest(rawBefore[id])===plan.originalAuthRowsDigestByAgent[id]);
    save(plan.baselineOutput,baselineDoc);
    check('two_managed_same_identity_generations',Array.isArray(plan.managedProfiles)
      &&plan.managedProfiles.length===2&&new Set(plan.managedProfiles.map(x=>x.profileId)).size===2);
    const managedIds=new Set(plan.managedProfiles.map(x=>x.profileId));
    const identity=cred=>({provider:cred?.provider,type:cred?.type,accountId:cred?.accountId,email:cred?.email});
    for(const id of agentIds)for(const [index,item]of plan.managedProfiles.entries())
      check('current_managed_identity_match.'+id+'.'+(index+1),
        Object.hasOwn(allCurrent[id].profiles,item.profileId)
        &&digest(identity(allCurrent[id].profiles[item.profileId]))===item.identityDigest);
    check('original_trnm_local_profile_free',Object.keys(allLocal.trnm.profiles).length===0);
    const plugin=(await import(pathToFileURL(plan.pluginEntry))).default;
    check('actual_installed_plugin_export',plugin?.id==='openclaw-authbus'&&typeof plugin.register==='function');
    let subscriptions=0;
    plugin.register({registrationMode:'full',pluginConfig:plan.pluginConfig,
      agent:{events:{registerAgentEventSubscription(){subscriptions++;}}},
      registerService(value){need(!service,'single_authbus_service');service=value;}});
    check('actual_one_service_registered',subscriptions===1&&service?.id==='openclaw-authbus');
    const logs={info:0,warn:0,error:0,debug:0};
    const logger=Object.fromEntries(Object.keys(logs).map(k=>[k,()=>{logs[k]++;}]));
    serviceStopped=false;
    await service.start({stateDir:plan.stateRoot,logger,config:cfg});
    await stopServiceOnce();
    const status=JSON.parse(privateRead(path.join(plan.stateRoot,'authbus/status.json')));
    report.plugin=Object.fromEntries(['ok','manifestProfiles','importedProfiles','agentStores','verifiedStores',
      'effectiveMissing','effectiveMismatched','changedOrders','verifiedOrderBindings','schedulerMode',
      'schedulerReports','pendingRuntimeRefreshes','publishedEvents'].map(k=>[k,status[k]??null]));
    report.plugin.logCounts=logs;
    if(status.error)report.plugin.errorSha256=hash(String(status.error));
    check('actual_complete_authbus_cycle',status.ok===true);
    check('shared_manifest_remains_two',status.manifestProfiles===2);
    const allAfter=currentStores();
    report.agentEffects=[];
    const withoutProfiles=store=>Object.fromEntries(Object.entries(store).filter(([key])=>key!=='profiles'));
    for(const id of agentIds){
      const before=baselineDoc.stores[id],after=allAfter[id];
      check('all_current_profile_ids_retained.'+id,
        digest(Object.keys(after.profiles).sort())===digest(Object.keys(before.profiles).sort()));
      check('all_unmanaged_credentials_retained.'+id,
        Object.entries(before.profiles).filter(([key])=>!managedIds.has(key))
          .every(([key,value])=>digest(after.profiles[key])===digest(value)));
      check('two_exact_managed_generations_imported.'+id,
        plan.managedProfiles.every(item=>digest(after.profiles[item.profileId])===item.credentialSha256));
      check('whole_noncredential_state_preserved.'+id,digest(withoutProfiles(after))===digest(withoutProfiles(before)));
      const order=orderApi.i({cfg,store:structuredClone(after),provider:plan.model.provider});
      const originalOrder=orderApi.i({cfg,store:structuredClone(before),provider:plan.model.provider});
      // Current selection is observed without quotas/cooldowns/exclusions reset.
      // Candidate eligibility can follow real credential expiry; persistent
      // configured order/usage are covered by the full noncredential check.
      report.agentEffects.push({agentId:id,profileCount:Object.keys(after.profiles).length,
        managedCredentialChanged:plan.managedProfiles.some(item=>
          digest(after.profiles[item.profileId])!==digest(before.profiles[item.profileId])),
        rawRowsChanged:authRowsDigest(captureAuthRows(plan.stateRoot,id))!==authRowsDigest(rawBefore[id]),
        actualOrderCount:order.length,earlierOrderCount:originalOrder.length,
        actualOrderOrdinals:order.map(key=>Object.keys(after.profiles).indexOf(key)+1)});
    }
    check('trnm_profile_free_raw_representation_not_materialized',
      authRowsDigest(captureAuthRows(plan.stateRoot,'trnm'))===authRowsDigest(rawBefore.trnm));
    check('actual_approle_login_and_manifest_tls',tokens.length===1&&report.wire.some(x=>
      x.method==='GET'&&x.path==='/v1/openclaw-auth/data/manifest'&&x.status===200&&x.complete));
    const applied=cachesBefore.files['applied-profiles.json'].present
      ?JSON.parse(Buffer.from(cachesBefore.files['applied-profiles.json'].base64,'base64')).profiles??{}:{};
    report.managedReadEffects=plan.managedProfiles.map((item,index)=>{
      const read=report.wire.some(x=>x.method==='GET'
        &&x.path==='/v1/openclaw-auth/data/profiles/'+item.key&&x.status===200&&x.complete);
      const preapplied=applied[item.profileId]===item.credentialSha256
        &&agentIds.every(id=>digest(baselineDoc.stores[id].profiles[item.profileId])===item.credentialSha256);
      check('managed_generation_read_or_already_exact.'+(index+1),read||preapplied);
      return {ordinal:index+1,actualTlsRead:read,previouslyExactInAllFive:preapplied};
    });
    report.publishNewFlagPreserved=plan.pluginConfig.publishNew===plan.originalPluginConfig.publishNew;
    report.inboxPostCountObserved=report.wire.filter(x=>x.method==='POST'
      &&x.path.startsWith('/v1/openclaw-auth/data/inbox/')).length;
    report.workerManifestWriteRouteAllowed=false;
    report.nativeFactoryExecutedInThisWorker=false;
  }
  check('no_unexpected_network_or_process_operations',blockedOperations===0);
  check('all_dispatched_http_responses_complete',report.wire.every(x=>x.complete&&!x.aborted&&!x.responseError&&!x.requestError));
  check('source_pins_unchanged',Object.entries(plan.sourcePins).every(([file,pin])=>hash(fs.readFileSync(file))===pin));
  check('no_public_credential_values',sensitive.every(value=>!JSON.stringify(report).includes(value)));
  remainingMs(1);report.ok=true;
}catch(error){
  report.error=error?.safeCode??'mac_five_agent_cycle_failed';
  report.errorClass=error?.constructor?.name??'unknown';
  report.errorCodeSha256=hash(String(error?.message??error));
  report.sourceFrame=String(error?.stack??'').split('\n').slice(1,5)
    .map(line=>line.match(/([A-Za-z0-9_.-]+\.(?:js|mjs)):(\d+):(\d+)/)?.slice(1)??['worker']);
}finally{
  if(service&&!serviceStopAttempted){
    try{await stopServiceOnce();}catch{serviceStopped=false;}
  }
  report.serviceStopped=serviceStopped;
  report.inverseMutationAttempted=inverseMutationAttempted;
  report.inverseCompleted=inverseCompleted;
  report.outcomeUnknown=report.wire.some(x=>!x.complete||x.aborted||x.responseError||x.requestError)
    ||!serviceStopped||(inverseMutationAttempted&&!inverseCompleted);
  if(report.outcomeUnknown)report.ok=false;
  baoAgent?.destroy();
  if(plan?.mode==='cycle'&&baselineDoc&&sdkRuntime&&serviceStopped){
    try{
      sdkRuntime.clearRuntimeAuthProfileStoreSnapshots();
      const stores=Object.fromEntries(agentIds.map(id=>[id,sdkRuntime.loadAuthProfileStoreWithoutExternalProfiles(
        path.join(plan.stateRoot,'agents',id,'agent'),{allowKeychainPrompt:false})]));
      const localStores={};
      for(const id of agentIds){
        let observed;const value=await storeRuntime.m({agentDir:path.join(plan.stateRoot,'agents',id,'agent'),
          updater:store=>{observed=structuredClone(store);return false;}});
        need(value!==null&&observed!==undefined&&digest(value)===digest(observed),'candidate_local_capture');
        localStores[id]=observed;
      }
      const authRows=Object.fromEntries(agentIds.map(id=>[id,captureAuthRows(plan.stateRoot,id)]));
      const authbusCaches=captureAuthBusCaches(plan.stateRoot);
      save(plan.candidateOutput,{schema:'heptabao.mac-five-agent-candidate.private.r1',phase:plan.phase,
        stores,localStores,authRows,authbusCaches});
      report.candidateRecorded=true;
    }catch(error){report.candidateRecorded=false;report.ok=false;
      report.candidateErrorSha256=hash(String(error?.message??error));}
  }
  try{if(plan)save(plan.custodyOutput,{tokens});}catch{report.ok=false;}
}
if(sensitive.some(value=>JSON.stringify(report).includes(value))){
  for(const key of Object.keys(report))delete report[key];
  Object.assign(report,{schema:'heptabao.mac-five-agent-authbus-cycle-and-inverse.r1',
    ok:false,error:'public_projection_contains_sensitive_value'});
}
process.stdout.write(JSON.stringify(report)+'\n');
process.exitCode=report.ok?0:1;
