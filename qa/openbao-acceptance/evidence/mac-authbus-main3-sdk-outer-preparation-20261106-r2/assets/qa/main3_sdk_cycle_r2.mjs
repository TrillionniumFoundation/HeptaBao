#!/usr/bin/env node
/** Actual installed AuthBus/SDK over three current OAuth objects in private
 * empty fixture stores. Two new Node processes share one private state root.
 * The second process verifies cold persistence and performs one exact inverse.
 * This is not a production-store snapshot, gateway restart or provider probe.
 */
import fs from 'node:fs';
import path from 'node:path';
import childProcess from 'node:child_process';
import net from 'node:net';
import {createHash} from 'node:crypto';
import {pathToFileURL,fileURLToPath} from 'node:url';
import {createRequire,syncBuiltinESMExports} from 'node:module';
import {installWireFence} from './main3_sdk_wire_r2.mjs';

const ROOT='/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-main3-sdk-20261106-r2';
const STATE=ROOT+'/state',SDK='/opt/homebrew/lib/node_modules/openclaw';
const AGENTS=Object.freeze(['main','trnm','hepta-ui','hepta','hepta-backend']);
const PLUGIN_FILES=Object.freeze(['index.js','package.json','order-policy.js','runtime-refresh-policy.js',
  'codex-client-recycler.js','provider-error-classifier.js','bad-refresh-quarantine.js','lease-assignments.js']);
const WORKER_FILES=Object.freeze(['main3_sdk_cycle_r2.mjs','main3_sdk_wire_r2.mjs',
  'main3_auth_rows_cas_r1.mjs','main3_authbus_cache_cas_r1.mjs']);
const REQUIRED_SDK=Object.freeze(['package.json','dist/plugin-sdk/agent-runtime.js','dist/store-DH33UrUj.js',
  'dist/order-CeBlX0NH.js','dist/profiles-DyU-YCq2.js','dist/sqlite-B1ze-fre.js',
  'dist/openclaw-agent-db-DKpxi-Ll.js','dist/openclaw-state-db-DzSsA9Ji.js','dist/sqlite-wal-Bhk2Ro-u.js']);
const output=process.stdout.write.bind(process.stdout);
const originalDiagnosticWrites={stdout:process.stdout.write,stderr:process.stderr.write};
const originalConsole=Object.fromEntries(['log','warn','error','info','debug'].map(key=>[key,console[key]]));
const started=process.hrtime.bigint();
let until=started,plan,cfg,capsule,wire,sqlGuard,sdk,storeApi,orderApi,stateApi,rowsApi,cachesApi,cacheExit;
let service=null,serviceStopAttempted=false,serviceStopped=true,baseline=null,candidateSaved=false;
let inverseAttempted=false,inverseComplete=false,diagnosticBytes=0,childDenied=0,mountCalls=0;
let privateReadsOpened=0,privateReadsClosed=0,childOriginals=null;
const sensitive=[];
const report={schema:'heptabao.mac-main3-sdk-private-cycle.r2',ok:false,
  sourceOwnerCredentialCount:3,sourceConsumerReferenceCount:15,
  productionChanged:false,productionTrafficCutover:false,productionClientRollbackQualified:false,
  actualGatewayRestarted:false,providerCalled:false,providerRefreshAttempted:false,providerValid:false,
  j3160Contacted:false,credentialValuesOrDigestsPublished:false,profileIdsPublished:false,
  actualCentralOrderPolicyCopied:false,syntheticCanaryControlPolicy:true,
  originalProductionNoncredentialStateCopied:false,sdkTransitiveDependencyClosureClaimed:false,
  checks:[],wire:[],agentObservations:[]};
function need(value,code){if(!value)throw Object.assign(new Error(code),{safeCode:code});}
function check(code,value){need(/^[a-z0-9_.-]{1,120}$/.test(code),'sdk_public_case_name');
  report.checks.push({case:code,passed:value===true});need(value===true,code);}
const stable=v=>Array.isArray(v)?v.map(stable):v&&typeof v==='object'
  ?Object.fromEntries(Object.keys(v).sort().map(key=>[key,stable(v[key])])):v;
const encoded=v=>JSON.stringify(stable(v));
const equal=(a,b)=>encoded(a)===encoded(b);
const hash=raw=>createHash('sha256').update(raw).digest('hex');
const identity=s=>['dev','ino','uid','gid','mode','nlink','size','mtimeNs','ctimeNs'].map(key=>String(s[key]));
function remainingMs(cap){const left=Number((until-process.hrtime.bigint())/1000000n);
  need(left>0,'sdk_original_phase_deadline');return Math.min(cap,left);}
function privateRead(file,maximum=1048576,publicSource=false){
  remainingMs(1);
  const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
  privateReadsOpened++;
  try{
    const before=fs.fstatSync(fd,{bigint:true});
    need(before.isFile()&&before.nlink===1n&&before.size>=0n&&before.size<=BigInt(maximum)&&
      [0n,501n].includes(before.uid)&&(before.mode&18n)===0n,'sdk_bounded_file_custody');
    if(!publicSource)need(before.uid===501n&&(before.mode&511n)===384n,'sdk_private_file_mode');
    const raw=fs.readFileSync(fd);
    need(BigInt(raw.length)===before.size&&equal(identity(before),identity(fs.fstatSync(fd,{bigint:true})))&&
      equal(identity(before),identity(fs.lstatSync(file,{bigint:true}))),'sdk_stable_whole_file');
    remainingMs(1);return raw;
  }finally{fs.closeSync(fd);privateReadsClosed++;}
}
function privateNew(file,value){
  remainingMs(1);const raw=Buffer.from(JSON.stringify(value)+'\n');
  need(raw.length<=4*1048576&&file.startsWith(ROOT+'/'),'sdk_private_output_bound');
  const parent=path.dirname(file),p=fs.lstatSync(parent,{bigint:true});
  need(fs.realpathSync(parent)===parent&&p.isDirectory()&&p.uid===501n&&(p.mode&511n)===448n,
    'sdk_private_output_parent');
  const fd=fs.openSync(file,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
  try{fs.writeFileSync(fd,raw);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
  const directory=fs.openSync(parent,fs.constants.O_RDONLY|fs.constants.O_DIRECTORY|fs.constants.O_NOFOLLOW);
  try{fs.fsyncSync(directory);}finally{fs.closeSync(directory);}
  remainingMs(1);
}
function sourceFence(){
  need(Object.keys(plan.sourcePins).length<=256,'sdk_bounded_public_source_inventory');
  const allowed=p=>WORKER_FILES.some(name=>p===ROOT+'/qa/'+name)||
    PLUGIN_FILES.some(name=>p===ROOT+'/plugin/'+name)||p===SDK+'/package.json'||
    p.startsWith(SDK+'/dist/')&&/^[-A-Za-z0-9_./]+\.(?:js|mjs)$/.test(p.slice(SDK.length+1))&&
      !p.includes('/../')&&!p.includes('//');
  for(const name of [...WORKER_FILES.map(name=>ROOT+'/qa/'+name),
    ...PLUGIN_FILES.map(name=>ROOT+'/plugin/'+name),...REQUIRED_SDK.map(name=>SDK+'/'+name)])
    need(Object.hasOwn(plan.sourcePins,name),'sdk_complete_required_public_source_pins');
  for(const [file,pin]of Object.entries(plan.sourcePins)){
    need(allowed(file)&&/^[0-9a-f]{64}$/.test(pin),'sdk_public_source_scope');
    need(hash(privateRead(file,2*1048576,true))===pin,'sdk_public_source_pin_changed');
  }
}
function installDiagnostics(){
  for(const key of Object.keys(originalConsole))console[key]=()=>{};
  const mute=function(data,...args){diagnosticBytes+=Buffer.byteLength(data);const callback=args.find(x=>typeof x==='function');
    if(callback)callback();return true;};
  process.stdout.write=mute;process.stderr.write=mute;
}
function installChildren(){
  const names=['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork'];
  childOriginals=Object.fromEntries(names.map(name=>[name,childProcess[name]]));
  const deny=()=>{childDenied++;need(false,'sdk_other_child_process_forbidden');};
  for(const name of names)childProcess[name]=deny;
  childProcess.execFileSync=(file,args,options)=>{
    if(file!=='mount'||!Array.isArray(args)||args.length!==0||options!==undefined)return deny();
    need(mountCalls<8,'sdk_finite_mount_probes');mountCalls++;
    const runtime=privateRead('/sbin/mount',1048576,true);
    need(typeof plan.mountToolSha256==='string'&&hash(runtime)===plan.mountToolSha256,'sdk_fixed_mount_tool_pin');
    return childOriginals.execFileSync('/sbin/mount',[],{timeout:remainingMs(3000),maxBuffer:262144,
      stdio:['ignore','pipe','pipe'],env:{PATH:'/usr/bin:/bin:/usr/sbin:/sbin'}});
  };
}
function installSqlite(){
  const sqlite=createRequire(import.meta.url)('node:sqlite'),Original=sqlite.DatabaseSync;
  const allowed=new Map(AGENTS.map((id,index)=>[STATE+'/agents/'+id+'/agent/openclaw-agent.sqlite',
    {category:'agent-auth',agentOrdinal:index+1}]));
  allowed.set(STATE+'/state/openclaw.sqlite',{category:'fixture-registry',agentOrdinal:0});
  const ledger={attempts:0,opened:0,readOnly:0,writable:0,memory:0,denials:0,connections:[]};
  sqlite.DatabaseSync=new Proxy(Original,{construct(target,args){
    const [file,options]=args,memory=file===':memory:';
    if(!memory&&!(typeof file==='string'&&allowed.has(file)&&path.resolve(file)===file)){
      ledger.denials++;need(false,'sdk_sqlite_outside_fixed_fixture_scope');
    }
    ledger.attempts++;
    const db=Reflect.construct(target,args,target),row={ordinal:++ledger.opened,
      ...(memory?{category:'memory',agentOrdinal:0}:allowed.get(file)),
      readOnly:options?.readOnly===true,closeAttempts:0,closed:false};
    if(memory)ledger.memory++;else if(row.readOnly)ledger.readOnly++;else ledger.writable++;
    ledger.connections.push(row);const close=db.close.bind(db);
    Object.defineProperty(db,'close',{value:(...values)=>{
      need(row.closeAttempts===0,'sdk_duplicate_database_close');row.closeAttempts++;
      const result=close(...values);row.closed=true;return result;
    }});return db;
  }});
  return {ledger,restore(){sqlite.DatabaseSync=Original;}};
}
function observeActualAgentCacheClose(){
  const walPath=SDK+'/dist/sqlite-wal-Bhk2Ro-u.js',agentPath=SDK+'/dist/openclaw-agent-db-DKpxi-Ll.js';
  const wal=privateRead(walPath,1048576,true).toString('utf8');
  const body='() => {\n\t\ttry {\n\t\t\tcloseAll();\n\t\t} catch {}\n\t}';
  const declaration='function registerSqliteCacheExitClose(closeAll) {\n\tconst closeOnExit = '+body+';\n'+
    '\tprocess.once("exit", closeOnExit);\n\treturn () => {\n\t\tprocess.removeListener("exit", closeOnExit);\n\t};\n}';
  need(wal.split(declaration).length===2,'sdk_exact_original_cache_close_source');
  const original=process.once;let callback=null,registered=0,invocations=0,restored=false;
  function observedOnce(event,listener,...args){
    if(event==='exit'&&typeof listener==='function'&&Function.prototype.toString.call(listener)===body){
      const stack=String(new Error().stack);
      need(this===process&&args.length===0&&registered===0&&
        stack.includes('registerSqliteCacheExitClose ('+pathToFileURL(walPath).href+':')&&
        stack.includes('openOpenClawAgentDatabase ('+pathToFileURL(agentPath).href+':'),
        'sdk_one_source_bound_agent_cache_close_registration');
      callback=listener;registered++;
    }
    return Reflect.apply(original,this,[event,listener,...args]);
  }
  process.once=observedOnce;
  return {
    restoreObserver(){need(process.once===observedOnce&&!restored,'sdk_exit_observer_identity');
      process.once=original;restored=true;},
    closeOriginalCache(){
      need(restored&&registered===1&&callback&&invocations===0&&process.listeners('exit').includes(callback),
        'sdk_original_agent_cache_close_once');
      invocations++;callback();
      need(!process.listeners('exit').includes(callback),'sdk_original_agent_close_unregisters_itself');
    },
    projection(){return {originalCallbackRegistrations:registered,originalCallbackInvocations:invocations,
      observerRestored:restored,originalListenerRemoved:callback!==null&&!process.listeners('exit').includes(callback),
      globalExitEventEmitted:false,arbitraryRawHandlesClosed:false};}
  };
}
function validateInputs(){
  need(process.platform==='darwin'&&process.getuid()===501,'sdk_exact_actual_mac_owner');
  need(process.argv.length===3,'sdk_one_private_plan_argument');
  const file=process.argv[2],phases=['initial','cold-new-process'];
  const phase=phases.find(value=>file===ROOT+'/'+value+'/worker-plan.private.json');
  need(Boolean(phase),'sdk_exact_private_plan_path');
  // Read the bounded plan before installing the authoritative phase allocation.
  until=started+120000000000n;
  plan=JSON.parse(privateRead(file));
  need(plan.schema==='heptabao.mac-main3-sdk-worker.private.r1'&&plan.phase===phase&&
    plan.mode===(phase==='initial'?'initial':'cold-inverse')&&plan.workRoot===ROOT&&plan.stateRoot===STATE&&
    plan.phaseRoot===ROOT+'/'+phase&&plan.sdkRoot===SDK&&plan.pluginEntry===ROOT+'/plugin/index.js',
    'sdk_exact_private_plan_scope');
  need(Number.isSafeInteger(plan.phaseRemainingMs)&&plan.phaseRemainingMs>0&&plan.phaseRemainingMs<=120000&&
    plan.phaseOwnerPid===process.ppid,'sdk_original_phase_allocation_and_parent');
  until=started+BigInt(plan.phaseRemainingMs)*1000000n;remainingMs(1);
  const outputs={inputCapsulePath:ROOT+'/input/selected-main3.private.json',
    baselineOutput:ROOT+'/private/baseline.private.json',initialCandidateOutput:ROOT+'/private/initial-candidate.private.json',
    latestCandidateOutput:ROOT+'/private/cold-candidate.private.json',rollbackOnce:ROOT+'/private/rollback-once.private.json',
    custodyOutput:ROOT+'/'+phase+'/custody.private.json'};
  for(const [key,value]of Object.entries(outputs))need(plan[key]===value,'sdk_fixed_private_output_'+key);
  need(fileURLToPath(import.meta.url)===ROOT+'/qa/main3_sdk_cycle_r2.mjs','sdk_actual_pinned_worker_entry');
  for(const folder of [ROOT,STATE,ROOT+'/input',ROOT+'/private',plan.phaseRoot,STATE+'/tmp',STATE+'/tmp/openclaw-501']){
    const s=fs.lstatSync(folder,{bigint:true});
    need(fs.realpathSync(folder)===folder&&s.isDirectory()&&s.uid===501n&&(s.mode&511n)===448n,
      'sdk_owned_private_fixture_directory');
  }
  process.env.OPENCLAW_STATE_DIR=STATE;
  process.env.OPENCLAW_CONFIG_PATH=STATE+'/openclaw.json';
  process.env.OPENCLAW_OAUTH_DIR=STATE+'/oauth';
  process.env.TMPDIR=STATE+'/tmp';
  process.env.OPENCLAW_AUTH_STORE_READONLY='1';
  cfg=JSON.parse(privateRead(STATE+'/openclaw.json'));
  need(equal(cfg.agents?.list?.map(x=>x.id),AGENTS),'sdk_exact_five_configured_agents');
  need(equal(cfg.plugins?.entries?.['openclaw-authbus']?.config,plan.pluginConfig),'sdk_owned_configuration_matches_plan');
  const withoutConnections=x=>Object.fromEntries(Object.entries(x).filter(([key])=>
    !['address','caFile','roleIdFile','secretIdFile'].includes(key)));
  need(equal(withoutConnections(plan.pluginConfig),withoutConnections(plan.originalPluginConfig)),
    'sdk_complete_original_nonconnection_flags');
  need(plan.pluginConfig.hostId==='mac'&&plan.pluginConfig.leader===false&&plan.pluginConfig.publishNew===true&&
    plan.pluginConfig.manageOrder===true,'sdk_actual_observed_mac_client_flags');
  need([plan.pluginConfig.caFile,plan.pluginConfig.roleIdFile,plan.pluginConfig.secretIdFile]
    .every(value=>typeof value==='string'&&value.startsWith(ROOT+'/server/')&&path.resolve(value)===value),
    'sdk_owned_connection_material_only');
  capsule=JSON.parse(privateRead(plan.inputCapsulePath));
  need(capsule.schema==='heptabao.actual-sdk-selected-owner-credentials.private.r1'&&capsule.host==='mac'&&
    capsule.constraints?.selectedOwnerCount===3&&capsule.constraints?.containsUnselectedCredentials===false&&
    Array.isArray(capsule.ownerEntries)&&capsule.ownerEntries.length===3&&
    Array.isArray(capsule.consumerBindings)&&capsule.consumerBindings.length===15,
    'sdk_private_current_capsule_three_owners');
  need(Array.isArray(plan.managedProfiles)&&plan.managedProfiles.length===3&&
    new Set(plan.managedProfiles.map(item=>item.profileId)).size===3,'sdk_exact_three_private_profiles');
  for(const [index,item]of plan.managedProfiles.entries()){
    need(item.key==='selected-main-'+(index+1)&&typeof item.profileId==='string'&&item.profileId.length>0&&
      item.profileId.length<=240,'sdk_fixed_three_slots');
    const original=capsule.ownerEntries.filter(entry=>entry.profileId===item.profileId);
    need(original.length===1&&original[0].ownerAgent==='main'&&original[0].actualProvider==='openai'&&
      equal(original[0].credential,item.credential)&&item.credential?.provider==='openai'&&
      item.credential.type==='oauth'&&['access','refresh'].every(key=>typeof item.credential[key]==='string'&&
        item.credential[key].length>=8)&&Number.isSafeInteger(item.credential.expires)&&item.credential.expires>0,
      'sdk_exact_current_oauth_object');
    sensitive.push(item.profileId,...Object.values(item.credential).filter(value=>typeof value==='string'&&value.length>=8));
    for(const id of AGENTS)need(capsule.consumerBindings.filter(binding=>binding.scopeAgent===id&&
      binding.profileId===item.profileId&&binding.ownerAgent==='main'&&binding.persistedOwnerMatchesEffective===true&&
      binding.selectedByActualSdkOrder===true).length===1,'sdk_current_five_by_three_source_binding');
  }
  report.mode=plan.mode;report.phase=phase;report.allocatedRemainingMs=plan.phaseRemainingMs;
  report.expiredInputCount=plan.managedProfiles.filter(item=>item.credential.expires<=Date.now()).length;
  sourceFence();report.publicSourcePinCount=Object.keys(plan.sourcePins).length;
}
const agentDir=id=>STATE+'/agents/'+id+'/agent';
async function verifyKernelSandbox(){
  // These two owned synthetic files are deliberately excluded from sandbox
  // data-read/data-write permissions. No production pathname is probed.
  for(const [name,flag]of [['protected-read',fs.constants.O_RDONLY],['protected-write',fs.constants.O_WRONLY]]){
    const file=ROOT+'/'+name,st=fs.lstatSync(file,{bigint:true});
    need(st.isFile()&&st.uid===501n&&st.nlink===1n&&(st.mode&511n)===384n,
      'sdk_kernel_probe_owned_synthetic_file');
    let fd,refused=false;
    try{fd=fs.openSync(file,flag|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);}
    catch(error){refused=['EPERM','EACCES'].includes(error.code);}
    finally{if(fd!==undefined)fs.closeSync(fd);}
    check('kernel_'+name.replace('-','_')+'_refused',refused);
  }
  // Port 9 is outside the single unprivileged owned-listener permit. A refused
  // TCP connection is not sufficient evidence: the kernel must deny access.
  const observed=await new Promise((resolve,reject)=>{
    const socket=new net.Socket();let errorCode=null,connected=false,expired=false;
    const timer=setTimeout(()=>{expired=true;socket.destroy();},remainingMs(750));
    socket.once('error',error=>{errorCode=error.code;socket.destroy();});
    socket.once('connect',()=>{connected=true;socket.destroy();});
    socket.once('close',()=>{clearTimeout(timer);resolve({errorCode,connected,expired,closed:true});});
    try{socket.connect({host:'127.0.0.1',port:9});}
    catch(error){clearTimeout(timer);socket.destroy();reject(Object.assign(new Error('sdk_kernel_connect_probe_failed'),
      {safeCode:'sdk_kernel_connect_probe_failed'}));}
  });
  check('kernel_other_loopback_connect_refused',observed.closed&&!observed.connected&&!observed.expired&&
    ['EPERM','EACCES'].includes(observed.errorCode));
  report.kernelSandbox={syntheticReadDenied:true,syntheticWriteDenied:true,
    otherLoopbackConnectDenied:true,originalProbeSocketClosed:true,productionPathProbed:false};
}
async function capture(){
  remainingMs(1);sdk.clearRuntimeAuthProfileStoreSnapshots();
  const rawBefore=Object.fromEntries(AGENTS.map(id=>[id,rowsApi.captureAuthRows(STATE,id)]));
  const effective=Object.fromEntries(AGENTS.map(id=>[id,sdk.loadAuthProfileStoreWithoutExternalProfiles(agentDir(id),
    {allowKeychainPrompt:false})]));
  const local={};
  for(const id of AGENTS){
    let observed;
    const result=await storeApi.m({agentDir:agentDir(id),updater:value=>{observed=structuredClone(value);return false;}});
    need(result!==null&&observed!==undefined&&equal(result,observed),'sdk_actual_local_read_transaction');
    local[id]=observed;
    need(equal(rowsApi.captureAuthRows(STATE,id),rawBefore[id]),'sdk_observation_preserves_raw_rows');
  }
  remainingMs(1);
  return {schema:'heptabao.mac-main3-private-state-image.r1',stateRoot:STATE,
    effective,local,authRows:rawBefore,caches:cachesApi.captureAuthBusCaches(STATE)};
}
function verifyStateImage(value){
  need(value?.schema==='heptabao.mac-main3-private-state-image.r1'&&value.stateRoot===STATE,
    'sdk_exact_private_state_image');
  for(const key of ['effective','local','authRows'])need(equal(Object.keys(value[key]).sort(),[...AGENTS].sort()),
    'sdk_private_five_store_image_scope');
}
function verifyRealProfiles(image,label){
  const ids=plan.managedProfiles.map(item=>item.profileId),sorted=[...ids].sort();
  for(const [index,id]of AGENTS.entries()){
    const effective=image.effective[id],local=image.local[id];
    check(label+'.three_effective.'+id,equal(Object.keys(effective.profiles).sort(),sorted));
    for(const item of plan.managedProfiles){
      check(label+'.exact_object.'+id+'.'+(ids.indexOf(item.profileId)+1),equal(effective.profiles[item.profileId],item.credential));
      const owner=storeApi.f({agentDir:agentDir(id),profileId:item.profileId});
      check(label+'.actual_main_owner.'+id+'.'+(ids.indexOf(item.profileId)+1),
        path.resolve(owner??sdk.resolveDefaultAgentDir({}))===agentDir('main'));
    }
    const order=orderApi.i({cfg,store:structuredClone(effective),provider:'openai'});
    check(label+'.actual_three_candidate_order.'+id,order.length===3&&new Set(order).size===3&&
      order.every(profile=>ids.includes(profile)));
    report.agentObservations.push({stage:label,agentOrdinal:index+1,agentId:id,
      actualLocalProfileCount:Object.keys(local.profiles).length,effectiveProfileCount:3,
      actualMainOwnedProfileCount:3,actualSdkOrderSlotOrdinals:order.map(profile=>ids.indexOf(profile)+1)});
  }
}
async function stopOnce(){need(service&&!serviceStopAttempted,'sdk_plugin_stop_once');
  serviceStopAttempted=true;await service.stop();serviceStopped=true;}
async function pluginCycle(){
  const plugin=(await import(pathToFileURL(plan.pluginEntry).href)).default;
  check('actual_plugin_export',plugin?.id==='openclaw-authbus'&&typeof plugin.register==='function');
  let subscriptions=0;
  plugin.register({registrationMode:'full',pluginConfig:plan.pluginConfig,
    agent:{events:{registerAgentEventSubscription(){subscriptions++;}}},
    registerService(value){need(service===null,'sdk_one_plugin_service');service=value;}});
  check('actual_one_plugin_service',subscriptions===1&&service?.id==='openclaw-authbus');
  const logCounts={info:0,warn:0,error:0,debug:0};
  const logger=Object.fromEntries(Object.keys(logCounts).map(key=>[key,()=>{logCounts[key]++;}]));
  serviceStopped=false;await service.start({stateDir:STATE,logger,config:cfg});await stopOnce();
  wire.stopNetwork();
  const status=JSON.parse(privateRead(STATE+'/authbus/status.json'));
  report.plugin=Object.fromEntries(['ok','manifestProfiles','importedProfiles','agentStores','verifiedStores',
    'effectiveMissing','effectiveMismatched','changedOrders','verifiedOrderBindings','schedulerMode',
    'schedulerReports','pendingRuntimeRefreshes','publishedEvents'].map(key=>[key,status[key]??null]));
  report.plugin.logCounts=logCounts;
  check('actual_complete_plugin_cycle',status.ok===true&&logCounts.error===0&&status.manifestProfiles===3&&
    status.agentStores===5&&status.verifiedStores===5&&status.effectiveMissing===0&&status.effectiveMismatched===0);
  check('actual_current_three_import_or_cache',status.importedProfiles===(plan.mode==='initial'?3:0));
  check('actual_one_approle_login',wire.tokens.length===1&&wire.rows.filter(row=>row.routeCategory==='approle-login').length===1);
  check('actual_manifest_pinned_tls_read',wire.rows.some(row=>row.routeCategory==='manifest-read'&&row.status===200&&row.responseComplete&&row.tlsVerified));
  if(plan.mode==='initial')check('actual_three_profile_pinned_tls_reads',plan.managedProfiles.every((_,index)=>
    wire.rows.filter(row=>row.routeCategory==='profile-read'&&row.slotOrdinal===index+1&&row.status===200&&
      row.responseComplete&&row.tlsVerified).length===1));
  check('all_plugin_http_complete',wire.rows.every(row=>row.dispatched&&row.requestCount===1&&row.responseComplete&&
    row.tlsVerified&&!row.outcomeUnknown&&!row.requestError&&!row.responseAborted&&!row.responseError));
}

try{
  process.umask(0o077);installDiagnostics();validateInputs();await verifyKernelSandbox();installChildren();
  sqlGuard=installSqlite();
  wire=installWireFence({address:plan.pluginConfig.address,ca:privateRead(plan.pluginConfig.caFile,65536),
    certificateSha256:plan.serverCertificateSha256,hostId:plan.pluginConfig.hostId,managed:plan.managedProfiles,remainingMs});
  report.wire=wire.rows;syncBuiltinESMExports();
  cacheExit=observeActualAgentCacheClose();
  sdk=await import(pathToFileURL(SDK+'/dist/plugin-sdk/agent-runtime.js').href);
  storeApi=await import(pathToFileURL(SDK+'/dist/store-DH33UrUj.js').href);
  orderApi=await import(pathToFileURL(SDK+'/dist/order-CeBlX0NH.js').href);
  stateApi=await import(pathToFileURL(SDK+'/dist/openclaw-state-db-DzSsA9Ji.js').href);
  rowsApi=await import('./main3_auth_rows_cas_r1.mjs');
  cachesApi=await import('./main3_authbus_cache_cas_r1.mjs');
  check('sdk_actual_main_default_scope',path.resolve(sdk.resolveDefaultAgentDir({}))===agentDir('main'));
  if(plan.mode==='initial'){
    for(const id of AGENTS){
      need(!fs.existsSync(agentDir(id)+'/openclaw-agent.sqlite'),'sdk_empty_schema_not_already_materialized');
      sdk.saveAuthProfileStore({version:1,profiles:{}},agentDir(id),{filterExternalAuthProfiles:false,syncExternalCli:false});
    }
    baseline=await capture();verifyStateImage(baseline);
    check('sdk_actual_five_empty_baseline',AGENTS.every(id=>Object.keys(baseline.local[id].profiles).length===0&&
      Object.keys(baseline.effective[id].profiles).length===0));
    check('sdk_original_six_cache_absences',baseline.caches.directory.absent===true&&
      Object.values(baseline.caches.files).every(value=>value.present===false));
    privateNew(plan.baselineOutput,baseline);
    await pluginCycle();const candidate=await capture();verifyRealProfiles(candidate,'import');
    privateNew(plan.initialCandidateOutput,candidate);candidateSaved=true;
  }else{
    baseline=JSON.parse(privateRead(plan.baselineOutput,4*1048576));verifyStateImage(baseline);
    const initial=JSON.parse(privateRead(plan.initialCandidateOutput,4*1048576));verifyStateImage(initial);
    const cold=await capture();
    check('cold_new_node_complete_candidate_exact',equal(cold,initial));verifyRealProfiles(cold,'cold');
    await pluginCycle();const candidate=await capture();verifyRealProfiles(candidate,'cold-cycle');
    privateNew(plan.latestCandidateOutput,candidate);candidateSaved=true;
    privateNew(plan.rollbackOnce,{schema:'heptabao.mac-main3-private-inverse-once.r1',phase:plan.phase,
      pid:process.pid,consumed:true,automaticRetry:false});
    inverseAttempted=true;
    for(const id of AGENTS){
      let applied=false;
      const result=await storeApi.m({agentDir:agentDir(id),
        saveOptions:{filterExternalAuthProfiles:false,syncExternalCli:false},updater:store=>{
          if(!equal(store,candidate.local[id]))return false;
          for(const key of Object.keys(store))delete store[key];
          Object.assign(store,structuredClone(baseline.local[id]));applied=true;return true;
        }});
      check('inverse_actual_sdk_local_cas.'+id,result!==null&&applied);
    }
    const postSdkRows=Object.fromEntries(AGENTS.map(id=>[id,rowsApi.captureAuthRows(STATE,id)]));
    for(const id of AGENTS)check('inverse_exact_raw_rows_and_stamps.'+id,
      rowsApi.restoreAuthRowsWithCas(STATE,id,postSdkRows[id],baseline.authRows[id])===true);
    check('inverse_exact_six_cache_candidate',equal(cachesApi.captureAuthBusCaches(STATE),candidate.caches));
    check('inverse_six_cache_original_bytes_modes_absences',cachesApi.restoreAuthBusCachesWithCas(STATE,candidate.caches,baseline.caches)===true);
    const restored=await capture();
    check('inverse_all_empty_local_and_effective_stores',equal(restored.local,baseline.local)&&equal(restored.effective,baseline.effective)&&
      AGENTS.every(id=>Object.keys(restored.local[id].profiles).length===0&&Object.keys(restored.effective[id].profiles).length===0));
    check('inverse_all_original_raw_rows_and_stamps',equal(restored.authRows,baseline.authRows));
    check('inverse_all_original_cache_content',cachesApi.cacheContentDigest(restored.caches)===cachesApi.cacheContentDigest(baseline.caches));
    inverseComplete=true;
  }
  sourceFence();remainingMs(1);
  check('no_other_child_or_network_attempts',childDenied===0&&wire.deniedCount()===0);
  check('no_unexpected_diagnostics',diagnosticBytes===0);
  report.ok=true;
}catch(error){
  report.errorCode=/^[a-z][a-z0-9_.-]{1,120}$/.test(error?.safeCode??'')?error.safeCode:'sdk_private_cycle_failed';
  report.errorType=['Error','TypeError','RangeError','SyntaxError'].includes(error?.constructor?.name)?error.constructor.name:'Error';
}finally{
  if(service&&!serviceStopAttempted){try{await stopOnce();}catch{serviceStopped=false;report.ok=false;}}
  if(wire){
    try{await wire.close();}catch{report.ok=false;report.connectionClosureFailed=true;}
    report.connections=wire.publicClosure();report.outcomeUnknown=wire.unknown()||!serviceStopped||(inverseAttempted&&!inverseComplete);
    if(wire.rows.some(row=>row.requestError||row.responseError||row.responseAborted||row.errorCode))report.ok=false;
    try{wire.restoreHooks();report.networkHooksRestored=true;}catch{report.ok=false;report.networkHooksRestored=false;}
  }else report.outcomeUnknown=inverseAttempted&&!inverseComplete;
  if(plan){try{privateNew(plan.custodyOutput,{schema:'heptabao.mac-main3-sdk-tokens.private.r1',
    phase:plan.phase,tokens:wire?.tokens??[]});report.privateTokenCustodyRecorded=true;}catch{report.ok=false;report.privateTokenCustodyRecorded=false;}}
  if(cacheExit){
    try{cacheExit.restoreObserver();cacheExit.closeOriginalCache();}
    catch{report.ok=false;report.originalAgentCacheClosureFailed=true;}
    report.sdkCacheClose=cacheExit.projection();
  }
  if(stateApi){
    try{stateApi.n();report.originalStateCacheCloseInvocations=1;}
    catch{report.ok=false;report.originalStateCacheClosureFailed=true;}
  }
  if(sqlGuard){
    const ledger=sqlGuard.ledger;
    report.sqlite={attempts:ledger.attempts,opened:ledger.opened,readOnly:ledger.readOnly,writable:ledger.writable,
      memory:ledger.memory,denials:ledger.denials,closed:ledger.connections.filter(row=>row.closed).length,
      allOriginalHandlesClosedOnce:ledger.connections.every(row=>row.closed&&row.closeAttempts===1)};
    if(!report.sqlite.allOriginalHandlesClosedOnce||ledger.denials)report.ok=false;
    sqlGuard.restore();
  }
  if(childOriginals)for(const [key,value]of Object.entries(childOriginals))childProcess[key]=value;
  syncBuiltinESMExports();
  for(const [key,value]of Object.entries(originalConsole))console[key]=value;
  process.stdout.write=originalDiagnosticWrites.stdout;process.stderr.write=originalDiagnosticWrites.stderr;
  Object.assign(report,{serviceStopAttempted,serviceStopped,candidateSaved,inverseMutationAttempted:inverseAttempted,
    inverseCompleted:inverseComplete,inverseRetried:false,exactOwnedMountProbeCount:mountCalls,
    forbiddenChildAttemptCount:childDenied,unexpectedDiagnosticBytes:diagnosticBytes,
    workerReadDescriptorsOpened:privateReadsOpened,workerReadDescriptorsClosed:privateReadsClosed,
    elapsedMs:Number((process.hrtime.bigint()-started)/1000000n)});
  if(report.outcomeUnknown||!serviceStopped||privateReadsOpened!==privateReadsClosed||process.hrtime.bigint()>=until)report.ok=false;
}
let publicText=JSON.stringify(report);
if(sensitive.some(value=>value.length>=8&&publicText.includes(value)))
  publicText=JSON.stringify({schema:report.schema,ok:false,errorCode:'sdk_public_projection_refused',
    productionChanged:false,providerCalled:false});
output(publicText+'\n');
process.exitCode=JSON.parse(publicText).ok?0:1;
