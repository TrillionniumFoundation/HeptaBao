/** Actual normal-HeptaBao qualification; every credential below is synthetic. */
import fs from 'node:fs';
import path from 'node:path';
import tls from 'node:tls';
import https from 'node:https';
import http from 'node:http';
import net from 'node:net';
import childProcess from 'node:child_process';
import { createRequire, syncBuiltinESMExports } from 'node:module';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';

const ROOT='/Users/qianqi/heptabao-fixed-slot-coordinator-normal-20261107-r1';
const CODE=ROOT+'/code',STATE=ROOT+'/state',PORT=31126;
const IMPLEMENTATION='248057b53a13708cc0650b73c83bc86729a7572e0d1bf24768ea94b8d3fd8265';
const OWNER='5c2073c4-7a2f-4542-9d96-ddcf35aa33f3',EPOCH='f84a000c-fdbb-49bd-9733-8eb91d420268';
const HOST='qualified-mac',AGENT='main';
const originalOutput=process.stdout.write.bind(process.stdout);
const start=process.hrtime.bigint();let until=start,plan,phase,wire,sql,fdLedger,producer,coordinator,negative,negativeStore,wrong,wrongStore;
let businessError=null,diagnosticCalls=0,childAttempts=0,networkDenials=0,expectedInterruption=false,closePromises=[];
const resources=[],checks=[];
const report={schema:'heptabao.fixed-slot-actual-worker.r1',ok:false,actualNormalHeptaBao:true,
  syntheticCredentialsOnly:true,productionCredentialReads:0,providerCalls:0,productionActions:0,
  sdkImported:false,j3160Contacted:false,networkResponseLossSimulated:false,localReceiptInterruptionInjected:false,
  sourceImplementationSha256:IMPLEMENTATION,checks};
function need(value,code){if(!value)throw Object.assign(new Error(code),{safeCode:code});}
function hash(value){return createHash('sha256').update(value).digest('hex');}
function identity(s){return ['dev','ino','uid','gid','mode','nlink','size','mtimeNs','ctimeNs'].map(k=>String(s[k])).join(':');}
function remaining(cap=120000){const left=Number((until-process.hrtime.bigint())/1000000n);need(left>0,'worker_original_phase_deadline');return Math.min(cap,left);}
function options(){return {deadlineMs:Date.now()+remaining(30000)};}
function check(name,condition){need(/^[a-z0-9._-]{1,110}$/.test(name),'worker_fixed_check_name');checks.push({case:name,passed:condition===true});need(condition===true,name);}
function canonical(value){if(Array.isArray(value))return value.map(canonical);
  if(value!==null&&typeof value==='object')return Object.fromEntries(Object.keys(value).sort().map(k=>[k,canonical(value[k])]));
  need(value===null||['string','boolean'].includes(typeof value)||Number.isSafeInteger(value),'worker_canonical_json_value');return value;}
function equal(a,b){return JSON.stringify(canonical(a))===JSON.stringify(canonical(b));}
function readPrivate(filename,maximum=1048576){
  need(filename.startsWith(ROOT+'/')&&path.resolve(filename)===filename,'worker_fixed_private_input');
  const parent=fs.lstatSync(path.dirname(filename),{bigint:true});
  need(parent.isDirectory()&&parent.uid===501n&&(parent.mode&0o777n)===0o700n,'worker_private_input_parent');
  const fd=fs.openSync(filename,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
  try{const before=fs.fstatSync(fd,{bigint:true});need(before.isFile()&&before.uid===501n&&before.nlink===1n
      &&(before.mode&0o777n)===0o600n&&before.size>0n&&before.size<=BigInt(maximum),'worker_private_input_file');
    const raw=Buffer.alloc(Number(before.size)+1);let offset=0;
    try{while(offset<raw.length){const count=fs.readSync(fd,raw,offset,raw.length-offset,null);if(!count)break;offset+=count;}
      need(BigInt(offset)===before.size&&identity(before)===identity(fs.fstatSync(fd,{bigint:true}))
        &&identity(before)===identity(fs.lstatSync(filename,{bigint:true}))
        &&identity(parent)===identity(fs.lstatSync(path.dirname(filename),{bigint:true})),'worker_private_input_generation');
      return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw.subarray(0,offset)));
    }finally{raw.fill(0);}
  }finally{fs.closeSync(fd);}
}
function privateNew(filename,value){need([ROOT+'/results/initial-state.private.json',ROOT+'/results/initial-error.private.json',
  ROOT+'/results/cold-error.private.json'].includes(filename),'worker_fixed_private_output');
  const raw=Buffer.from(JSON.stringify(value)+'\n');need(raw.length<=1048576,'worker_private_output_bound');
  const fd=fs.openSync(filename,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
  try{let n=0;while(n<raw.length){const count=fs.writeSync(fd,raw,n,raw.length-n,null);need(count>0,'worker_output_progress');n+=count;}
    fs.fsyncSync(fd);const held=fs.fstatSync(fd,{bigint:true});need(held.uid===501n&&held.nlink===1n&&(held.mode&0o777n)===0o600n
      &&held.size===BigInt(raw.length)&&identity(held)===identity(fs.lstatSync(filename,{bigint:true})),'worker_output_original_inode');
    const d=fs.openSync(path.dirname(filename),fs.constants.O_RDONLY|fs.constants.O_DIRECTORY|fs.constants.O_NOFOLLOW);
    try{fs.fsyncSync(d);}finally{fs.closeSync(d);}
  }finally{raw.fill(0);fs.closeSync(fd);}
}
function sourceFence(){for(const row of plan.sourcePins){
  need(row.path.startsWith(CODE+'/')&&path.resolve(row.path)===row.path&&Number.isSafeInteger(row.bytes)
    &&row.bytes>0&&row.bytes<=131072&&/^[a-f0-9]{64}$/.test(row.sha256),'worker_public_source_pin_shape');
  const fd=fs.openSync(row.path,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
  try{const before=fs.fstatSync(fd,{bigint:true});need(before.isFile()&&before.uid===501n&&before.nlink===1n
    &&(before.mode&0o022n)===0n&&before.size===BigInt(row.bytes),'worker_source_file_custody');
    const b=Buffer.alloc(row.bytes+1);let n=0;while(n<b.length){const count=fs.readSync(fd,b,n,b.length-n,null);if(!count)break;n+=count;}
    need(n===row.bytes&&hash(b.subarray(0,n))===row.sha256&&identity(before)===identity(fs.fstatSync(fd,{bigint:true}))
      &&identity(before)===identity(fs.lstatSync(row.path,{bigint:true})),'worker_source_exact_generation');
  }finally{fs.closeSync(fd);}
}}
function observeFds(){const open=fs.openSync,close=fs.closeSync,rows=[],live=new Map();
  fs.openSync=function(...args){const fd=Reflect.apply(open,this,args);const row={ordinal:rows.length+1,closeAttempts:0,closed:false};
    need(!live.has(fd),'worker_fd_number_already_owned');rows.push(row);live.set(fd,row);return fd;};
  fs.closeSync=function(fd,...args){const row=live.get(fd);need(row&&row.closeAttempts===0,'worker_close_original_explicit_fd');row.closeAttempts++;
    const value=Reflect.apply(close,this,[fd,...args]);row.closed=true;live.delete(fd);return value;};
  return {rows,restore(){fs.openSync=open;fs.closeSync=close;},public(){return {opened:rows.length,closed:rows.filter(r=>r.closed).length,
    allOriginalExplicitDescriptorsClosedOnce:rows.every(r=>r.closed&&r.closeAttempts===1),scope:'explicit JavaScript fs.openSync calls; SQLite tracked separately'};}};
}
function observeSqlite(){const sqlite=createRequire(import.meta.url)('node:sqlite'),Original=sqlite.DatabaseSync,rows=[];
  const dirs=[STATE+'/coordinator/journal-store',STATE+'/producer/authbus/production-transport',STATE+'/negative',STATE+'/wrong-pin'];
  const allowed=new Set(dirs.flatMap(d=>[d+'/state.sqlite',d+'/operation.sqlite']));
  sqlite.DatabaseSync=new Proxy(Original,{construct(target,args){need(typeof args[0]==='string'&&allowed.has(args[0]),'worker_exact_fixture_database');
    const db=Reflect.construct(target,args,target),row={ordinal:rows.length+1,closeAttempts:0,closed:false};rows.push(row);
    const close=db.close.bind(db);Object.defineProperty(db,'close',{value:(...a)=>{need(row.closeAttempts===0,'worker_sql_close_once');row.closeAttempts++;
      const result=close(...a);row.closed=true;return result;}});return db;}});
  syncBuiltinESMExports();return {rows,restore(){sqlite.DatabaseSync=Original;syncBuiltinESMExports();},public(){return {opened:rows.length,
    closed:rows.filter(r=>r.closed).length,allOriginalHandlesClosedOnce:rows.every(r=>r.closed&&r.closeAttempts===1)};}};
}
function category(route){if(route==='/v1/auth/approle/login')return 'approle-login';
  if(route==='/v1/auth/token/renew-self')return 'renew';if(route==='/v1/auth/token/revoke-self')return 'revoke';
  if(route==='/v1/auth/token/lookup-self')return 'lookup';if(route==='/v1/sys/mounts')return 'admin-denial';
  if(route==='/v1/openclaw-auth/config')return 'mount-retention';
  if(route.startsWith('/v1/openclaw-auth/metadata/'))return 'key-retention';
  if(route.startsWith('/v1/openclaw-auth/data/')){const key=route.slice('/v1/openclaw-auth/data/'.length).split('?')[0];
    if(key==='manifest')return 'manifest';if(key==='transport-v1/control')return 'control';
    if(key.startsWith('profiles/'))return 'profile';if(key.startsWith('coordinator-receipts/'))return 'receipt';
    if(key.includes('/outbox/'))return 'slot';if(key.includes('/ack/'))return 'ack';if(key.includes('/reports/'))return 'report';}
  need(false,'worker_route_outside_fixture_protocol');
}
function observeWire(){const originalTls=tls.connect,originalHttps=https.request,originalHttp=http.request,originalFetch=globalThis.fetch;
  const sockets=[],requests=[],socketRows=new WeakMap();let denied=0;
  tls.connect=function(...args){const o=args[0];need(o&&o.host==='127.0.0.1'&&o.port===PORT,'worker_one_fixed_tls_destination');remaining();
    const socket=Reflect.apply(originalTls,this,args),row={ordinal:sockets.length+1,secureConnectObserved:false,authorized:false,
      actualIpv4AndPort:false,leafExact:false,closed:false};sockets.push(row);socketRows.set(socket,row);
    closePromises.push(new Promise(resolve=>socket.once('close',()=>{row.closed=true;resolve();})));
    socket.once('secureConnect',()=>{row.secureConnectObserved=true;row.authorized=socket.authorized===true;
      row.actualIpv4AndPort=socket.remoteAddress==='127.0.0.1'&&socket.remotePort===PORT;
      const peer=socket.getPeerCertificate(true);row.leafExact=Buffer.isBuffer(peer.raw)&&hash(peer.raw)===plan.coordinator.serverCertificateSha256;
      row.protocol=socket.getProtocol();});return socket;};
  https.request=function(...args){const o=args[0];need(o&&o.hostname==='127.0.0.1'&&o.port===PORT&&typeof args[1]==='function','worker_one_https_request_shape');remaining();
    const row={ordinal:requests.length+1,method:o.method,routeCategory:category(o.path),responseSeen:false,responseComplete:false,
      ended:false,status:null,bodyBytes:0,closed:false,socketOrdinal:null,originalSocketBound:false};need(requests.length<512,'worker_finite_wire_count');requests.push(row);
    const callback=args[1];args[1]=function(response){row.responseSeen=true;row.status=response.statusCode;
      response.on('data',chunk=>{row.bodyBytes+=chunk.length;});response.once('end',()=>{row.ended=true;row.responseComplete=response.complete===true;});
      return Reflect.apply(callback,this,[response]);};
    const request=Reflect.apply(originalHttps,this,args);request.once('socket',socket=>{const original=socketRows.get(socket);
      if(original){row.socketOrdinal=original.ordinal;row.originalSocketBound=true;}});
    closePromises.push(new Promise(resolve=>request.once('close',()=>{row.closed=true;resolve();})));return request;};
  http.request=function(){denied++;need(false,'worker_plain_http_denied');};
  globalThis.fetch=async()=>{denied++;need(false,'worker_fetch_denied');};
  syncBuiltinESMExports();return {sockets,requests,restore(){tls.connect=originalTls;https.request=originalHttps;http.request=originalHttp;globalThis.fetch=originalFetch;syncBuiltinESMExports();},
    public(){return {requests,sockets,requestCount:requests.length,allOriginalRequestsClosed:requests.every(r=>r.closed),
      allDispatchedResponsesComplete:requests.every(r=>r.ended&&r.responseComplete),allOriginalSocketsClosed:sockets.every(r=>r.closed),
      allDispatchedTlsVerified:requests.every(r=>{const socket=sockets[r.socketOrdinal-1];return r.originalSocketBound&&socket
        &&socket.secureConnectObserved&&socket.authorized&&socket.actualIpv4AndPort&&socket.leafExact;}),deniedOtherNetwork:denied};}};
}
async function kernelProbes(){const seen={};for(const [name,flag]of [['protected-read',fs.constants.O_RDONLY],['protected-write',fs.constants.O_WRONLY|fs.constants.O_APPEND]]){
  try{const fd=fs.openSync(ROOT+'/'+name,flag);fs.closeSync(fd);need(false,'worker_protected_file_was_opened');}
  catch(error){need(['EPERM','EACCES'].includes(error.code),'worker_actual_protected_file_denial');seen[name]=true;}}
  const socket=new net.Socket();let denied=false,closed=false;const close=new Promise(resolve=>socket.once('close',()=>{closed=true;resolve();}));
  await new Promise((resolve,reject)=>{socket.once('error',error=>{denied=['EPERM','EACCES'].includes(error.code);resolve();});
    socket.once('connect',()=>reject(Object.assign(new Error('worker_forbidden_port_connected'),{safeCode:'worker_forbidden_port_connected'})));
    socket.setTimeout(remaining(2000),()=>reject(Object.assign(new Error('worker_forbidden_port_timeout'),{safeCode:'worker_forbidden_port_timeout'})));
    socket.connect(9,'127.0.0.1');}).finally(()=>socket.destroy());await close;
  need(denied&&closed,'worker_actual_other_port_kernel_denial');report.kernelSandbox={readDenied:seen['protected-read'],writeDenied:seen['protected-write'],
    otherLoopbackDenied:denied,originalProbeSocketClosed:closed,productionFileProbed:false};
}
function event(number,reason='leader-refresh'){const credential={provider:'openai',type:'oauth',access:'SYNTHETIC-ACCESS-'+number,
  refresh:'SYNTHETIC-REFRESH-'+number,expires:2000000000000+number,accountId:'SYNTHETIC-ACCOUNT'};
  return {schemaVersion:1,eventId:'72ef31b1-87f0-4c72-b1b2-'+String(number).padStart(12,'0'),sourceHost:HOST,reason,
    profileId:'SYNTHETIC-PROFILE',credential};}
function canonicalEvent(number,protocol,reason){const e=event(number,reason);e.digest=protocol.digest(e.credential);e.identity=protocol.credentialIdentity(e.credential);return e;}
function grantFor(next,previous,ordinal){return {authorizationId:'acda97c3-cfe1-458c-b631-'+String(ordinal).padStart(12,'0'),
  profileId:next.profileId,sourceHost:HOST,provider:'openai',identityDigest:next.identity,
  expectedCurrentDigest:previous?.digest??null,nextDigest:next.digest};}
function producerConfig(protocol){return {...plan.producer,hostId:HOST,productionTransport:{schema:protocol.TRANSPORT,production:true,
  epoch:EPOCH,slots:1,agents:[AGENT],controlDigest:protocol.digest(coordinator.control),serverCertificateSha256:plan.coordinator.serverCertificateSha256}};}
const originalChild=Object.fromEntries(['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork'].map(k=>[k,childProcess[k]]));
const originalConsole=Object.fromEntries(['log','warn','error','info','debug'].map(k=>[k,console[k]]));

try{
  need(process.platform==='darwin'&&process.getuid()===501&&process.getgid()===20,'worker_actual_mac_owner');
  need(process.argv.length===3&&[ROOT+'/input/initial-plan.private.json',ROOT+'/input/cold-plan.private.json'].includes(process.argv[2]),'worker_fixed_plan_argument');
  fdLedger=observeFds();plan=readPrivate(process.argv[2]);phase=plan.phase;
  need(plan.schema==='heptabao.coordinator-actual-plan.r1'&&['initial','cold'].includes(phase)&&plan.parentPid===process.ppid
    &&typeof plan.parentNowMonotonicNs==='string'&&/^[0-9]{1,24}$/.test(plan.parentNowMonotonicNs)
    &&typeof plan.phaseUntilMonotonicNs==='string'&&/^[0-9]{1,24}$/.test(plan.phaseUntilMonotonicNs),'worker_plan_original_scope');
  const parentNow=BigInt(plan.parentNowMonotonicNs),originalUntil=BigInt(plan.phaseUntilMonotonicNs),current=process.hrtime.bigint();
  need(originalUntil>parentNow&&originalUntil-parentNow<=120000000000n&&parentNow<=start&&start<=current&&current<originalUntil,
    'worker_same_monotonic_clock_original_absolute_deadline');
  until=originalUntil;report.phase=phase;
  need(plan.coordinator.schema==='heptabao.fixed-slot-coordinator.r1.config'&&plan.coordinator.implementationSha256===IMPLEMENTATION
    &&plan.coordinator.stateDir===STATE+'/coordinator'&&plan.coordinator.ownerId===OWNER&&plan.coordinator.operationMs===30000
    &&plan.coordinator.bootstrapProfileCount===1&&plan.coordinator.address==='https://127.0.0.1:'+PORT
    &&equal(plan.coordinator.topology,[{host_id:HOST,epoch:EPOCH,slots:1,agents:[AGENT]}]),'worker_exact_coordinator_configuration');
  for(const [name,c]of [['coordinator',plan.coordinator],['producer',plan.producer]])need(c.caFile===ROOT+'/pki/ca.crt'
    &&c.address==='https://127.0.0.1:'+PORT&&c.roleIdFile===ROOT+'/input/'+name+'-role-id'
    &&c.secretIdFile===ROOT+'/input/'+name+'-secret-id'&&c.serverCertificateSha256===plan.coordinator.serverCertificateSha256,'worker_exact_synthetic_role_inputs');
  need(Array.isArray(plan.sourcePins)&&plan.sourcePins.length===11&&new Set(plan.sourcePins.map(x=>x.path)).size===11,'worker_exact_source_inventory');
  sourceFence();await kernelProbes();
  for(const k of Object.keys(originalChild))childProcess[k]=()=>{childAttempts++;need(false,'worker_child_process_denied');};
  for(const k of Object.keys(originalConsole))console[k]=()=>{diagnosticCalls++;};
  sql=observeSqlite();wire=observeWire();syncBuiltinESMExports();
  const protocol=await import(pathToFileURL(CODE+'/protocol.mjs').href);
  const module=await import(pathToFileURL(CODE+'/coordinator.mjs').href);
  const {ProductionTransportClient}=await import(pathToFileURL(CODE+'/transport/production-client.js').href);
  const {StrictBaoClient}=await import(pathToFileURL(CODE+'/transport/strict-bao-client.js').href);
  const {PrivateOutboxStore}=await import(pathToFileURL(CODE+'/transport/private-outbox-store.js').href);
  coordinator=module.openCoordinator(plan.coordinator);
  const first=canonicalEvent(1,protocol,'new-profile'),second=canonicalEvent(2,protocol),third=canonicalEvent(3,protocol),fourth=canonicalEvent(4,protocol);
  if(phase==='initial'){
    wrongStore=new PrivateOutboxStore(STATE+'/wrong-pin',{schema:'synthetic-wrong-leaf-qualification'});
    wrong=new StrictBaoClient({...plan.producer,serverCertificateSha256:'0'.repeat(64)},wrongStore);
    const before=wire.requests.length;let denied=false;try{await wrong.login(options());}catch(e){denied=e.code==='tls_leaf_pin_mismatch';}
    check('strict_wrong_leaf_before_any_http',denied&&wire.requests.length===before&&wrongStore.loadAuth().value===null);
    await wrong.close({revoke:false,deadlineMs:Date.now()+remaining(15000)});wrong=null;wrongStore.close();wrongStore=null;
    await coordinator.initialize(options());await coordinator.authorize(grantFor(first,null,1),options());await coordinator.bootstrap(first,options());
    await coordinator.enroll(options());check('exact_authorized_bootstrap_and_finite_enrollment',true);
    producer=new ProductionTransportClient(producerConfig(protocol),STATE+'/producer');
    await producer.writeInbox(HOST,second.eventId,second,options());
    let result=await coordinator.once(options());check('pending_event_without_grant_not_committed',result.deferredUnauthorized===1&&result.credentialAcknowledgements===0);
    let full=false;try{await producer.writeInbox(HOST,third.eventId,third,options());}catch(e){full=e.backpressure===true;}
    check('fixed_single_slot_preserves_backpressure',full);
    const approval=grantFor(second,first,2);await coordinator.authorize(approval,options());await coordinator.revokeAuthorization(approval.authorizationId,options());
    result=await coordinator.once(options());check('revoked_operator_grant_keeps_event_pending',result.deferredUnauthorized===1);
    await coordinator.authorize(grantFor(second,first,3),options());result=await coordinator.once(options());
    check('exact_new_grant_commits_profile_manifest_receipt_ack',result.credentialAcknowledgements===1);
    check('repeated_confirmed_event_is_already_canonical',(await producer.writeInbox(HOST,second.eventId,second,options())).alreadyCanonical===true);
    const health={schemaVersion:2,kind:'health-observation',sourceHost:HOST,eventId:'4a8fd110-e560-4c51-881c-d90c48bc7504',agentId:AGENT,healthy:false};
    await producer.writeInbox(HOST,health.eventId,health,options());result=await coordinator.once(options());
    check('health_receipt_is_observation_without_scheduler_authority',result.healthAcknowledgements===1&&result.schedulerActions===0);
    const agentReport={schemaVersion:2,kind:'agent-report',sourceHost:HOST,eventId:'2fcf0cc2-451f-4855-878f-8b67c41e2408',agentId:AGENT,profiles:[]};
    await producer.writeInbox(HOST,agentReport.eventId,agentReport,options());result=await coordinator.once(options());
    check('finite_report_is_read_only_observation',result.reportsObserved===1&&result.schedulerActions===0&&result.providerCalls===0);
    await coordinator.authorize(grantFor(third,second,4),options());await producer.writeInbox(HOST,third.eventId,third,options());
    coordinator.phaseHook=async(name,detail)=>{if(name==='remote-confirmed-before-receipt'&&detail.role==='ack'){
      expectedInterruption=true;throw Object.assign(new Error('fixture_expected_local_receipt_interruption'),{safeCode:'fixture_expected_local_receipt_interruption'});}};
    let interrupted=false;try{await coordinator.once(options());}catch(e){interrupted=e.safeCode==='fixture_expected_local_receipt_interruption';}
    const active=coordinator.store.get('active').value,originalPlan=coordinator.journal.read(active.id+'.json');
    check('original_ack_pending_only_after_returned_remote_response',interrupted&&expectedInterruption&&active.phase==='dispatched'
      &&originalPlan.steps[active.step].role==='ack'&&coordinator.journal.read(active.id+'.step-'+String(active.step).padStart(4,'0')+'.response.json')===null);
    privateNew(ROOT+'/results/initial-state.private.json',{schema:'heptabao.coordinator-local-interruption.private.r1',active,
      originalPlan,coordinatorAuth:coordinator.store.loadAuth().value,third,coordinatorBinding:coordinator.binding});
    report.localReceiptInterruptionInjected=true;report.originalOperationPendingForColdReconciliation=true;
  }else{
    const before=readPrivate(ROOT+'/results/initial-state.private.json');
    check('cold_process_reopens_exact_original_local_intent',before.schema==='heptabao.coordinator-local-interruption.private.r1'
      &&protocol.equal(coordinator.store.get('active').value,before.active)&&protocol.equal(coordinator.binding,before.coordinatorBinding)
      &&protocol.equal(coordinator.journal.read(before.active.id+'.json'),before.originalPlan));
    check('cold_process_retains_original_known_active_bearer',protocol.equal(coordinator.store.loadAuth().value,before.coordinatorAuth));
    const writes=coordinator.adapter.counts.writeDispatches;const recovered=await coordinator.recover(options());
    check('cold_exact_ack_readback_completes_without_rewrite',recovered.completed===true&&coordinator.adapter.counts.writeDispatches===writes
      &&coordinator.store.get('active').value===null);
    const manifest=await coordinator.manifest(options().deadlineMs),entry=manifest.data.profiles.find(x=>x.profileId===third.profileId);
    check('cold_canonical_third_credential_and_immutable_profile_match',entry?.digest===third.digest
      &&protocol.equal((await coordinator.adapter.read('profiles/'+entry.key,options().deadlineMs)).data.credential,third.credential));
    producer=new ProductionTransportClient(producerConfig(protocol),STATE+'/producer');await producer.reconcile(options());
    check('cold_producer_reconciles_original_slot',(await producer.writeInbox(HOST,third.eventId,third,options())).alreadyCanonical===true);
    const oldBearer=coordinator.store.loadAuth().value.token;
    await coordinator.locked(untilMs=>coordinator.adapter.client.renew({deadlineMs:untilMs}),options());
    check('actual_scoped_bearer_renews_without_replacement',coordinator.store.loadAuth().value.token===oldBearer
      &&coordinator.store.loadAuth().value.renewable===true);
    await coordinator.authorize(grantFor(fourth,third,5),options());await producer.writeInbox(HOST,fourth.eventId,fourth,options());
    check('cold_new_exact_rotation_and_slot_reuse',(await coordinator.once(options())).credentialAcknowledgements===1);
    let denied=false;try{await coordinator.adapter.client.request('GET','/v1/sys/mounts',undefined,undefined,options());}catch(e){denied=e.status===403&&e.unknown===false;}
    check('coordinator_cannot_administer_server',denied);
    negativeStore=new PrivateOutboxStore(STATE+'/negative',{schema:'synthetic-producer-policy-qualification'});
    negative=new StrictBaoClient(plan.producer,negativeStore);await negative.login(options());
    for(const [label,key]of [['canonical_manifest','manifest'],['immutable_profile','profiles/not-authorized'],['control','transport-v1/control'],
      ['other_host_slot','transport-v1/foreign-host/outbox/slot-000']]){
      let refused=false;try{await negative.writeSecret(key,{syntheticDenied:true},0,options());}catch(e){refused=e.status===403&&e.unknown===false;}
      check('producer_denied_'+label,refused);
    }
    report.originalOperationPendingForColdReconciliation=false;
  }
  sourceFence();report.ok=true;
}catch(error){businessError=error;report.errorType=['Error','TypeError','SyntaxError','RangeError','CoordinatorError','OutboxError','BaoError','Conflict','UnknownOutcome'].includes(error?.name)?error.name:'OtherError';
  report.errorCode=typeof error?.safeCode==='string'&&/^[a-z0-9._-]{1,120}$/.test(error.safeCode)?error.safeCode:'actual_coordinator_qualification_failed';report.ok=false;
  if(['initial','cold'].includes(phase))try{privateNew(ROOT+'/results/'+phase+'-error.private.json',{
    schema:'heptabao.fixed-slot-worker-error.private.r1',name:String(error?.name).slice(0,256),
    code:String(error?.code).slice(0,256),message:String(error?.message).slice(0,16384),stack:String(error?.stack).slice(0,32768)});
    report.privateErrorRetained=true;}catch{report.privateErrorRetained=false;}
}finally{
  const failures=[];
  async function closeOne(name,fn){try{const value=await fn();resources.push({name,closed:true,revoked:value?.revoked===true});}
    catch{failures.push(name);resources.push({name,closed:false});}}
  if(negative){await closeOne('negative-bearer',()=>negative.close({revoke:true,deadlineMs:Date.now()+remaining(15000)}));negative=null;}
  if(negativeStore){await closeOne('negative-store',()=>negativeStore.close());negativeStore=null;}
  if(wrong){await closeOne('wrong-leaf-client',()=>wrong.close({revoke:false,deadlineMs:Date.now()+remaining(15000)}));wrong=null;}
  if(wrongStore){await closeOne('wrong-leaf-store',()=>wrongStore.close());wrongStore=null;}
  if(producer){await closeOne('producer',()=>producer.close());producer=null;}
  if(coordinator){await closeOne('coordinator',()=>coordinator.close({revoke:phase==='cold'&&!businessError,deadlineMs:Date.now()+remaining(15000)}));coordinator=null;}
  if(wire){let timer;try{await Promise.race([Promise.all(closePromises),new Promise((_,reject)=>{
      timer=setTimeout(()=>reject(new Error('original_socket_close_unobserved')),remaining(5000));})]);}
    catch{failures.push('original-network-close');}finally{clearTimeout(timer);}
    report.wire=wire.public();wire.restore();}
  if(sql){report.sqlite=sql.public();sql.restore();}
  for(const [key,value]of Object.entries(originalChild))childProcess[key]=value;
  for(const [key,value]of Object.entries(originalConsole))console[key]=value;
  syncBuiltinESMExports();
  if(fdLedger){report.explicitFiles=fdLedger.public();fdLedger.restore();}
  report.resources=resources;report.closureFailures=failures;report.childProcessAttempts=childAttempts;
  report.unexpectedConsoleCalls=diagnosticCalls;report.elapsedMs=Number((process.hrtime.bigint()-start)/1000000n);
  report.completedWithinOriginalPhase=process.hrtime.bigint()<until;
  report.ok=Boolean(report.ok&&!failures.length&&report.completedWithinOriginalPhase&&childAttempts===0&&diagnosticCalls===0
    &&report.sqlite?.allOriginalHandlesClosedOnce&&report.explicitFiles?.allOriginalExplicitDescriptorsClosedOnce
    &&report.wire?.allOriginalRequestsClosed&&report.wire?.allDispatchedResponsesComplete&&report.wire?.allOriginalSocketsClosed
    &&report.wire?.allDispatchedTlsVerified&&report.wire?.deniedOtherNetwork===0);
  originalOutput(JSON.stringify(report)+'\n');process.exitCode=report.ok?0:1;
}
