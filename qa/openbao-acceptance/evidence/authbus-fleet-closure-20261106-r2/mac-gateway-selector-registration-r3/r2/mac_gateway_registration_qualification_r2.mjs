#!/usr/bin/env node
/** Installed original gateway selectors and registration, exclusively synthetic state. */
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import net from 'node:net';
import http from 'node:http';
import https from 'node:https';
import dns from 'node:dns';
import dnsPromises from 'node:dns/promises';
import childProcess from 'node:child_process';
import * as moduleApi from 'node:module';
import {pathToFileURL,fileURLToPath} from 'node:url';
import {isDeepStrictEqual} from 'node:util';
import {ROOT,SDK,STATE,HOME,CONFIG,AUTHBUS_ROOT,CONTROL_ROOT,runGatewayCases} from './mac_gateway_registration_cases_r2.mjs';

const started=process.hrtime.bigint(),budget=Number(process.argv[2]);
let until=started+BigInt(Number.isFinite(budget)?Math.trunc(budget*1000000):0);
const report={schema:'heptabao.actual-mac-gateway-selectors-registration.r2',ok:false,
 actualInstalledSdk:true,syntheticConfigurationAndStateOnly:true,productionCredentialReads:0,
 productionWrites:0,providerCalls:0,serviceMutations:0,fullGatewayServerStarted:false,
 actualProductionGatewayMemoryQualified:false,productionFallbackConfigurationQualified:false,
 productionMutexAcquired:false,productionOnceLedgerOpened:false,cases:[],fileDescriptors:[],
 forbiddenChildAttempts:0,allowedReadonlyMountCalls:0,completedReadonlyMountCalls:0,
 forbiddenNetworkAttempts:0,forbiddenProductionReadAttempts:0,forbiddenWriteAttempts:0,
 authbusModuleLoadAttempts:0,controlModuleLoadAttempts:0,loadedEntryModules:[],
 originalDotenvReads:{state:0,gateway:0},privateDiagnosticFiles:[],
 sqlite:{attempts:0,opened:0,denials:0,connections:[]}};
const output=process.stdout.write.bind(process.stdout),originalOut=process.stdout.write,originalErr=process.stderr.write;
const restores=[],codes=new Set(),originalFs={openSync:fs.openSync,readFileSync:fs.readFileSync,writeFileSync:fs.writeFileSync,closeSync:fs.closeSync};
let plan,stateApi,sqliteOriginal,sqliteModule,moduleHooks,activeCase=null,diagnosticBytes=0;
let hooksDeregistered=false,guardsInstalled=false,privateErrorSaved=false;
function need(value,code){if(!value){codes.add(code);throw new Error(code);}}
function remainingMs(cap=30000){const left=Number((until-process.hrtime.bigint())/1000000n);need(left>0,'gateway_qualification_original_deadline');return Math.min(cap,left);}
function sha(raw){return crypto.createHash('sha256').update(raw).digest('hex');}
function full(s){return ['dev','ino','uid','gid','mode','nlink','size','mtimeNs','ctimeNs'].map(k=>String(s[k]));}
function readPinned(filename,pin,cap=1048576){
 remainingMs();const fd=originalFs.openSync(filename,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
 const row={role:'bounded-public-or-synthetic-input',closeAttempts:0,closed:false};report.fileDescriptors.push(row);
 try{
  const before=fs.fstatSync(fd,{bigint:true});need(before.isFile()&&before.nlink===1n&&[0n,501n].includes(before.uid)
   &&(before.mode&18n)===0n&&before.size>=0n&&before.size<=BigInt(cap),'gateway_owned_or_public_input_identity');
  const buffer=Buffer.alloc(Number(before.size)+1);let count=0;
  while(count<buffer.length){remainingMs();const n=fs.readSync(fd,buffer,count,buffer.length-count,null);if(!n)break;count+=n;}
  const raw=buffer.subarray(0,count);
  need(count===Number(before.size)&&isDeepStrictEqual(full(before),full(fs.fstatSync(fd,{bigint:true})))
   &&isDeepStrictEqual(full(before),full(fs.lstatSync(filename,{bigint:true}))), 'gateway_complete_stable_input_bytes');
  if(pin!==undefined)need(sha(raw)===pin,'gateway_exact_whole_source_or_fixture_pin');
  return raw;
 }finally{row.closeAttempts++;originalFs.closeSync(fd);row.closed=true;}
}
function recordPrivate(name,value){
 need(['selection','empty-config','runtime'].includes(name),'gateway_fixed_private_diagnostic_name');
 const raw=Buffer.from(JSON.stringify(value)+'\n');need(raw.length<=262144,'gateway_bounded_private_diagnostics');
 const fd=originalFs.openSync(ROOT+'/output/'+name+'-diagnostic.private.json',
  fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
 const row={role:'private-synthetic-diagnostic',closeAttempts:0,closed:false};report.fileDescriptors.push(row);
 try{let offset=0;while(offset<raw.length){remainingMs();const n=fs.writeSync(fd,raw,offset,raw.length-offset,null);
  need(n>0,'gateway_private_diagnostic_write_progress');offset+=n;}fs.fsyncSync(fd);}
 finally{row.closeAttempts++;originalFs.closeSync(fd);row.closed=true;}
 const directory=originalFs.openSync(ROOT+'/output',fs.constants.O_RDONLY|fs.constants.O_DIRECTORY|fs.constants.O_NOFOLLOW);
 const dirRow={role:'private-diagnostic-directory',closeAttempts:0,closed:false};report.fileDescriptors.push(dirRow);
 try{fs.fsyncSync(directory);}finally{dirRow.closeAttempts++;originalFs.closeSync(directory);dirRow.closed=true;}
 report.privateDiagnosticFiles.push(name);
}
function sourceFence(){
 for(const [relative,pin]of Object.entries(plan.sdkPins)){
  need(relative.startsWith('dist/')&&!relative.includes('..')&&/^[a-f0-9]{64}$/.test(pin),'gateway_exact_public_sdk_pin_key');
  readPinned(SDK+'/'+relative,pin);
 }
 for(const [relative,pin]of Object.entries(plan.fixturePins)){
  need(!relative.startsWith('/')&&!relative.split('/').includes('..'),'gateway_fixed_fixture_source_relative_path');
  readPinned(ROOT+'/'+relative,pin);
 }
}
async function load(relative){
 need(Object.hasOwn(plan.sdkPins,relative),'gateway_direct_sdk_import_requires_pin');
 readPinned(SDK+'/'+relative,plan.sdkPins[relative]);
 const value=await import(pathToFileURL(SDK+'/'+relative).href);
 report.loadedEntryModules.push(relative);remainingMs();return value;
}
function replace(object,key,value){
 const original=object[key];need(typeof original==='function','gateway_original_guard_target_function');object[key]=value;
 restores.push(()=>{need(object[key]===value,'gateway_original_guard_identity_unchanged');object[key]=original;});
}
function deny(counter,code){return ()=>{report[counter]++;throw new Error(code);};}
async function deniedNetwork(host,port){
 return await new Promise(resolve=>{
  const socket=new net.Socket();let connected=false,error=null;
  const timer=setTimeout(()=>socket.destroy(),remainingMs(750));
  socket.once('error',e=>{error=e.code;socket.destroy();});socket.once('connect',()=>{connected=true;socket.destroy();});
  socket.once('close',()=>{clearTimeout(timer);resolve(!connected&&['EACCES','EPERM'].includes(error));});socket.connect(port,host);
 });
}
function absoluteName(value){return value instanceof URL?fileURLToPath(value):typeof value==='string'?path.resolve(value):null;}
function productionGuard(value){
 const name=absoluteName(value);
 if(name==='/Users/qianqi/.openclaw'||name?.startsWith('/Users/qianqi/.openclaw/')){
  report.forbiddenProductionReadAttempts++;throw new Error('gateway_current_production_file_read_forbidden');
 }
 return name;
}
function writeGuard(value){
 const name=productionGuard(value);
 if(name!==ROOT+'/output'&&!name?.startsWith(ROOT+'/output/')){
  report.forbiddenWriteAttempts++;throw new Error('gateway_mutation_outside_new_private_fixture_forbidden');
 }
}
async function installGuards(){
 for(const [name,flags]of [['protected-read',fs.constants.O_RDONLY],['protected-write',fs.constants.O_WRONLY]]){
  let fd,refused=false;
  try{fd=fs.openSync(ROOT+'/'+name,flags|fs.constants.O_NOFOLLOW);}
  catch(e){refused=['EPERM','EACCES'].includes(e.code);}
  finally{if(fd!==undefined)fs.closeSync(fd);}
  need(refused,'gateway_kernel_protected_file_refused');
 }
 need(await deniedNetwork('127.0.0.1',9)&&await deniedNetwork('203.0.113.1',443),'gateway_kernel_both_network_targets_refused');
 report.kernelReadWriteAndBothNetworkRefusalsObserved=true;report.completedKernelDeniedConnectProbes=2;
 for(const name of ['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork']){
  const original=childProcess[name];
  const blocked=deny('forbiddenChildAttempts','gateway_other_child_process_forbidden');
  if(name!=='execFileSync'){replace(childProcess,name,blocked);continue;}
  replace(childProcess,name,function(file,args,options){
   if(file!=='mount'||!Array.isArray(args)||args.length!==0||options!==undefined)return blocked();
   need(report.allowedReadonlyMountCalls<8,'gateway_finite_original_mount_calls');
   report.allowedReadonlyMountCalls++;
   readPinned('/sbin/mount','e0368cc89f48770e30dcbc639ae4d99d3ee478516b0186baf3e030ce9828e5dd');
   const value=original('/sbin/mount',[],{timeout:remainingMs(3000),maxBuffer:262144,
    stdio:['ignore','pipe','pipe'],env:{PATH:'/usr/bin:/bin:/usr/sbin:/sbin'}});
   report.completedReadonlyMountCalls++;return value;
  });
 }
 for(const object of [fs,fsp]){
  for(const key of ['readFile','readFileSync','createReadStream'])if(typeof object[key]==='function'){
   const original=object[key];replace(object,key,function(file,...args){
    const name=productionGuard(file),value=original.call(this,file,...args);
    if(object===fs&&key==='readFileSync'){
     if(name===STATE+'/.env')report.originalDotenvReads.state++;
     if(name===HOME+'/.config/openclaw/gateway.env')report.originalDotenvReads.gateway++;
    }return value;
   });
  }
  for(const key of ['open','openSync'])if(typeof object[key]==='function'){
   const original=object[key];replace(object,key,function(file,...args){
    productionGuard(file);const flags=args[0],mask=fs.constants.O_WRONLY|fs.constants.O_RDWR|fs.constants.O_CREAT|fs.constants.O_TRUNC|fs.constants.O_APPEND;
    if((typeof flags==='number'&&(flags&mask)!==0)||(typeof flags==='string'&&!/^r[s]?$/.test(flags)))writeGuard(file);
    return original.call(this,file,...args);
   });
  }
  for(const key of ['writeFile','writeFileSync','appendFile','appendFileSync','mkdir','mkdirSync','mkdtemp','mkdtempSync',
   'rm','rmSync','rmdir','rmdirSync','unlink','unlinkSync','chmod','chmodSync','chown','chownSync','truncate','truncateSync','createWriteStream']){
   if(typeof object[key]!=='function')continue;const original=object[key];replace(object,key,function(file,...args){
    if(typeof file!=='number')writeGuard(file);return original.call(this,file,...args);
   });
  }
  for(const key of ['rename','renameSync','copyFile','copyFileSync','cp','cpSync','link','linkSync','symlink','symlinkSync']){
   if(typeof object[key]!=='function')continue;const original=object[key];replace(object,key,function(from,to,...args){
    writeGuard(from);writeGuard(to);return original.call(this,from,to,...args);
   });
  }
 }
 sqliteModule=moduleApi.createRequire(import.meta.url)('node:sqlite');sqliteOriginal=sqliteModule.DatabaseSync;
 replace(sqliteModule,'DatabaseSync',new Proxy(sqliteOriginal,{construct(target,args){
  const [file,options]=args,memory=file===':memory:';report.sqlite.attempts++;
  if(!memory&&file!==STATE+'/state/openclaw.sqlite'){
   report.sqlite.denials++;throw new Error('gateway_sqlite_outside_new_registry_fixture');
  }
  const db=Reflect.construct(target,args,target);const row={ordinal:++report.sqlite.opened,memory,
   readOnly:options?.readOnly===true,closeAttempts:0,closed:false};report.sqlite.connections.push(row);
  const close=db.close.bind(db);Object.defineProperty(db,'close',{value:(...values)=>{
   need(row.closeAttempts===0,'gateway_original_sqlite_close_once');row.closeAttempts++;
   const result=close(...values);row.closed=true;return result;
  }});return db;
 }}));
 const network=deny('forbiddenNetworkAttempts','gateway_runtime_network_forbidden');
 for(const object of [http,https])for(const key of ['request','get'])replace(object,key,network);
 replace(net.Socket.prototype,'connect',network);replace(net.Server.prototype,'listen',network);replace(globalThis,'fetch',network);
 for(const object of [dns,dnsPromises])for(const key of ['lookup','lookupService','resolve','resolve4','resolve6','resolveAny','reverse'])
  if(typeof object[key]==='function')replace(object,key,network);
 need(typeof moduleApi.registerHooks==='function','gateway_actual_node_sync_module_hooks_available');
 moduleHooks=moduleApi.registerHooks({load(url,context,nextLoad){
  if(url===pathToFileURL(AUTHBUS_ROOT+'/index.js').href){report.authbusModuleLoadAttempts++;throw new Error('gateway_disabled_authbus_module_import_forbidden');}
  if(url===pathToFileURL(CONTROL_ROOT+'/index.cjs').href)report.controlModuleLoadAttempts++;
  return nextLoad(url,context);
 }});
 moduleApi.syncBuiltinESMExports();guardsInstalled=true;
}
async function check(id,fn){remainingMs();activeCase=id;await fn();report.cases.push({id,passed:true});activeCase=null;}
try{
 need(process.platform==='darwin'&&process.getuid()===501&&budget>0&&budget<=30000,'gateway_original_mac_and_bounded_worker');
 need(process.env.HOME===HOME&&process.env.OPENCLAW_STATE_DIR===STATE&&process.env.OPENCLAW_CONFIG_PATH===CONFIG,
  'gateway_explicit_child_environment_before_import');
 plan=JSON.parse(readPinned(ROOT+'/code/plan.public.json',undefined,131072));
 need(plan.schema==='heptabao.gateway-selectors-registration.synthetic-plan.r2'&&plan.expectedCases===15,
  'gateway_exact_qualification_plan');
 for(const required of ['dist/pre-bootstrap-8G8HyMEQ.js','dist/config/config.js','dist/io-By0s-a_s.js',
  'dist/paths-C6ahtu79.js','dist/paths-BMBAvkNf.js','dist/loader-D8d2EvVh.js','dist/server-plugin-bootstrap-CtU_XTUf.js',
  'dist/server-plugins-XoQmHCe9.js','dist/manifest-registry--UiRn6nq.js','dist/runtime-D0xGMZdc.js',
  'dist/hook-runner-global-BmIrGlLG.js','dist/openclaw-state-db-DzSsA9Ji.js'])
  need(Object.hasOwn(plan.sdkPins,required),'gateway_required_original_source_bound');
 process.stdout.write=value=>{diagnosticBytes+=Buffer.byteLength(String(value));return true;};
 process.stderr.write=value=>{diagnosticBytes+=Buffer.byteLength(String(value));return true;};
 sourceFence();
 await check('K01_kernel_guards_and_private_fixture_scope',installGuards);
 stateApi=await load('dist/openclaw-state-db-DzSsA9Ji.js');
 await runGatewayCases({check,need,report,load,sourceFence,recordPrivate});
 need(report.cases.length===15&&['forbiddenChildAttempts','forbiddenNetworkAttempts','forbiddenProductionReadAttempts',
  'forbiddenWriteAttempts','authbusModuleLoadAttempts'].every(key=>report[key]===0)
  &&report.sqlite.denials===0&&report.allowedReadonlyMountCalls===report.completedReadonlyMountCalls,
  'gateway_all_original_cases_and_no_unexpected_effects');
 sourceFence();remainingMs();report.ok=true;
}catch(error){
 report.errorCode=codes.has(error?.message)?error.message:'gateway_selector_or_registration_qualification_refused';
 report.errorType=error?.constructor?.name??'Error';report.failedCase=activeCase;report.ok=false;
 try{
  const fd=originalFs.openSync(ROOT+'/output/qualification-error.private.txt',fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
  try{originalFs.writeFileSync(fd,String(error?.stack??error));fs.fsyncSync(fd);privateErrorSaved=true;}finally{originalFs.closeSync(fd);}
 }catch{}
}finally{
 if(stateApi){try{stateApi.n();report.originalStateCacheCloseInvocations=1;}catch{report.ok=false;report.originalStateCacheCloseFailed=true;}}
 report.sqlite.allOriginalHandlesClosedOnce=report.sqlite.connections.every(row=>row.closeAttempts===1&&row.closed);
 if(!report.sqlite.allOriginalHandlesClosedOnce||report.sqlite.denials)report.ok=false;
 if(moduleHooks){try{moduleHooks.deregister();hooksDeregistered=true;}catch{report.ok=false;}}
 let restored=true;for(const restore of restores.reverse()){try{restore();}catch{restored=false;}}
 try{moduleApi.syncBuiltinESMExports();}catch{restored=false;}
 process.stdout.write=originalOut;process.stderr.write=originalErr;
 report.guardsInstalled=guardsInstalled;report.allInstalledGuardsRestored=restored;
 report.originalModuleHookDeregistered=hooksDeregistered;
 report.suppressedDiagnosticBytes=diagnosticBytes;report.privateFailureDetailsSaved=privateErrorSaved;
 report.allRecordedFileDescriptorsClosedOnce=report.fileDescriptors.every(row=>row.closeAttempts===1&&row.closed);
 report.executed=report.cases.length+(activeCase?1:0);report.passed=report.cases.length;
 report.elapsedSeconds=Number(process.hrtime.bigint()-started)/1e9;
 report.sdkSourcePins=plan?.sdkPins??{};
 if(!restored||!hooksDeregistered||!report.allRecordedFileDescriptorsClosedOnce||process.hrtime.bigint()>=until)report.ok=false;
 output(JSON.stringify(report)+'\n');
}
process.exitCode=report.ok?0:1;
