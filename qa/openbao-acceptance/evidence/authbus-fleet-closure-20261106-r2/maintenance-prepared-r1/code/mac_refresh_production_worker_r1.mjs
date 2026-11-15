#!/usr/bin/env node
/** One real selected-owner refresh, only as the original maintenance child.
 *
 * This worker is prepared source, not an executed refresh. Its private stdin
 * comes directly from the original Mac parent after a new qualified capture.
 * Two explicit descriptors are original inherited request/response pipes. Every writer check is
 * a synchronous request to that still-owning parent, not a status-file receipt.
 * The parent must execute the bound launchd and current consumer checks and may not
 * reply from a cached boolean. Parent custody and its absolute deadline remain
 * authoritative while a synchronous pipe read is pending.
 */
import fs from 'node:fs';
import path from 'node:path';
import {isDeepStrictEqual} from 'node:util';
import {openPrivateOnceLedger,bindMain3RefreshOnce,FIXED_LEDGER_ROOT,FIXED_STATE_ROOT}
 from './mac_refresh_once_controller_r2.mjs';
import {bindObservedGeneration} from './mac_refresh_generation_fence_r2.mjs';
import {loadQualifiedMacProvider} from './mac_refresh_provider_hooks_r2.mjs';
import {loadQualifiedMacSdkMutex} from './mac_sdk_refresh_mutex_r3.mjs';
import {loadActualMacRawSdk,bindSdkRawOwnerCas} from './mac_sdk_raw_owner_cas_r1.mjs';

export const ROOT='/Users/qianqi/heptabao-authbus-writer-maintenance-20261106-r1';
export const NODE='/opt/homebrew/Cellar/node/25.9.0_1/bin/node';
const MAX_INPUT=2*1048576;
const MAX_MESSAGE=4096;
const STAGES=new Set(['before-lock','under-lock','after-current-owner-read','intent-durable',
 'provider-preparation','before-dispatch-record','final-native-send','after-provider-return',
 'before-original-owner-cas','after-own-commit','before-read','after-read',
 'before-write-open','before-begin','after-commit','after-readback','worker-before-retirement']);
const FORBIDDEN_ENV=['NODE_OPTIONS','NODE_PATH','NODE_EXTRA_CA_CERTS','NODE_TLS_REJECT_UNAUTHORIZED',
 'HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy',
 'OPENCLAW_TEST_FAST','VITEST','OPENCLAW_GATEWAY_MINIMAL',
 'OPENCLAW_ALLOW_OLDER_BINARY_DESTRUCTIVE_ACTIONS'];

export class WorkerRefused extends Error{
 constructor(code){super(code);this.name='WorkerRefused';this.code=code;}
}
function need(value,code){if(!value)throw new WorkerRefused(code);}
function plain(value){return value!==null&&typeof value==='object'&&!Array.isArray(value)
 &&Object.getPrototypeOf(value)===Object.prototype;}
function exactKeys(value,keys){return plain(value)&&isDeepStrictEqual(Object.keys(value).sort(),[...keys].sort());}
function full(value){return ['dev','ino','uid','gid','mode','nlink','size','mtimeNs','ctimeNs'].map(key=>String(value[key]));}
function first5(value){return full(value).slice(0,5);}
function typedFull(value,size=9){return Array.isArray(value)&&value.length===size&&value.every(item=>
 typeof item==='string'&&/^[0-9]{1,30}$/.test(item));}
function fixedCode(error){const code=error?.code;
 return typeof code==='string'&&/^(refresh_once|generation|provider|sdk_mutex|worker)_[a-z0-9_]{1,100}$/.test(code)
  ?code:'worker_original_refresh_or_io_refused';}

/** Validate the private direct-parent handoff before any SDK import or lock. */
export function validatePrivateInput(value){
 need(exactKeys(value,['schema','ordinal','remainingMilliseconds','parentPid','parentNonce',
  'channels','capsulePath','capsuleIdentity','capsuleBytesBase64']), 'worker_exact_private_input_fields');
 need(value.schema==='heptabao.main3-refresh-original-worker.private.r1'
  &&Number.isInteger(value.ordinal)&&value.ordinal>=0&&value.ordinal<3
  &&Number.isInteger(value.remainingMilliseconds)&&value.remainingMilliseconds>0&&value.remainingMilliseconds<=120000
  &&Number.isInteger(value.parentPid)&&value.parentPid>1
  &&typeof value.parentNonce==='string'&&/^[a-f0-9]{64}$/.test(value.parentNonce),
  'worker_fixed_original_scope_and_budget');
 need(exactKeys(value.channels,['request','response'])
  &&Object.values(value.channels).every(row=>exactKeys(row,['descriptor','identity'])
   &&Number.isInteger(row.descriptor)&&row.descriptor>=3&&row.descriptor<=65535&&typedFull(row.identity,5))
  &&value.channels.request.descriptor!==value.channels.response.descriptor
  &&!isDeepStrictEqual(value.channels.request.identity,value.channels.response.identity),
  'worker_distinct_original_channel_bindings');
 need(typeof value.capsulePath==='string'&&path.normalize(value.capsulePath)===value.capsulePath
  &&value.capsulePath.startsWith(ROOT+'/captures/')&&/^owner-0[123]\/output\/selected-owner-credentials\.private\.json$/
   .test(value.capsulePath.slice((ROOT+'/captures/').length))
  &&value.capsulePath.startsWith(ROOT+'/captures/owner-0'+(value.ordinal+1)+'/'),
  'worker_fixed_fresh_ordinal_capture_path');
 need(typedFull(value.capsuleIdentity)&&typeof value.capsuleBytesBase64==='string'
  &&value.capsuleBytesBase64.length>0&&value.capsuleBytesBase64.length<=1398104
  &&/^[A-Za-z0-9+/]*={0,2}$/.test(value.capsuleBytesBase64), 'worker_bounded_private_capsule_handoff');
 const bytes=Buffer.from(value.capsuleBytesBase64,'base64');
 need(bytes.length>0&&bytes.length<=1048576&&bytes.toString('base64')===value.capsuleBytesBase64
  &&BigInt(value.capsuleIdentity[6])===BigInt(bytes.length), 'worker_canonical_complete_private_capsule_bytes');
 return bytes;
}

/** A synchronous direct-parent authority channel. There is no retry or file
 * fallback. A pending original read stays bounded by the owning supervisor. */
export function bindWriterChannel({input,until,io=fs,clock=()=>process.hrtime.bigint(),
 parentPid=()=>process.ppid},report={}){
 let closed=false,failed=false,sequence=0;
 const requestFd=input.channels.request.descriptor,responseFd=input.channels.response.descriptor;
 const rows=[{fd:requestFd,expected:input.channels.request.identity,closed:false,closeAttempts:0},
             {fd:responseFd,expected:input.channels.response.identity,closed:false,closeAttempts:0}];
 Object.assign(report,{schema:'heptabao.refresh-original-parent-writer-channel.public.r1',
  requests:0,completeAuthorizations:0,completeRefusals:0,automaticRetries:0,authorityReadFromStatusFile:false,
  originalInheritedPipes:true,originalParentPid:input.parentPid,valuesOrDigestsPublished:false});
 const check=()=>{
  need(!closed&&!failed&&clock()<until&&parentPid()===input.parentPid,'worker_original_writer_channel_lifetime');
  for(const row of rows){const info=io.fstatSync(row.fd,{bigint:true});
   need(info.isFIFO()&&info.uid===501n&&isDeepStrictEqual(first5(info),row.expected),
    'worker_original_parent_pipe_identity');}
 };
 const retire=()=>{
  closed=true;
  for(const row of [...rows].reverse())if(!row.closeAttempts){
   row.closeAttempts++;
   try{io.closeSync(row.fd);row.closed=true;}catch{report.closeUnknown=true;}
  }
  report.allOriginalPipesClosedOnce=rows.every(row=>row.closed&&row.closeAttempts===1);
  report.originalPipeCloseAttempts=rows.reduce((n,row)=>n+row.closeAttempts,0);
  report.sequenceFailed=failed;
 };
 const api={
  verify(_observed,stage){
   let attempted=false,responseKnown=false;
   try{
    check();need(STAGES.has(stage)&&sequence<96,'worker_finite_original_writer_check_stage');
    const current=sequence++;report.requests++;
    const request=Buffer.from(JSON.stringify({schema:'heptabao.refresh-writer-check.private.r1',
     nonce:input.parentNonce,sequence:current,ordinal:input.ordinal,stage})+'\n');
    need(request.length<=MAX_MESSAGE,'worker_bounded_writer_request');
    let offset=0;
    while(offset<request.length){check();attempted=true;
     const n=io.writeSync(requestFd,request,offset,request.length-offset,null);
     need(Number.isInteger(n)&&n>0&&n<=request.length-offset,'worker_original_writer_pipe_write_progress');offset+=n;}
    const parts=[];let total=0,complete=false;
    while(!complete){
     check();const block=Buffer.alloc(Math.min(1024,MAX_MESSAGE+1-total));
     const n=io.readSync(responseFd,block,0,block.length,null);
     need(Number.isInteger(n)&&n>0&&n<=block.length,'worker_original_parent_response_not_eof');
     const part=block.subarray(0,n);parts.push(part);total+=n;
     need(total<=MAX_MESSAGE,'worker_bounded_parent_response');
     const newline=part.indexOf(10);
     if(newline>=0){need(newline===part.length-1,'worker_single_complete_parent_response');complete=true;}
    }
    check();const raw=Buffer.concat(parts,total),response=JSON.parse(raw.toString('utf8'));
    need(exactKeys(response,['schema','nonce','sequence','ordinal','stage','allowed'])
     &&response.schema==='heptabao.refresh-writer-check.private.r1'
     &&response.nonce===input.parentNonce&&response.sequence===current
     &&response.ordinal===input.ordinal&&response.stage===stage&&typeof response.allowed==='boolean'
     &&raw.equals(Buffer.from(JSON.stringify({schema:response.schema,nonce:response.nonce,
      sequence:response.sequence,ordinal:response.ordinal,stage:response.stage,allowed:response.allowed})+'\n')),
     'worker_exact_original_parent_authorization');
    responseKnown=true;
    if(!response.allowed){report.completeRefusals++;throw new WorkerRefused('worker_original_parent_refused');}
    report.completeAuthorizations++;return true;
   }catch(error){failed=true;report.outcomeUnknown=report.outcomeUnknown===true||(attempted&&!responseKnown);
    report.failureBeforeRequestDispatch=report.failureBeforeRequestDispatch===true||!attempted;throw error;}
  },
  close(){
   need(!closed,'worker_writer_channel_close_once');retire();
   need(report.allOriginalPipesClosedOnce,'worker_original_parent_channel_close_unknown');
  }
 };
 try{check();return Object.freeze(api);}
 catch(error){failed=true;report.initialAdmissionFailed=true;retire();throw error;}
}

function readOriginalInput(){
 const chunks=[];let total=0;
 for(;;){const block=Buffer.alloc(Math.min(65536,MAX_INPUT+1-total));
  const n=fs.readSync(0,block,0,block.length,null);if(!n)break;
  total+=n;need(total<=MAX_INPUT,'worker_bounded_original_stdin');chunks.push(block.subarray(0,n));}
 need(total>0,'worker_complete_original_private_stdin');
 return JSON.parse(Buffer.concat(chunks,total).toString('utf8'));
}

function privateDiagnostic(ordinal,raw,report){
 need(Buffer.isBuffer(raw)&&raw.length<=262144,'worker_bounded_private_diagnostic');
 if(!raw.length)return;
 const filename=ROOT+'/output/owner-0'+(ordinal+1)+'.diagnostic.private.bin';
 const rows=[],parents=[];
 const close=row=>{row.closeAttempts++;try{fs.closeSync(row.fd);row.closed=true;}catch{report.diagnosticCloseUnknown=true;}};
 const verifyParents=()=>{
  for(const row of parents){
   const width=row.filename===ROOT+'/output'?5:9;
   need(!row.closeAttempts&&isDeepStrictEqual(full(fs.fstatSync(row.fd,{bigint:true})).slice(0,width),row.identity.slice(0,width))
    &&isDeepStrictEqual(full(fs.lstatSync(row.filename,{bigint:true})).slice(0,width),row.identity.slice(0,width)),
    'worker_original_private_diagnostic_parent_identity');
  }
 };
 try{
  const chain=[];
  for(let p=ROOT+'/output';;p=path.dirname(p)){chain.unshift(p);if(p===path.dirname(p))break;}
  for(const filename of chain){
   const fd=fs.openSync(filename,fs.constants.O_RDONLY|fs.constants.O_DIRECTORY|fs.constants.O_NOFOLLOW);
   const row={fd,filename,closeAttempts:0,closed:false};rows.push(row);parents.push(row);
   const value=fs.fstatSync(fd,{bigint:true});row.identity=full(value);
   need(value.isDirectory()&&[0n,501n].includes(value.uid)&&(value.mode&18n)===0n
    &&isDeepStrictEqual(row.identity,full(fs.lstatSync(filename,{bigint:true}))),
    'worker_private_diagnostic_parent_custody');
   if(filename===ROOT||filename===ROOT+'/output')need(value.uid===501n&&(value.mode&511n)===448n,
    'worker_staged_private_diagnostic_directory');
  }
  verifyParents();
  const fd=fs.openSync(filename,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
  const row={fd,closeAttempts:0,closed:false};rows.push(row);
  const before=fs.fstatSync(fd,{bigint:true});
  need(before.isFile()&&before.uid===501n&&before.nlink===1n&&(before.mode&511n)===384n,
   'worker_owned_private_diagnostic_file');
  let offset=0;while(offset<raw.length){const n=fs.writeSync(fd,raw,offset,raw.length-offset,null);
   need(n>0,'worker_diagnostic_write_progress');offset+=n;}
  fs.fsyncSync(fd);
  const after=fs.fstatSync(fd,{bigint:true});
  need(isDeepStrictEqual(first5(before),first5(after))&&after.nlink===1n&&after.size===BigInt(raw.length)
   &&isDeepStrictEqual(full(after),full(fs.lstatSync(filename,{bigint:true}))),
   'worker_complete_original_private_diagnostic_file');
  verifyParents();close(row);fs.fsyncSync(parents.at(-1).fd);verifyParents();
  report.privateDiagnosticsDurable=true;
 }finally{
  for(const row of rows)if(!row.closeAttempts)close(row);
  report.allDiagnosticDescriptorsClosedOnce=rows.every(row=>row.closed&&row.closeAttempts===1);
 }
}

/** Actual joined components, one owner only. All arguments remain private. */
export async function runOriginalWorker(input,report={}){
 const started=process.hrtime.bigint(),capsule=validatePrivateInput(input);
 need(process.platform==='darwin'&&process.getuid()===501&&process.execPath===NODE
  &&process.umask()===0o077&&process.ppid===input.parentPid,
  'worker_actual_mac_node_original_parent');
 need(process.env.HOME==='/Users/qianqi'&&process.env.OPENCLAW_STATE_DIR===FIXED_STATE_ROOT
  &&process.env.TMPDIR===ROOT+'/output/tmp'&&FORBIDDEN_ENV.every(key=>process.env[key]===undefined),
  'worker_closed_original_environment');
 const until=started+BigInt(input.remainingMilliseconds)*1000000n;
 Object.assign(report,{schema:'heptabao.actual-main3-refresh-worker.public.r1',ok:false,ordinal:input.ordinal,
  oneOriginalOwnerOnly:true,originalPhaseMaximumMilliseconds:120000,originalHttpMaximumMilliseconds:30000,
  productionTrafficSwitched:false,gatewayRestorationAuthorized:false,
  credentialValuesOrDigestsPublished:false,configurationValuesOrDigestsPublished:false,
  originalStdinComplete:true,providerHook:{},generation:{},writerChannel:{},ledger:{},once:{},
  sourceLoaderClosuresKnown:false});
 let provider=null,generation=null,channel=null,ledger=null,primary=null,providerLoadAttempted=false;
 const originalOut=process.stdout.write,originalErr=process.stderr.write;
 const diagnostics=[];let diagnosticBytes=0;
 const suppress=(value,encoding,callback)=>{const bytes=Buffer.isBuffer(value)?value:Buffer.from(String(value),
   typeof encoding==='string'?encoding:'utf8');
  diagnosticBytes+=bytes.length;
  if(diagnosticBytes<=262144)diagnostics.push(Buffer.from(bytes));
  else report.privateDiagnosticsOverflow=true;
  const completed=typeof encoding==='function'?encoding:callback;
  if(typeof completed==='function')queueMicrotask(()=>completed());
  return true;
 };
 process.stdout.write=suppress;process.stderr.write=suppress;
 try{
  channel=bindWriterChannel({input,until},report.writerChannel);
  // The provider loader installs exact source overlays before *any* SDK
  // import. Its lazy native transport is still absent until its original flow.
  providerLoadAttempted=true;provider=await loadQualifiedMacProvider(report.providerHook);
  const rawSdk=await loadActualMacRawSdk(),mutex=await loadQualifiedMacSdkMutex();
  generation=bindObservedGeneration({stateRoot:FIXED_STATE_ROOT,capsulePath:input.capsulePath,
   expectedCapsuleIdentity:input.capsuleIdentity,expectedCapsuleBytes:capsule,until,uid:501},report.generation);
  const scope={schema:'heptabao.main3-once-private-scope.r1',provider:'openai',stateRoot:FIXED_STATE_ROOT,
   ownerDir:path.join(FIXED_STATE_ROOT,'agents/main/agent'),profileIds:[...generation.profileIds]};
  ledger=openPrivateOnceLedger({root:FIXED_LEDGER_ROOT,scope,uid:501},report.ledger);
  const rawFactory=({observed,assertResponse})=>{
   let activeReceipt=null;
   const raw=bindSdkRawOwnerCas({sdk:rawSdk.sdk,sqlite:rawSdk.sqlite,sourceFence:rawSdk.sourceFence,
    ownerDir:scope.ownerDir,assertResponse,
    admit(stage,databasePath){
     need(activeReceipt!==null,'worker_original_raw_receipt_bound');
     channel.verify(observed,stage);generation.admit(stage,databasePath,activeReceipt);
    }});
   return Object.freeze({
    readBefore(deadline,receipt){activeReceipt=receipt;return raw.readBefore(deadline,receipt);},
    apply(parameters,receipt){activeReceipt=receipt;return raw.apply(parameters,receipt);}
   });
  };
  const controller=bindMain3RefreshOnce({scope,ledger,mutex,source:generation.source,
   writer:channel,rawFactory,provider});
  await controller.runOne({ordinal:input.ordinal,until},report.once);
  need(report.once.ok===true&&report.once.localOwnerCommitKnown===true
   &&report.once.knownTerminalPrivateRecord===true&&report.once.outcomeUnknown===false,
   'worker_original_committed_once_required');
  channel.verify(null,'worker-before-retirement');
  report.ok=true;
 }catch(error){primary=error;report.errorCode=fixedCode(error);report.ok=false;}
 finally{
  // The core intentionally never returns through here for an unclosed native
  // transport. The original parent owns that deadline/UNKNOWN reconciliation.
  let known=true;
  if(provider){try{need(provider.contextIsClosed(),'worker_provider_context_still_open');provider.dispose();}
   catch{known=false;report.providerLoaderClosureUnknown=true;}}
  else if(providerLoadAttempted&&report.providerHook.disposed!==true){known=false;report.providerLoaderClosureUnknown=true;}
  if(generation){try{generation.close();}catch{known=false;report.generationClosureUnknown=true;}}
  else if(report.generation.schema&&report.generation.allOwnedDescriptorsClosedOnce!==true){known=false;report.generationClosureUnknown=true;}
  if(ledger){try{ledger.close();}catch{known=false;report.ledgerClosureUnknown=true;}}
  else if(report.ledger.schema&&report.ledger.allOwnedDescriptorsClosedOnce!==true){known=false;report.ledgerClosureUnknown=true;}
  if(channel){try{channel.close();}catch{known=false;report.parentChannelClosureUnknown=true;}}
  else if(report.writerChannel.schema&&report.writerChannel.allOriginalPipesClosedOnce!==true){known=false;report.parentChannelClosureUnknown=true;}
  report.suppressedPrivateDiagnosticBytes=diagnosticBytes;
  try{privateDiagnostic(input.ordinal,Buffer.concat(diagnostics),report);}catch{report.privateDiagnosticPublicationUnknown=true;known=false;}
  report.sourceLoaderClosuresKnown=known;
  process.stdout.write=originalOut;process.stderr.write=originalErr;
  report.outputHooksRestored=process.stdout.write===originalOut&&process.stderr.write===originalErr;
  report.elapsedSeconds=Number(process.hrtime.bigint()-started)/1e9;
  if(!known||!report.outputHooksRestored||report.privateDiagnosticsOverflow
   ||report.allDiagnosticDescriptorsClosedOnce===false||process.hrtime.bigint()>=until)report.ok=false;
  report.newFreshCaptureRequiredBeforeAnyNextOrdinal=true;
  report.originalParentCustodyStillRequired=true;
  report.providerApplicationLivenessProven=false;
 }
 if(primary)throw new WorkerRefused(report.errorCode);
 need(report.ok,'worker_original_effect_or_closure_unfinished');return report;
}

// A direct invocation must be staged at the one production code path. Importing
// this module for pure channel/input tests performs no I/O or provider call.
if(process.argv[1]===ROOT+'/code/mac_refresh_production_worker_r1.mjs'){
 const report={schema:'heptabao.actual-main3-refresh-worker.public.r1',ok:false};
 const out=process.stdout.write.bind(process.stdout);
 try{await runOriginalWorker(readOriginalInput(),report);}
 catch(error){report.ok=false;report.errorCode=fixedCode(error);}
 out(JSON.stringify(report)+'\n');process.exitCode=report.ok?0:1;
}
