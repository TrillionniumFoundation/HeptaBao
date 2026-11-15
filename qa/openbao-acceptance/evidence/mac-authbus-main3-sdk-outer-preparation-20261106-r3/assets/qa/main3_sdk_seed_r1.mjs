#!/usr/bin/env node
/** Build private AuthBus wire objects with the pinned plugin's actual pure
 * digest and validation functions. No SDK import, provider or database access.
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import net from 'node:net';
import {fileURLToPath} from 'node:url';

const ROOT='/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-main3-sdk-20261106-r3';
const INDEX_SHA='b19b6a9e7c1d57ccef8d67994ed3421891788ac30a82ff6bad2eef2ef7e30f9b';
const hash=raw=>crypto.createHash('sha256').update(raw).digest('hex');
const need=(value,code)=>{if(!value)throw Object.assign(new Error(code),{safeCode:code});};
const identity=s=>['dev','ino','uid','gid','mode','nlink','size','mtimeNs','ctimeNs'].map(k=>String(s[k])).join(':');
const AGENTS=['main','trnm','hepta-ui','hepta','hepta-backend'];

export function buildPrivateSeed(index,capsule){
  need(typeof index==='string'&&hash(Buffer.from(index))===INDEX_SHA,'seed_exact_original_plugin');
  const start='function isRecord(value) {',end='class BaoClient {';
  need(index.split(start).length===2&&index.split(end).length===2,'seed_unique_pure_source_region');
  const region=index.slice(index.indexOf(start),index.indexOf(end));
  const pure=new Function('crypto',region+'\nreturn {credentialDigest,identityDigest,validCredential};')(crypto);
  need(capsule?.schema==='heptabao.actual-sdk-selected-owner-credentials.private.r1'&&capsule.host==='mac'&&
    capsule.constraints?.selectedOwnerCount===3&&capsule.constraints?.containsUnselectedCredentials===false&&
    Array.isArray(capsule.ownerEntries)&&capsule.ownerEntries.length===3,'seed_exact_current_capsule');
  const ids=new Set(),profiles=[],payloads=[],managedProfiles=[];
  for(const [i,entry]of capsule.ownerEntries.entries()){
    need(entry.ownerAgent==='main'&&entry.actualProvider==='openai'&&entry.credential?.type==='oauth'&&
      entry.credential.provider==='openai'&&pure.validCredential(entry.profileId,entry.credential)&&
      !ids.has(entry.profileId),'seed_three_distinct_actual_owner_objects');
    ids.add(entry.profileId);
    const key='selected-main-'+(i+1),digest=pure.credentialDigest(entry.credential),
      identity=pure.identityDigest(entry.credential);
    profiles.push({profileId:entry.profileId,key,digest,identity});
    payloads.push({key,data:{profileId:entry.profileId,credential:entry.credential,digest,identity}});
    managedProfiles.push({profileId:entry.profileId,key,credential:entry.credential});
  }
  return {schema:'heptabao.mac-main3-authbus-seed.private.r1',managedProfiles,payloads,
    manifest:{schemaVersion:1,generation:1,profiles},
    orderPolicy:{schemaVersion:1,generation:1,providers:{openai:{
      candidates:profiles.map(row=>({profileId:row.profileId,digest:row.digest,enrolledAt:0})),
      activeProfile:profiles[0].profileId,enforceManagedOrder:true}}},
    schedulerAssignments:{schemaVersion:1,generation:1,scopes:[],assignments:[],refreshLeases:[]},
    syntheticControlPolicy:true,actualCentralOrderPolicyCopied:false,agents:AGENTS};
}

async function main(){
  const started=process.hrtime.bigint();let until=started+10000000000n,opened=0,closed=0;
  const report={schema:'heptabao.mac-main3-authbus-seed.public.r1',ok:false,providerCalled:false,
    sqliteOpened:false,productionWrites:0,credentialValuesOrDigestsPublished:false,profileIdsPublished:false};
  const left=cap=>{const remaining=Number((until-process.hrtime.bigint())/1000000n);
    need(remaining>0,'seed_original_phase_deadline');return Math.min(cap,remaining);};
  function read(file,maximum,privateFile){
    left(1);const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);opened++;
    try{
      const before=fs.fstatSync(fd,{bigint:true});
      need(before.isFile()&&before.uid===501n&&before.nlink===1n&&(before.mode&511n)===384n&&
        before.size>0n&&before.size<=BigInt(maximum),'seed_private_input_custody');
      const data=Buffer.alloc(Number(before.size)+1);let count=0;
      while(count<data.length){left(1);const n=fs.readSync(fd,data,count,data.length-count,null);if(!n)break;count+=n;}
      need(BigInt(count)===before.size&&identity(before)===identity(fs.fstatSync(fd,{bigint:true}))&&
        identity(before)===identity(fs.lstatSync(file,{bigint:true})),'seed_stable_bounded_whole_file');
      return data.subarray(0,count);
    }finally{fs.closeSync(fd);closed++;}
  }
  try{
    process.umask(0o077);
    need(process.platform==='darwin'&&process.getuid()===501&&process.argv.length===3&&
      process.argv[2]===ROOT+'/input/seed-plan.private.json'&&
      fileURLToPath(import.meta.url)===ROOT+'/qa/main3_sdk_seed_r1.mjs','seed_exact_mac_entry');
    for(const [name,flag]of [['protected-read',fs.constants.O_RDONLY],['protected-write',fs.constants.O_WRONLY]]){
      let fd,denied=false;try{fd=fs.openSync(ROOT+'/'+name,flag|fs.constants.O_NOFOLLOW);}
      catch(error){denied=['EPERM','EACCES'].includes(error.code);}finally{if(fd!==undefined)fs.closeSync(fd);}
      need(denied,'seed_actual_kernel_file_refusal');
    }
    const denied=await new Promise(resolve=>{
      const socket=new net.Socket();let code=null,connected=false;
      const timer=setTimeout(()=>socket.destroy(),left(750));
      socket.once('error',error=>{code=error.code;socket.destroy();});
      socket.once('connect',()=>{connected=true;socket.destroy();});
      socket.once('close',()=>{clearTimeout(timer);resolve(!connected&&['EPERM','EACCES'].includes(code));});
      socket.connect(9,'127.0.0.1');
    });need(denied,'seed_actual_kernel_network_refusal');
    const plan=JSON.parse(read(process.argv[2],65536,true));
    need(plan.schema==='heptabao.mac-main3-seed-plan.private.r1'&&plan.parentPid===process.ppid&&
      Number.isSafeInteger(plan.remainingMs)&&plan.remainingMs>0&&plan.remainingMs<=10000,
      'seed_original_parent_allocation');
    until=started+BigInt(plan.remainingMs)*1000000n;left(1);
    const capsule=JSON.parse(read(ROOT+'/input/selected-main3.private.json',1048576,true));
    const index=read(ROOT+'/plugin/index.js',1048576,false).toString('utf8');
    const seed=buildPrivateSeed(index,capsule),raw=Buffer.from(JSON.stringify(seed)+'\n');
    need(raw.length<=1048576,'seed_bounded_private_wire_packet');
    const parent=ROOT+'/private',s=fs.lstatSync(parent,{bigint:true});
    need(s.isDirectory()&&s.uid===501n&&(s.mode&511n)===448n&&fs.realpathSync(parent)===parent,
      'seed_owned_output_directory');
    const fd=fs.openSync(parent+'/seed.private.json',fs.constants.O_CREAT|fs.constants.O_EXCL|
      fs.constants.O_WRONLY|fs.constants.O_NOFOLLOW,0o600);opened++;
    try{fs.writeFileSync(fd,raw);fs.fsyncSync(fd);}finally{fs.closeSync(fd);closed++;}
    const directory=fs.openSync(parent,fs.constants.O_RDONLY|fs.constants.O_DIRECTORY|fs.constants.O_NOFOLLOW);opened++;
    try{fs.fsyncSync(directory);}finally{fs.closeSync(directory);closed++;}
    left(1);report.ok=true;report.selectedOwnerCount=3;report.actualPluginPureFunctionsExecuted=true;
    report.kernelReadWriteNetworkRefusalsObserved=true;report.privateWirePacketSaved=true;
  }catch(error){report.errorCode=/^[a-z][a-z0-9_.-]{1,100}$/.test(error?.safeCode??'')?error.safeCode:'seed_refused';}
  report.openedDescriptors=opened;report.closedDescriptors=closed;report.allOwnedDescriptorsClosed=opened===closed;
  report.elapsedMs=Number((process.hrtime.bigint()-started)/1000000n);
  if(opened!==closed||process.hrtime.bigint()>=until)report.ok=false;
  process.stdout.write(JSON.stringify(report)+'\n');process.exitCode=report.ok?0:1;
}
if(process.argv[1]&&fileURLToPath(import.meta.url)===path.resolve(process.argv[1]))await main();
