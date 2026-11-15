#!/usr/bin/env node
/** Actual installed SDK policy/path compatibility, never a gateway process. */
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import net from "node:net";
import http from "node:http";
import https from "node:https";
import dns from "node:dns";
import dnsPromises from "node:dns/promises";
import childProcess from "node:child_process";
import {createRequire,syncBuiltinESMExports} from "node:module";
import {isDeepStrictEqual} from "node:util";
import {ROOT,SDK_ROOT,SDK_PINS,runOriginalSdkCases} from "./mac_gateway_fallback_sdk_cases_r1.mjs";

const started=process.hrtime.bigint(),budget=Number(process.argv[2]);
const until=started+BigInt(Math.trunc(budget*1000000));
const report={schema:"heptabao.actual-mac-gateway-fallback-sdk-policy-qualification.r1",ok:false,
 actualInstalledSdk:true,syntheticConfigurationOnly:true,productionCredentialReads:0,
 productionWrites:0,actualProviderCalls:0,networkRequests:0,serviceMutations:0,
 productionMutexAcquired:false,productionOnceLedgerOpened:false,
 cases:[],fileDescriptors:[],childAttempts:0,sqliteAttempts:0,mutationAttempts:0,
 networkAttempts:0,productionReadAttempts:0};
const emit=process.stdout.write.bind(process.stdout),oldOut=process.stdout.write,oldErr=process.stderr.write;
const codes=new Set(),restores=[];
let activeCase=null,suppressedDiagnostics=0,guardsInstalled=false;
function need(value,code){if(!value){codes.add(code);throw new Error(code);}}
function remaining(){need(process.hrtime.bigint()<until,"fallback_sdk_original_deadline");}
function full(s){return ["dev","ino","uid","gid","mode","nlink","size","mtimeNs","ctimeNs"].map(k=>String(s[k]));}
function sourceFence(){
 for(const [relative,pin]of Object.entries(SDK_PINS)){
  remaining();const filename=path.join(SDK_ROOT,relative);
  const fd=fs.openSync(filename,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
  const row={kind:"public-source",closeAttempts:0,closed:false};report.fileDescriptors.push(row);
  try{
   const before=fs.fstatSync(fd,{bigint:true});
   need(before.isFile()&&before.nlink===1n&&[0n,501n].includes(before.uid)&&(before.mode&18n)===0n
    &&before.size>0n&&before.size<=1048576n,"fallback_sdk_public_source_custody");
   const raw=Buffer.alloc(Number(before.size)+1);let offset=0;
   while(offset<raw.length){remaining();const n=fs.readSync(fd,raw,offset,raw.length-offset,null);if(!n)break;offset+=n;}
   need(offset===Number(before.size)&&isDeepStrictEqual(full(before),full(fs.fstatSync(fd,{bigint:true})))
    &&isDeepStrictEqual(full(before),full(fs.lstatSync(filename,{bigint:true})))
    &&crypto.createHash("sha256").update(raw.subarray(0,offset)).digest("hex")===pin,
    "fallback_sdk_current_whole_public_source_pin");
  }finally{row.closeAttempts++;fs.closeSync(fd);row.closed=true;}
 }
}
async function deniedNetwork(host,port){
 return await new Promise(resolve=>{
  const socket=new net.Socket();let error=null,connected=false;
  const timer=setTimeout(()=>socket.destroy(),Math.min(750,Math.max(1,Number((until-process.hrtime.bigint())/1000000n))));
  socket.once("error",e=>{error=e.code;socket.destroy();});
  socket.once("connect",()=>{connected=true;socket.destroy();});
  socket.once("close",()=>{clearTimeout(timer);resolve(!connected&&["EACCES","EPERM"].includes(error));});
  socket.connect(port,host);
 });
}
function replace(object,key,value){
 const original=object[key];object[key]=value;
 restores.push(()=>{need(object[key]===value,"fallback_sdk_guard_identity_unchanged");object[key]=original;});
}
function forbidden(counter,code){return ()=>{report[counter]++;throw new Error(code);};}
async function installGuards(){
 for(const [name,mode]of [["protected-read",fs.constants.O_RDONLY],["protected-write",fs.constants.O_WRONLY]]){
  let fd,denied=false;
  try{fd=fs.openSync(ROOT+"/"+name,mode|fs.constants.O_NOFOLLOW);}
  catch(e){denied=["EACCES","EPERM"].includes(e.code);}
  finally{if(fd!==undefined)fs.closeSync(fd);}
  need(denied,"fallback_sdk_kernel_read_write_refusal");
 }
 need(await deniedNetwork("127.0.0.1",9)&&await deniedNetwork("203.0.113.1",443),
   "fallback_sdk_kernel_two_network_refusals");
 report.kernelReadWriteAndBothNetworkRefusalsObserved=true;
 report.deniedNetworkConnectAttempts=2;
 for(const key of ["spawn","spawnSync","exec","execSync","execFile","execFileSync","fork"])
  replace(childProcess,key,forbidden("childAttempts","fallback_sdk_child_forbidden"));
 const sqlite=createRequire(import.meta.url)("node:sqlite"),originalSqlite=sqlite.DatabaseSync;
 replace(sqlite,"DatabaseSync",new Proxy(originalSqlite,{construct(){report.sqliteAttempts++;throw new Error("fallback_sdk_sqlite_forbidden");}}));
 const denyWrite=forbidden("mutationAttempts","fallback_sdk_mutation_forbidden");
 for(const object of [fs,fsp])for(const key of ["writeFile","writeFileSync","appendFile","appendFileSync",
  "mkdir","mkdirSync","mkdtemp","mkdtempSync","rm","rmSync","rmdir","rmdirSync","unlink","unlinkSync",
  "rename","renameSync","chmod","chmodSync","chown","chownSync","copyFile","copyFileSync",
  "cp","cpSync","link","linkSync","symlink","symlinkSync","truncate","truncateSync",
  "write","writeSync","writev","writevSync","createWriteStream"])
  if(typeof object[key]==="function")replace(object,key,denyWrite);
 const writes=fs.constants.O_WRONLY|fs.constants.O_RDWR|fs.constants.O_CREAT|fs.constants.O_TRUNC|fs.constants.O_APPEND;
 for(const object of [fs,fsp])for(const key of ["open","openSync","readFile","readFileSync"]){
  if(typeof object[key]!=="function")continue;
  const original=object[key];
  replace(object,key,function(filename,...args){
   const name=filename instanceof URL?filename.pathname:typeof filename==="string"?filename:null;
   if(name?.startsWith("/Users/qianqi/.openclaw/")){
    report.productionReadAttempts++;throw new Error("fallback_sdk_production_read_forbidden");
   }
   if(key.startsWith("open")){
    const flags=args[0];
    if((typeof flags==="number"&&(flags&writes)!==0)||(typeof flags==="string"&&!/^r[s]?$/.test(flags)))return denyWrite();
   }
   return original.call(this,filename,...args);
  });
 }
 const denyNetwork=forbidden("networkAttempts","fallback_sdk_network_forbidden");
 for(const object of [http,https])for(const key of ["request","get"])replace(object,key,denyNetwork);
 replace(net.Socket.prototype,"connect",denyNetwork);
 replace(globalThis,"fetch",denyNetwork);
 for(const object of [dns,dnsPromises])for(const key of ["lookup","lookupService","resolve","resolve4","resolve6","resolveAny","resolveCname","resolveTxt","reverse"])
  if(typeof object[key]==="function")replace(object,key,denyNetwork);
 syncBuiltinESMExports();guardsInstalled=true;
}
async function check(id,fn){remaining();activeCase=id;await fn();report.cases.push({id,passed:true});activeCase=null;}
try{
 need(process.platform==="darwin"&&process.getuid()===501&&budget>0&&budget<=30000,
   "fallback_sdk_exact_mac_runtime_and_budget");
 process.stdout.write=()=>{suppressedDiagnostics++;return true;};
 process.stderr.write=()=>{suppressedDiagnostics++;return true;};
 await check("P01_kernel_and_no_side_effect_guards",installGuards);
 await runOriginalSdkCases({check,need,sourceFence,report});
 sourceFence();remaining();
 need(report.cases.length===20&&["childAttempts","sqliteAttempts","mutationAttempts","networkAttempts","productionReadAttempts"]
   .every(k=>report[k]===0),"fallback_sdk_exact_twenty_cases_without_unexpected_effects");
 report.ok=true;
}catch(error){
 report.errorCode=codes.has(error.message)?error.message:"fallback_sdk_policy_qualification_refused";
 report.failedCase=activeCase;report.ok=false;
}finally{
 let restored=true;
 for(const restore of restores.reverse()){try{restore();}catch{restored=false;}}
 try{syncBuiltinESMExports();}catch{restored=false;}
 process.stdout.write=oldOut;process.stderr.write=oldErr;
 report.guardsInstalled=guardsInstalled;report.allInstalledGuardsRestored=restored;
 report.suppressedDiagnosticCount=suppressedDiagnostics;
 report.allRecordedFileDescriptorsClosedOnce=report.fileDescriptors.every(x=>x.closeAttempts===1&&x.closed);
 report.executed=report.cases.length+(activeCase?1:0);report.passed=report.cases.length;
 report.elapsedSeconds=Number(process.hrtime.bigint()-started)/1e9;
 report.sdkSourcePins=SDK_PINS;
 if(!restored||!report.allRecordedFileDescriptorsClosedOnce)report.ok=false;
 emit(JSON.stringify(report)+"\n");
}
process.exitCode=report.ok?0:1;
