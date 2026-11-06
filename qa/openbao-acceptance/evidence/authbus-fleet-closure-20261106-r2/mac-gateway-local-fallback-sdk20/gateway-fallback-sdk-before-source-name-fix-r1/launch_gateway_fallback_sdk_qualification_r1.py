#!/usr/bin/env python3
"""One actual Mac SDK fallback policy/path qualification; no gateway or provider."""
import hashlib,json,os,stat,subprocess,sys,time
from pathlib import Path
START=time.monotonic();UNTIL=START+45.0
ROOT=Path('/Users/qianqi/heptabao-authbus-gateway-fallback-sdk-qualification-20261106-r1')
QUAL=Path('/Users/qianqi/heptabao-authbus-auth-wal-qualification-20261106-r2')
SDK=Path('/opt/homebrew/lib/node_modules/openclaw')
PYTHON='/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14'
NODE='/opt/homebrew/Cellar/node/25.9.0_1/bin/node'
PAYLOAD={'sources': {'mac_gateway_fallback_sdk_cases_r1.mjs': '/** Original installed SDK policy/path calls on synthetic values only.\n * This is not a gateway launch, config-loader integration, or memory proof. */\nimport {pathToFileURL} from "node:url";\nimport {isDeepStrictEqual} from "node:util";\n\nexport const SDK_ROOT="/opt/homebrew/lib/node_modules/openclaw";\nexport const SDK_PINS=Object.freeze({\n "dist/index.js":"9832720dcaf85519d315dda624497e352588f0d65c5607390df0501cc2358985",\n "dist/paths-BMBAvkNf.js":"099ff305aa7662710b2b0f1f925c99b203f30d283ab6b2ada34233a8188fab77",\n "dist/config-state-CtMlHVRM.js":"af2e3bc003048755d820284d3e01a777fae907aff3be8bc4e281dee663f409c5",\n "dist/config-normalization-shared-w2iz0aeC.js":"c3b7bccc26f72ac0ab79ef0635daaa5931d23f86d9bc7e21f4ae8b60ce80f7c2",\n "dist/installed-plugin-index-N4jxqS0-.js":"695dc3196348aa176780979d8c3a75428e9029890470670bcb77cf1a7fa03719"\n});\nexport const ROOT="/Users/qianqi/heptabao-authbus-gateway-fallback-sdk-qualification-20261106-r1";\nconst STATE=ROOT+"/output/state/initial",CONFIG=ROOT+"/output/config.json";\nconst ACTUAL_STATE="/Users/qianqi/.openclaw";\nconst ACTUAL_FALLBACK="/Users/qianqi/heptabao-authbus-writer-maintenance-20261106-r1/local-sdk-fallback.private.json";\nconst ID="openclaw-authbus";\n\nexport async function runOriginalSdkCases({check,need,sourceFence,report}){\n sourceFence();\n const paths=await import(pathToFileURL(SDK_ROOT+"/dist/paths-BMBAvkNf.js").href);\n const states=await import(pathToFileURL(SDK_ROOT+"/dist/config-state-CtMlHVRM.js").href);\n const index=await import(pathToFileURL(SDK_ROOT+"/dist/installed-plugin-index-N4jxqS0-.js").href);\n sourceFence();\n report.actualPolicyAndPathModulesImported=true;\n report.gatewayEntrypointImported=false;\n const environment={HOME:"/Users/qianqi",OPENCLAW_STATE_DIR:STATE,OPENCLAW_CONFIG_PATH:CONFIG};\n const original={plugins:{enabled:true,entries:{[ID]:{enabled:true,config:{\n  address:"https://synthetic.invalid:8200",publishNew:true,leader:true}},\n  "synthetic-unrelated-plugin":{enabled:true}},allow:[]},\n  gateway:{port:18789,auth:{token:"synthetic-fixture-only"}},\n  agents:{defaults:{model:{primary:"openai/synthetic-model"}}}};\n const disabled=structuredClone(original);disabled.plugins.entries[ID].enabled=false;\n const unchanged=structuredClone(disabled);\n function state(config=disabled,extra={}){\n  return states.f({id:ID,origin:"global",config:states.s(config.plugins),rootConfig:config,...extra});\n }\n function disabledState(value){\n  need(value.enabled===false&&value.activated===false&&value.source==="disabled"\n    &&value.reason==="disabled in config","fallback_sdk_exact_explicit_disable_decision");\n }\n await check("P02_original_module_exports",()=>{\n  need([paths.v,paths.s,paths.c,paths.l,paths.o,states.s,states.f,index.n,index.h]\n    .every(x=>typeof x==="function"),"fallback_sdk_exact_original_exports");\n });\n await check("P03_explicit_state_overrides_default",()=>{\n  need(paths.v(environment)===STATE&&paths.v({...environment,OPENCLAW_STATE_DIR:ACTUAL_STATE})===ACTUAL_STATE,\n    "fallback_sdk_original_state_override");\n });\n await check("P04_explicit_config_overrides_existing_state_config",()=>{\n  need(paths.s(environment,STATE)===CONFIG&&paths.c(environment)===CONFIG,\n    "fallback_sdk_original_explicit_config_override");\n });\n await check("P05_explicit_candidates_do_not_include_old_default",()=>{\n  need(isDeepStrictEqual(paths.l(environment),[CONFIG]),"fallback_sdk_explicit_candidate_only");\n });\n await check("P06_missing_explicit_config_stays_explicit",()=>{\n  const env={...environment,OPENCLAW_CONFIG_PATH:ROOT+"/output/missing-explicit.json"};\n  need(paths.c(env)===env.OPENCLAW_CONFIG_PATH&&paths.s(env,STATE)===env.OPENCLAW_CONFIG_PATH,\n    "fallback_sdk_missing_explicit_no_default_fallback");\n });\n await check("P07_actual_registered_paths_are_resolution_only",()=>{\n  const env={...environment,OPENCLAW_STATE_DIR:ACTUAL_STATE,OPENCLAW_CONFIG_PATH:ACTUAL_FALLBACK};\n  need(paths.s(env,ACTUAL_STATE)===ACTUAL_FALLBACK&&isDeepStrictEqual(paths.l(env),[ACTUAL_FALLBACK]),\n    "fallback_sdk_exact_registered_maintenance_resolution");\n  report.actualRegisteredPathsResolvedWithoutOpening=true;\n });\n await check("P08_runtime_path_repin_retains_explicit_scope",()=>{\n  need(isDeepStrictEqual(paths.o({...environment}),{configPath:CONFIG,stateDir:STATE})\n    &&paths.r===STATE&&paths.t===CONFIG,"fallback_sdk_runtime_path_repin");\n });\n await check("P09_false_survives_original_normalization",()=>{\n  need(states.s(disabled.plugins).entries[ID].enabled===false,"fallback_sdk_exact_false_normalized");\n  disabledState(state());\n });\n await check("P10_explicit_false_overrides_allowlist",()=>{\n  const cfg=structuredClone(disabled);cfg.plugins.allow=[ID];disabledState(state(cfg));\n });\n await check("P11_explicit_false_overrides_memory_slot",()=>{\n  const cfg=structuredClone(disabled);cfg.plugins.slots={memory:ID};disabledState(state(cfg));\n });\n await check("P12_explicit_false_overrides_context_engine_slot",()=>{\n  const cfg=structuredClone(disabled);cfg.plugins.slots={contextEngine:ID};disabledState(state(cfg));\n });\n await check("P13_explicit_false_overrides_auto_reason",()=>{\n  disabledState(state(disabled,{autoEnabledReason:"synthetic earlier auto-enable"}));\n });\n await check("P14_explicit_false_overrides_older_activation_source",()=>{\n  disabledState(state(disabled,{activationSource:{plugins:states.s(original.plugins),rootConfig:original}}));\n });\n await check("P15_explicit_false_overrides_origin_defaults",()=>{\n  for(const origin of ["global","config","workspace","bundled"])\n   disabledState(state(disabled,{origin,enabledByDefault:true}));\n });\n await check("P16_old_persisted_enabled_record_cannot_override_false",()=>{\n  const persisted={plugins:[{pluginId:ID,origin:"global",enabled:true,enabledByDefault:true}]};\n  need(index.n(persisted,ID,disabled)===false,"fallback_sdk_cached_index_true_is_not_activation");\n });\n await check("P17_original_enabled_positive_control",()=>{\n  const persisted={plugins:[{pluginId:ID,origin:"global",enabled:true}]};\n  need(state(original).enabled===true&&state(original).activated===true\n    &&index.n(persisted,ID,original)===true,"fallback_sdk_original_enabled_positive_control");\n });\n await check("P18_policy_hash_changes_for_single_boolean",()=>{\n  need(index.h(original)!==index.h(disabled),"fallback_sdk_current_policy_invalidates_old_hash");\n  report.privateOrSyntheticConfigurationHashesPublished=false;\n });\n await check("P19_integer_zero_does_not_disable_original_sdk",()=>{\n  const cfg=structuredClone(original);cfg.plugins.entries[ID].enabled=0;\n  const persisted={plugins:[{pluginId:ID,origin:"global",enabled:true}]};\n  need(states.s(cfg.plugins).entries[ID].enabled===undefined\n    &&state(cfg).enabled===true&&index.n(persisted,ID,cfg)===true,\n    "fallback_sdk_zero_is_not_false_negative_control");\n });\n await check("P20_original_functions_do_not_mutate_input",()=>{\n  need(isDeepStrictEqual(disabled,unchanged),"fallback_sdk_input_configuration_unchanged");\n });\n sourceFence();\n report.gatewayStarted=false;report.pluginRegisterInvoked=false;\n report.gatewayRegistrationChainQualified=false;\n report.runningGatewayMemoryFlagsProven=false;\n report.actualSdkPolicyAndPathsQualified=true;\n}\n', 'mac_gateway_fallback_sdk_qualification_r1.mjs': '#!/usr/bin/env node\n/** Actual installed SDK policy/path compatibility, never a gateway process. */\nimport fs from "node:fs";\nimport fsp from "node:fs/promises";\nimport path from "node:path";\nimport crypto from "node:crypto";\nimport net from "node:net";\nimport http from "node:http";\nimport https from "node:https";\nimport dns from "node:dns";\nimport dnsPromises from "node:dns/promises";\nimport childProcess from "node:child_process";\nimport {createRequire,syncBuiltinESMExports} from "node:module";\nimport {isDeepStrictEqual} from "node:util";\nimport {ROOT,SDK_ROOT,SDK_PINS,runOriginalSdkCases} from "./mac_gateway_fallback_sdk_cases_r1.mjs";\n\nconst started=process.hrtime.bigint(),budget=Number(process.argv[2]);\nconst until=started+BigInt(Math.trunc(budget*1000000));\nconst report={schema:"heptabao.actual-mac-gateway-fallback-sdk-policy-qualification.r1",ok:false,\n actualInstalledSdk:true,syntheticConfigurationOnly:true,productionCredentialReads:0,\n productionWrites:0,actualProviderCalls:0,networkRequests:0,serviceMutations:0,\n productionMutexAcquired:false,productionOnceLedgerOpened:false,\n cases:[],fileDescriptors:[],childAttempts:0,sqliteAttempts:0,mutationAttempts:0,\n networkAttempts:0,productionReadAttempts:0};\nconst emit=process.stdout.write.bind(process.stdout),oldOut=process.stdout.write,oldErr=process.stderr.write;\nconst codes=new Set(),restores=[];\nlet activeCase=null,suppressedDiagnostics=0,guardsInstalled=false;\nfunction need(value,code){if(!value){codes.add(code);throw new Error(code);}}\nfunction remaining(){need(process.hrtime.bigint()<until,"fallback_sdk_original_deadline");}\nfunction full(s){return ["dev","ino","uid","gid","mode","nlink","size","mtimeNs","ctimeNs"].map(k=>String(s[k]));}\nfunction sourceFence(){\n for(const [relative,pin]of Object.entries(SDK_PINS)){\n  remaining();const filename=path.join(SDK_ROOT,relative);\n  const fd=fs.openSync(filename,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);\n  const row={kind:"public-source",closeAttempts:0,closed:false};report.fileDescriptors.push(row);\n  try{\n   const before=fs.fstatSync(fd,{bigint:true});\n   need(before.isFile()&&before.nlink===1n&&[0n,501n].includes(before.uid)&&(before.mode&18n)===0n\n    &&before.size>0n&&before.size<=1048576n,"fallback_sdk_public_source_custody");\n   const raw=Buffer.alloc(Number(before.size)+1);let offset=0;\n   while(offset<raw.length){remaining();const n=fs.readSync(fd,raw,offset,raw.length-offset,null);if(!n)break;offset+=n;}\n   need(offset===Number(before.size)&&isDeepStrictEqual(full(before),full(fs.fstatSync(fd,{bigint:true})))\n    &&isDeepStrictEqual(full(before),full(fs.lstatSync(filename,{bigint:true})))\n    &&crypto.createHash("sha256").update(raw.subarray(0,offset)).digest("hex")===pin,\n    "fallback_sdk_current_whole_public_source_pin");\n  }finally{row.closeAttempts++;fs.closeSync(fd);row.closed=true;}\n }\n}\nasync function deniedNetwork(host,port){\n return await new Promise(resolve=>{\n  const socket=new net.Socket();let error=null,connected=false;\n  const timer=setTimeout(()=>socket.destroy(),Math.min(750,Math.max(1,Number((until-process.hrtime.bigint())/1000000n))));\n  socket.once("error",e=>{error=e.code;socket.destroy();});\n  socket.once("connect",()=>{connected=true;socket.destroy();});\n  socket.once("close",()=>{clearTimeout(timer);resolve(!connected&&["EACCES","EPERM"].includes(error));});\n  socket.connect(port,host);\n });\n}\nfunction replace(object,key,value){\n const original=object[key];object[key]=value;\n restores.push(()=>{need(object[key]===value,"fallback_sdk_guard_identity_unchanged");object[key]=original;});\n}\nfunction forbidden(counter,code){return ()=>{report[counter]++;throw new Error(code);};}\nasync function installGuards(){\n for(const [name,mode]of [["protected-read",fs.constants.O_RDONLY],["protected-write",fs.constants.O_WRONLY]]){\n  let fd,denied=false;\n  try{fd=fs.openSync(ROOT+"/"+name,mode|fs.constants.O_NOFOLLOW);}\n  catch(e){denied=["EACCES","EPERM"].includes(e.code);}\n  finally{if(fd!==undefined)fs.closeSync(fd);}\n  need(denied,"fallback_sdk_kernel_read_write_refusal");\n }\n need(await deniedNetwork("127.0.0.1",9)&&await deniedNetwork("203.0.113.1",443),\n   "fallback_sdk_kernel_two_network_refusals");\n report.kernelReadWriteAndBothNetworkRefusalsObserved=true;\n report.deniedNetworkConnectAttempts=2;\n for(const key of ["spawn","spawnSync","exec","execSync","execFile","execFileSync","fork"])\n  replace(childProcess,key,forbidden("childAttempts","fallback_sdk_child_forbidden"));\n const sqlite=createRequire(import.meta.url)("node:sqlite"),originalSqlite=sqlite.DatabaseSync;\n replace(sqlite,"DatabaseSync",new Proxy(originalSqlite,{construct(){report.sqliteAttempts++;throw new Error("fallback_sdk_sqlite_forbidden");}}));\n const denyWrite=forbidden("mutationAttempts","fallback_sdk_mutation_forbidden");\n for(const object of [fs,fsp])for(const key of ["writeFile","writeFileSync","appendFile","appendFileSync",\n  "mkdir","mkdirSync","mkdtemp","mkdtempSync","rm","rmSync","rmdir","rmdirSync","unlink","unlinkSync",\n  "rename","renameSync","chmod","chmodSync","chown","chownSync","copyFile","copyFileSync",\n  "cp","cpSync","link","linkSync","symlink","symlinkSync","truncate","truncateSync",\n  "write","writeSync","writev","writevSync","createWriteStream"])\n  if(typeof object[key]==="function")replace(object,key,denyWrite);\n const writes=fs.constants.O_WRONLY|fs.constants.O_RDWR|fs.constants.O_CREAT|fs.constants.O_TRUNC|fs.constants.O_APPEND;\n for(const object of [fs,fsp])for(const key of ["open","openSync","readFile","readFileSync"]){\n  if(typeof object[key]!=="function")continue;\n  const original=object[key];\n  replace(object,key,function(filename,...args){\n   const name=filename instanceof URL?filename.pathname:typeof filename==="string"?filename:null;\n   if(name?.startsWith("/Users/qianqi/.openclaw/")){\n    report.productionReadAttempts++;throw new Error("fallback_sdk_production_read_forbidden");\n   }\n   if(key.startsWith("open")){\n    const flags=args[0];\n    if((typeof flags==="number"&&(flags&writes)!==0)||(typeof flags==="string"&&!/^r[s]?$/.test(flags)))return denyWrite();\n   }\n   return original.call(this,filename,...args);\n  });\n }\n const denyNetwork=forbidden("networkAttempts","fallback_sdk_network_forbidden");\n for(const object of [http,https])for(const key of ["request","get"])replace(object,key,denyNetwork);\n replace(net.Socket.prototype,"connect",denyNetwork);\n replace(globalThis,"fetch",denyNetwork);\n for(const object of [dns,dnsPromises])for(const key of ["lookup","lookupService","resolve","resolve4","resolve6","resolveAny","resolveCname","resolveTxt","reverse"])\n  if(typeof object[key]==="function")replace(object,key,denyNetwork);\n syncBuiltinESMExports();guardsInstalled=true;\n}\nasync function check(id,fn){remaining();activeCase=id;await fn();report.cases.push({id,passed:true});activeCase=null;}\ntry{\n need(process.platform==="darwin"&&process.getuid()===501&&budget>0&&budget<=30000,\n   "fallback_sdk_exact_mac_runtime_and_budget");\n process.stdout.write=()=>{suppressedDiagnostics++;return true;};\n process.stderr.write=()=>{suppressedDiagnostics++;return true;};\n await check("P01_kernel_and_no_side_effect_guards",installGuards);\n await runOriginalSdkCases({check,need,sourceFence,report});\n sourceFence();remaining();\n need(report.cases.length===20&&["childAttempts","sqliteAttempts","mutationAttempts","networkAttempts","productionReadAttempts"]\n   .every(k=>report[k]===0),"fallback_sdk_exact_twenty_cases_without_unexpected_effects");\n report.ok=true;\n}catch(error){\n report.errorCode=codes.has(error.message)?error.message:"fallback_sdk_policy_qualification_refused";\n report.failedCase=activeCase;report.ok=false;\n}finally{\n let restored=true;\n for(const restore of restores.reverse()){try{restore();}catch{restored=false;}}\n try{syncBuiltinESMExports();}catch{restored=false;}\n process.stdout.write=oldOut;process.stderr.write=oldErr;\n report.guardsInstalled=guardsInstalled;report.allInstalledGuardsRestored=restored;\n report.suppressedDiagnosticCount=suppressedDiagnostics;\n report.allRecordedFileDescriptorsClosedOnce=report.fileDescriptors.every(x=>x.closeAttempts===1&&x.closed);\n report.executed=report.cases.length+(activeCase?1:0);report.passed=report.cases.length;\n report.elapsedSeconds=Number(process.hrtime.bigint()-started)/1e9;\n report.sdkSourcePins=SDK_PINS;\n if(!restored||!report.allRecordedFileDescriptorsClosedOnce)report.ok=false;\n emit(JSON.stringify(report)+"\\n");\n}\nprocess.exitCode=report.ok?0:1;\n'}, 'sourcePins': {'mac_gateway_fallback_sdk_cases_r1.mjs': '75410c2b796801e1386b8775b93391205c960bb02d7abd75bde3b64126e4fd66', 'mac_gateway_fallback_sdk_qualification_r1.mjs': 'c4ec7bffd1a97fbb5fdcba9ae030f7d6f0fe4df5aaa0e40055a3a816853f4b4e'}, 'sdkPins': {'dist/index.js': '9832720dcaf85519d315dda624497e352588f0d65c5607390df0501cc2358985', 'dist/paths-BMBAvkNf.js': '099ff305aa7662710b2b0f1f925c99b203f30d283ab6b2ada34233a8188fab77', 'dist/config-state-CtMlHVRM.js': 'af2e3bc003048755d820284d3e01a777fae907aff3be8bc4e281dee663f409c5', 'dist/config-normalization-shared-w2iz0aeC.js': 'c3b7bccc26f72ac0ab79ef0635daaa5931d23f86d9bc7e21f4ae8b60ce80f7c2', 'dist/installed-plugin-index-N4jxqS0-.js': '695dc3196348aa176780979d8c3a75428e9029890470670bcb77cf1a7fa03719'}, 'custodyQualificationAuthority': {'at_unix_ms': 1793975259508, 'audit_recorded': True, 'automatic_retry': False, 'cancelled': False, 'exit_code': 0, 'job_id': '1a1b141ef40-fc05-7750', 'launch_nonce': '6ee37ff3af8195a8d1bef14099a8e948', 'log_bytes': {'stderr': {'seen': 0, 'stored': 0}, 'stdout': {'seen': 58701, 'stored': 58701}}, 'log_errors': {'stderr': None, 'stdout': None}, 'log_synced': {'stderr': True, 'stdout': True}, 'log_truncated': {'stderr': False, 'stdout': False}, 'output_complete': True, 'output_durable': True, 'state': 'succeeded', 'terminal_publication_confirmed': True, 'terminal_publication_protocol': 1, 'timed_out': False}}
CUSTODY_PINS={
 'kv2_dr_process_custody.py':'669e2cd1d9ee597529c08b88f3fc21c813d4ff7b57f3792381baa44fbdbe7008',
 'owned_process.py':'0ee96c9f43b50ebd57ee8f0ef95f2431c441ec02c1799992588dbf50768745d0'}
RUNTIME_PINS={
 PYTHON:'cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13',
 NODE:'a46ed02589ca3af795237111ff854262064f8ff5c5b58d75c1509f37311eb15e',
 '/usr/bin/sandbox-exec':'abc5bb136d6b5cce8fa85d789f78e3326c51ca60cae637b2064adfb67a1dcd9a'}
report={'schema':'heptabao.actual-sdk-gateway-fallback-owned-qualification.r1','ok':False,
 'sharedSeconds':45,'supervisorSeconds':70,'automaticRetry':False,'providerCalls':0,
 'productionCredentialReads':0,'productionWrites':0,'productionMutexAcquired':False,
 'nativeServiceStarted':False,'syntheticStateOnly':True,'actualSdkPolicyAndPathsOnly':True,'gatewayRegistrationChainQualified':False,
 'originalChildrenExpected':3,'children':[],
 'candidateCommit':'4bde9aee03fcd27c59e13607e529b1cee594b249'}
owner=None;created=False;children=[];error_codes=set()
def need(value,code):
 if not value:error_codes.add(code);raise RuntimeError(code)
def remaining(cap=45):
 value=UNTIL-time.monotonic();need(value>0,'original_fallback_sdk_qualification_deadline');return min(cap,value)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def ident(s):return (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def read(path,cap=1048576):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  s=os.fstat(fd);need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_uid in (0,501)
    and not stat.S_IMODE(s.st_mode)&0o022 and 0<=s.st_size<=cap,'bounded_public_fallback_sdk_source')
  out=bytearray()
  while len(out)<=cap:
   remaining();part=os.read(fd,min(65536,cap+1-len(out)))
   if not part:break
   out.extend(part)
  need(len(out)==s.st_size and ident(s)==ident(os.fstat(fd))==ident(Path(path).lstat()),'stable_public_fallback_sdk_source')
  return bytes(out)
 finally:os.close(fd)
def private(path,data):
 raw=data if isinstance(data,bytes) else data.encode();need(len(raw)<=262144,'bounded_owned_fallback_sdk_artifact')
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  view=memoryview(raw)
  while view:
   remaining();n=os.write(fd,view);need(n>0,'owned_fallback_sdk_write_progress');view=view[n:]
  os.fsync(fd)
 finally:os.close(fd)
 fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
def fence():
 for name,pin in CUSTODY_PINS.items():need(sha(read(QUAL/'qa'/name))==pin,'qualified_custody_source_unchanged')
 for path,pin in RUNTIME_PINS.items():need(sha(read(Path(path),2*1048576))==pin,'qualified_fallback_sdk_runtime_unchanged')
 for name,pin in PAYLOAD['sdkPins'].items():need(sha(read(SDK/name))==pin,'qualified_fallback_sdk_sdk_source_unchanged')
def close_streams(child):
 for stream in (child.stdin,child.stdout,child.stderr):
  if stream is not None and not stream.closed:stream.close()
def record(label,child,out,err):
 close_streams(child)
 need(len(out)<=65536 and len(err)<=65536,'bounded_fallback_sdk_worker_output')
 private(ROOT/'output'/(label+'.stdout.public.json'),out)
 private(ROOT/'output'/(label+'.stderr.private'),err)
 report['children'].append({'label':label,'exitCode':child.returncode,'stdoutBytes':len(out),
   'stderrBytes':len(err),'stdoutSha256':sha(out),'streamsClosed':True})
 need(child.returncode==0 and not err,'actual_fallback_sdk_child_complete_zero')
try:
 os.umask(0o077)
 need(sys.platform=='darwin' and os.getuid()==501 and os.path.realpath(sys.executable)==PYTHON,'exact_mac_fallback_sdk_runtime')
 authority=PAYLOAD['custodyQualificationAuthority']
 need(authority['job_id']=='1a1b141ef40-fc05-7750' and authority['state']=='succeeded' and authority['exit_code']==0
   and all(authority[k] is True for k in ('output_complete','output_durable','terminal_publication_confirmed'))
   and all(authority[k] is False for k in ('timed_out','cancelled','automatic_retry')),'original_custody_qualification_authority')
 q=read(QUAL/'result.public.json',65536)
 need(len(q)==58701 and sha(q)=='67cb6bb6804c7285f13f373f6af607405ada39ab734423bf328ffe27915cee4e','same_original_custody_qualification')
 proof=json.loads(q)
 need(proof['ok'] and proof['allCasesMatched'] and proof['allOwnedClosed']
   and proof['custody']['passed_process_custody'] and proof['custody']['original_count']==18,'complete_original_18_custody_cases')
 fence();home=ROOT.parent.lstat()
 need(stat.S_ISDIR(home.st_mode) and home.st_uid==501 and not stat.S_IMODE(home.st_mode)&0o022,'owned_mac_home_parent')
 ROOT.mkdir(mode=0o700,exist_ok=False);created=True
 for name in ('code','output','output/tmp','output/tmp/openclaw-501','output/state','output/state/initial'):
  (ROOT/name).mkdir(mode=0o700,exist_ok=False)
 private(ROOT/'protected-read',b'synthetic kernel read refusal probe\n')
 private(ROOT/'protected-write',b'synthetic kernel write refusal probe\n')
 private(ROOT/'output/config.json',b'{"synthetic":"explicit"}\n')
 private(ROOT/'output/state/initial/openclaw.json',b'{"synthetic":"old-default"}\n')
 for name,raw in PAYLOAD['sources'].items():
  need(name in ('mac_refresh_fallback_sdks_r2.mjs','mac_gateway_fallback_sdk_qualification_r1.mjs'),'fixed_fallback_sdk_source_name')
  need(sha(raw.encode())==PAYLOAD['sourcePins'][name],'prepared_fallback_sdk_source_pin');private(ROOT/'code'/name,raw)
 private(ROOT/'plan.public.json',json.dumps({'schema':'heptabao.actual-sdk-gateway-fallback-synthetic-plan.r1',
  'sharedSeconds':45,'supervisorSeconds':70,'originalChildren':3,'caseCount':20,
  'sourcePins':PAYLOAD['sourcePins'],'sdkPins':PAYLOAD['sdkPins'],
  'productionReadAuthorized':False,'productionMutationAuthorized':False,'providerCallAuthorized':False,
  'productionMutexAcquisitionAuthorized':False},sort_keys=True).encode()+b'\n')
 lines=['(version 1)','(deny default)','(allow process*)','(allow signal (target children))',
   '(allow sysctl-read)','(allow mach-lookup)','(allow file-read-metadata)']
 for name in ('/System','/usr','/bin','/sbin','/Library','/private/etc','/opt/homebrew','/dev/fd'):
  lines.append('(allow file-read* (subpath '+json.dumps(name)+'))')
 for name in (ROOT/'code',ROOT/'output'):lines.append('(allow file-read* (subpath '+json.dumps(str(name))+'))')
 for name in [ROOT,*ROOT.parents]:lines.append('(allow file-read* (literal '+json.dumps(str(name))+'))')
 for name in ('/dev/null','/dev/urandom','/dev/random'):lines.append('(allow file-read* (literal '+json.dumps(name)+'))')
 lines.extend(['(allow file-write* (subpath '+json.dumps(str(ROOT/'output'))+'))','(allow file-write* (literal "/dev/null"))'])
 policy='\n'.join(lines)+'\n';private(ROOT/'fixture.sb',policy)
 environment={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','HOME':'/Users/qianqi','NODE_NO_WARNINGS':'1',
  'TMPDIR':str(ROOT/'output/tmp'),'OPENCLAW_STATE_DIR':str(ROOT/'output/state/initial'),
  'OPENCLAW_CONFIG_PATH':str(ROOT/'output/config.json'),'OPENCLAW_AUTH_STORE_READONLY':'1'}
 sys.path.insert(0,str(QUAL/'qa'));import kv2_dr_process_custody as custody
 original_popen=subprocess.Popen;original_killpg=os.killpg
 with custody.activated() as owner:
  for number,name in enumerate(PAYLOAD['sources']):
   child=subprocess.Popen([NODE,'--check',str(ROOT/'code'/name)],stdin=subprocess.DEVNULL,
     stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=str(ROOT),env=environment)
   children.append(child);out,err=child.communicate(timeout=remaining(5));record('syntax-'+str(number),child,out,err)
  child=subprocess.Popen(['/usr/bin/sandbox-exec','-f',str(ROOT/'fixture.sb'),NODE,'--no-warnings',
    str(ROOT/'code/mac_gateway_fallback_sdk_qualification_r1.mjs'),str(int(remaining(30)*1000))],
    stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=str(ROOT),env=environment)
  children.append(child);out,err=child.communicate(timeout=remaining(30));record('unit',child,out,err)
  value=json.loads(out);report['unitResult']=value
  need(value.get('ok') is True and value.get('actualInstalledSdk') is True
    and value.get('executed')==20 and value.get('passed')==20 and len(value.get('cases',[]))==20
    and all(row.get('passed') is True for row in value['cases'])
    and value.get('kernelReadWriteAndBothNetworkRefusalsObserved') is True
    and value.get('allRecordedFileDescriptorsClosedOnce') is True
    and value.get('allInstalledGuardsRestored') is True
    and value.get('actualSdkPolicyAndPathsQualified') is True
    and value.get('gatewayEntrypointImported') is False
    and value.get('gatewayRegistrationChainQualified') is False
    and value.get('runningGatewayMemoryFlagsProven') is False
    and all(value.get(key)==0 for key in ('actualProviderCalls','productionWrites','productionCredentialReads',
      'childAttempts','sqliteAttempts','mutationAttempts','networkAttempts','productionReadAttempts','serviceMutations')),
    'actual_original_sdk_policy_and_paths_twenty_cases_passed')
 report['custody']=owner.receipt()
 need(report['custody']['passed_process_custody'] and report['custody']['original_count']==3
   and subprocess.Popen is original_popen and os.killpg is original_killpg,'three_original_fallback_sdk_children_closed')
 for name,pin in PAYLOAD['sourcePins'].items():need(sha(read(ROOT/'code'/name))==pin,'owned_fallback_sdk_source_unchanged')
 fence();remaining()
 report.update(ok=True,caseCount=20,allOriginalChildrenClosed=True,sourcePins=PAYLOAD['sourcePins'],
   sdkSourcePins=PAYLOAD['sdkPins'],runtimePins=RUNTIME_PINS,sandboxProfileSha256=sha(policy.encode()),
   actualSdkPolicyAndPathsQualified=True,gatewayRegistrationChainQualified=False,
   runningGatewayMemoryFlagsProven=False,productionRefreshControllerQualified=False,dynamicLibraryDependencyClosureClaimed=False)
except BaseException as error:
 report['errorCode']=str(error) if str(error) in error_codes else 'fallback_sdk_qualification_refused'
 report['errorType']=type(error).__name__
finally:
 for child in children:close_streams(child)
 if owner is not None:report['custody']=owner.receipt()
 report['elapsedSeconds']=round(time.monotonic()-START,6)
 if created:
  try:private(ROOT/'result.public.json',json.dumps(report,sort_keys=True).encode()+b'\n')
  except BaseException:report['ok']=False;report['resultPublicationFailed']=True
 print(json.dumps(report,sort_keys=True))
raise SystemExit(0 if report['ok'] else 1)
