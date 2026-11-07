#!/usr/bin/env python3
"""Bounded current main3 refresh concurrency facts; no refresh or source write."""
import contextlib,hashlib,json,os,stat,subprocess,sys,time
from pathlib import Path
START=time.monotonic();UNTIL=START+45.0
ROOT=Path('/Users/qianqi/heptabao-authbus-current-refresh-flags-20261106-r2')
LIVE=Path('/Users/qianqi/.openclaw');SDK=Path('/opt/homebrew/lib/node_modules/openclaw')
PLUGIN=LIVE/'extensions/openclaw-authbus'
QUAL=Path('/Users/qianqi/heptabao-authbus-auth-wal-qualification-20261106-r2')
CONFIG_ROOT=Path('/Users/qianqi/heptabao-authbus-current-source-20261106-r1')
ORDER_ROOT=Path('/Users/qianqi/heptabao-authbus-current-sdk-order-20261106-r1')
BINDING=CONFIG_ROOT/'output/current-source-binding.private.json'
MAPPING=ORDER_ROOT/'output/owner-mapping.private.json'
STATES=('bad-refresh-quarantine.json','refresh-backoff.json')
PYTHON='/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14'
NODE='/opt/homebrew/Cellar/node/25.9.0_1/bin/node'
PAYLOAD=json.loads('{"additionalSdkPins":{"dist/openclaw-agent-db-DKpxi-Ll.js":"5c99ab6de1ccc1419ed1bdbc783b79203afc34e564f794df4d91bf10e0b53360","dist/openclaw-state-db-DzSsA9Ji.js":"ba920b2e6f63293a27c34615fc31dcb16a20a68a1e1e34fbccdcac56a9608149"},"configAuthority":{"at_unix_ms":1793974583163,"audit_recorded":true,"automatic_retry":false,"cancelled":false,"exit_code":0,"job_id":"1a1b137a21d-fc05-76f8","launch_nonce":"a239982bdb0254dcddfc7c14f7d347b7","log_bytes":{"stderr":{"seen":0,"stored":0},"stdout":{"seen":5091,"stored":5091}},"log_errors":{"stderr":null,"stdout":null},"log_synced":{"stderr":true,"stdout":true},"log_truncated":{"stderr":false,"stdout":false},"output_complete":true,"output_durable":true,"state":"succeeded","terminal_publication_confirmed":true,"terminal_publication_protocol":1,"timed_out":false},"configResult":{"bytes":5091,"sha256":"52a7a44f88db47037f3b86697955cb7f303093497bc5a2ca6c49ad8248b12930"},"custodyAuthority":{"at_unix_ms":1793975259508,"audit_recorded":true,"automatic_retry":false,"cancelled":false,"exit_code":0,"job_id":"1a1b141ef40-fc05-7750","launch_nonce":"6ee37ff3af8195a8d1bef14099a8e948","log_bytes":{"stderr":{"seen":0,"stored":0},"stdout":{"seen":58701,"stored":58701}},"log_errors":{"stderr":null,"stdout":null},"log_synced":{"stderr":true,"stdout":true},"log_truncated":{"stderr":false,"stdout":false},"output_complete":true,"output_durable":true,"state":"succeeded","terminal_publication_confirmed":true,"terminal_publication_protocol":1,"timed_out":false},"orderAuthority":{"at_unix_ms":1793980890892,"audit_recorded":true,"automatic_retry":false,"cancelled":false,"exit_code":0,"job_id":"1a1b197fa0e-fc05-79c0","launch_nonce":"5adfc7bfbc3aad4247dfd8a0561cacab","log_bytes":{"stderr":{"seen":0,"stored":0},"stdout":{"seen":22033,"stored":22033}},"log_errors":{"stderr":null,"stdout":null},"log_synced":{"stderr":true,"stdout":true},"log_truncated":{"stderr":false,"stdout":false},"output_complete":true,"output_durable":true,"state":"succeeded","terminal_publication_confirmed":true,"terminal_publication_protocol":1,"timed_out":false},"orderResult":{"bytes":22033,"sha256":"fb65fe07d9afc97aa102d7f00561537b315cf0b349b339f6ca8f3285bd5a10c4"},"pluginPins":{"bad-refresh-quarantine.js":"916617f296bd2e4b97b240a13418ac6220bb6513a1a0b83f5ee21854edc62286","index.js":"b19b6a9e7c1d57ccef8d67994ed3421891788ac30a82ff6bad2eef2ef7e30f9b"},"sdkPins":{"dist/agent-scope-config-BxAUeF6t.js":"83ef65476ae41bfcf040b1503f468074f36d602e9fa46551822cb7768bef3a1f","dist/credential-state-BY-oz-QV.js":"596a57e2ef09a3bc13a584781ddf749b66598b52a6b3f0817584bc6f401b4db4","dist/current-plugin-metadata-snapshot-CmOpmveB.js":"0c2efc7943a5f6407d938ddea68275e58cbaf916f1378cab8791ec9f5338808b","dist/installed-plugin-index-store-CWgFGnm0.js":"0d7bfad658ef322012b9b68b9709620bca8c0b202046f6f3d623ed7d31fc7a18","dist/logger-DPps3u8A.js":"90366fb73663dd713d58f4389e41331566a1ed82b1649844cf05d0c769175d44","dist/manifest-registry-installed-DMplEARQ.js":"6732b5661610d5b57c10478b77714c2767310b4b5544f158987de1c3ef9af832","dist/order-CeBlX0NH.js":"4674b1d9ccf77f2b3ef7dd87c394ad99404ba34e6b2a0efed661c4546ac5c732","dist/plugin-metadata-snapshot-rpSrEgGf.js":"2264d7441cd9690df32caf42d3c71c7c7e674b6c10f0f6a19a667605b479db4b","dist/plugin-registry-8E8D2Hou.js":"570f856a8f4e517d8bf0e0d768bcf691eaf9bf44b9f8e560c8f86ff8a7cef983","dist/plugin-sdk/agent-runtime.js":"7831532d17eeaddd62889b2e8bb7b65ea7a7851901f69ceec23607a8c579dd95","dist/profile-list-XT2LKXsd.js":"b64042c7f5fc9e8902c68dd2f63ad66b200f6a92a176c7d7ccfed312dfec4f6c","dist/provider-auth-aliases-Cp2PXhsh.js":"7a22ef68a9275fc0700e657dc4b71257c956dd38feb370cdc1387e83f5963efa","dist/provider-id-Dq06Bcx6.js":"99187ac3607cf72bd2f2f8bd253b61b490d56f657cf07dfdb5c3fe7198336cc0","dist/source-check-ZSz5NzGW.js":"9c02bbf2df3cf123efe8c34c423ae4ea044371aab91d727f38986351695ce1c9","dist/sqlite-B1ze-fre.js":"ed940f0ba0877eea0f00b2da30e727714993db60156fefc6fe80ac8564984c50","dist/store-DH33UrUj.js":"25a5c7075e13b8fb32f498a90e5ee91d93b7e15972b3b74796f1325b5ba98ebf","dist/tmp-openclaw-dir-uPgNO8da.js":"c12ed50f959d17d9e4ca3e3cce60aa471ee160bdd705035a6d1ed63c47207b23","dist/usage-state-BFMjBJsu.js":"aa0a93c88c1b10046e614d476c27568f985a60580433c4763c5b3c3e78c1c097"},"sourcePins":{"authbus_sdk_read_guard.mjs":"f5fb13e04b394320a44b6687b474f06c0bb49b2ef1e194b956f528e454453d1f","mac_current_refresh_flags_r2.mjs":"53c823a493b08a95e3aade6b45a9e745951e40f7d4da8b03a9dbe208a595bbbb"},"sources":{"authbus_sdk_read_guard.mjs":"/** Exact installed-source read guard, with denial counters; no credential hashing. */\\nimport fs from \\"node:fs\\";\\nimport fsp from \\"node:fs/promises\\";\\nimport http from \\"node:http\\";\\nimport https from \\"node:https\\";\\nimport net from \\"node:net\\";\\nimport dns from \\"node:dns\\";\\nimport childProcess from \\"node:child_process\\";\\nimport { syncBuiltinESMExports } from \\"node:module\\";\\nconst LIMIT=2*1024*1024;\\nfunction fail(code){const error=new Error(code);error.code=code;throw error;}\\nfunction requireValue(value,code){if(!value)fail(code);}\\nexport function protectReadPhase(diagnostics) {\\n  const changes = [];\\n  const replace = (object, key, value) => {\\n    if (typeof object[key] !== \\"function\\") return;\\n    changes.push([object, key, object[key]]); object[key] = value;\\n  };\\n  const denied = () => { diagnostics.blockedAttempts += 1; fail(\\"sdk_attempted_mutation_or_network\\"); };\\n  for (const prefix of [\\"writeFile\\", \\"appendFile\\", \\"mkdir\\", \\"mkdtemp\\", \\"rename\\", \\"unlink\\", \\"rm\\", \\"rmdir\\", \\"copyFile\\", \\"cp\\", \\"link\\", \\"symlink\\", \\"truncate\\", \\"chmod\\", \\"chown\\", \\"utimes\\", \\"write\\", \\"writev\\"]) {\\n    replace(fs, prefix, denied); replace(fs, prefix + \\"Sync\\", denied); replace(fsp, prefix, denied);\\n  }\\n  const readOnlyFlags = flags => typeof flags === \\"string\\" ? [\\"r\\", \\"rs\\", \\"sr\\"].includes(flags)\\n    : Number.isInteger(flags) && !(flags & (fs.constants.O_WRONLY | fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_TRUNC | fs.constants.O_APPEND));\\n  for (const [object, name] of [[fs, \\"openSync\\"], [fs, \\"open\\"], [fsp, \\"open\\"]]) {\\n    const original = object[name];\\n    replace(object, name, function (filename, flags, ...rest) {\\n      if (!readOnlyFlags(flags)) diagnostics.blockedAttempts += 1;\\n      requireValue(readOnlyFlags(flags), \\"sdk_attempted_writable_open\\");\\n      return original.call(this, filename, flags, ...rest);\\n    });\\n  }\\n  for (const object of [http, https]) for (const key of [\\"request\\", \\"get\\"]) replace(object, key, denied);\\n  replace(net.Socket.prototype, \\"connect\\", denied);\\n  for (const key of [\\"lookup\\", \\"lookupService\\", \\"resolve\\", \\"resolve4\\", \\"resolve6\\", \\"resolveAny\\", \\"resolveCname\\", \\"resolveMx\\", \\"resolveTxt\\", \\"reverse\\"]) {\\n    replace(dns, key, denied); replace(dns.promises, key, denied);\\n  }\\n  for (const key of [\\"exec\\", \\"execFile\\", \\"execSync\\", \\"execFileSync\\", \\"spawn\\", \\"spawnSync\\", \\"fork\\"]) replace(childProcess, key, denied);\\n  const previousFetch = globalThis.fetch; globalThis.fetch = denied;\\n  const capture = name => function (chunk, encoding, callback) {\\n    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), typeof encoding === \\"string\\" ? encoding : \\"utf8\\");\\n    diagnostics.bytes += bytes.length;\\n    if (diagnostics.bytes > LIMIT) fail(\\"sdk_diagnostic_bound_exceeded\\");\\n    diagnostics[name].push(bytes);\\n    if (typeof encoding === \\"function\\") encoding(); else if (typeof callback === \\"function\\") callback();\\n    return true;\\n  };\\n  replace(process.stdout, \\"write\\", capture(\\"stdout\\")); replace(process.stderr, \\"write\\", capture(\\"stderr\\"));\\n  syncBuiltinESMExports();\\n  return () => {\\n    for (const [object, key, original] of changes.reverse()) object[key] = original;\\n    globalThis.fetch = previousFetch; syncBuiltinESMExports();\\n  };\\n}\\n\\n\\n","mac_current_refresh_flags_r2.mjs":"#!/usr/bin/env node\\n/** Current configured refresh flags and three already selected owner-state matches.\\n * No plugin service, provider request, mutex acquisition, or production write.\\n */\\nimport fs from \\"node:fs\\";\\nimport path from \\"node:path\\";\\nimport crypto from \\"node:crypto\\";\\nimport net from \\"node:net\\";\\nimport {createRequire} from \\"node:module\\";\\nimport {pathToFileURL} from \\"node:url\\";\\nimport {isDeepStrictEqual} from \\"node:util\\";\\nimport {protectReadPhase} from \\"./authbus_sdk_read_guard.mjs\\";\\nconst ROOT=\\"/Users/qianqi/heptabao-authbus-current-refresh-flags-20261106-r2\\";\\nconst LIVE=\\"/Users/qianqi/.openclaw\\",SDK=\\"/opt/homebrew/lib/node_modules/openclaw\\";\\nconst PLUGIN=LIVE+\\"/extensions/openclaw-authbus\\";\\nconst started=process.hrtime.bigint(),budget=Number(process.argv[2]),until=started+BigInt(Math.trunc(budget*1000000));\\nconst report={schema:\\"heptabao.current-main3-refresh-flags-readonly.r2\\",ok:false,\\n  providerCalled:false,refreshDispatched:false,productionWrites:0,productionMutexAcquired:false,\\n  j3160Contacted:false,activeGatewayBindingProven:false,pluginServiceStarted:false,\\n  credentialValuesOrDigestsPublished:false,profileIdsPublished:false,rawConfigurationHashPublished:false,\\n  selectionOrderReexecuted:false,scopeFromPriorActualSdkMainThree:true};\\nconst errors=new Set(),diagnostics={stdout:[],stderr:[],bytes:0,blockedAttempts:0};\\nlet restore=null,sqlGuard=null;\\nfunction need(value,code){if(!value){errors.add(code);throw Object.assign(new Error(code),{code});}}\\nfunction remaining(){need(process.hrtime.bigint()<until,\\"original_refresh_flags_deadline\\");}\\nconst plain=x=>x!==null&&typeof x===\\"object\\"&&!Array.isArray(x);\\nconst sha=raw=>crypto.createHash(\\"sha256\\").update(raw).digest(\\"hex\\");\\nconst identity=s=>[\\"dev\\",\\"ino\\",\\"uid\\",\\"gid\\",\\"mode\\",\\"nlink\\",\\"size\\",\\"mtimeNs\\",\\"ctimeNs\\"].map(k=>String(s[k]));\\nfunction read(file,max=1048576,privateFile=false){\\n remaining();const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);\\n try{\\n  const s=fs.fstatSync(fd,{bigint:true});need(s.isFile()&&s.nlink===1n&&s.size>=0n&&s.size<=BigInt(max)&&\\n    [0n,501n].includes(s.uid)&&(s.mode&18n)===0n,\\"bounded_refresh_flags_source\\");\\n  if(privateFile)need(s.uid===501n&&(s.mode&511n)===384n,\\"private_refresh_flags_input\\");\\n  const bytes=Buffer.alloc(Number(s.size)+1);let count=0;\\n  while(count<bytes.length){remaining();const n=fs.readSync(fd,bytes,count,bytes.length-count,null);if(!n)break;count+=n;}\\n  need(BigInt(count)===s.size&&isDeepStrictEqual(identity(s),identity(fs.fstatSync(fd,{bigint:true})))&&\\n    isDeepStrictEqual(identity(s),identity(fs.lstatSync(file,{bigint:true}))),\\"stable_refresh_flags_source\\");\\n  return bytes.subarray(0,count);\\n }finally{fs.closeSync(fd);}\\n}\\nfunction installSqlite(){\\n const sqlite=createRequire(import.meta.url)(\\"node:sqlite\\"),Original=sqlite.DatabaseSync;\\n const ledger={memory:0,readonly:0,denied:0,connections:[]};\\n sqlite.DatabaseSync=new Proxy(Original,{construct(target,args){\\n  const [file,options]=args,memory=file===\\":memory:\\";\\n  if(!memory&&!(file===LIVE+\\"/agents/main/agent/openclaw-agent.sqlite\\"&&options?.readOnly===true)){\\n    ledger.denied++;need(false,\\"main_owner_readonly_database_only\\");\\n  }\\n  const db=Reflect.construct(target,args,target),row={closed:false,closeAttempts:0};\\n  if(memory)ledger.memory++;else ledger.readonly++;ledger.connections.push(row);\\n  const close=db.close.bind(db);Object.defineProperty(db,\\"close\\",{value:()=>{row.closeAttempts++;const v=close();row.closed=true;return v;}});\\n  return db;\\n }});\\n return {ledger,restore(){sqlite.DatabaseSync=Original;}};\\n}\\nfunction exactPart(text,start,end){\\n need(text.split(start).length===2&&text.split(end).length===2,\\"unique_pinned_plugin_function_region\\");\\n const a=text.indexOf(start),b=text.indexOf(end,a);need(a>=0&&b>a,\\"ordered_pinned_plugin_function_region\\");return text.slice(a,b);\\n}\\nfunction purePlugin(index){\\n const base=exactPart(index,\\"function isRecord(value) {\\",\\"function identityDigest(credential) {\\");\\n const normalized=exactPart(index,\\"function normalizedConfig(raw) {\\",\\"export default definePluginEntry({\\");\\n const backoff=exactPart(index,\\"function readRefreshBackoff(stateDir) {\\",\\"function writeRefreshBackoff(stateDir, profiles) {\\");\\n const quarantine=exactPart(index,\\"function readBadRefreshQuarantine(stateDir) {\\",\\"function writeBadRefreshQuarantine(stateDir, profiles) {\\");\\n const statePath=exactPart(index,\\"function authBusStatePath(stateDir, name) {\\",\\"function readDigestMap(stateDir, name) {\\");\\n const build=new Function(\\"crypto\\",\\"fs\\",\\"path\\",base+statePath+normalized+backoff+quarantine+\\n   \\"return {credentialDigest,normalizedConfig,readRefreshBackoff,readBadRefreshQuarantine};\\");\\n return projections=>build(crypto,{readFileSync(file){\\n   const name=path.basename(file);need(file===LIVE+\\"/authbus/\\"+name&&Object.hasOwn(projections,name),\\"only_selected_private_state_projection\\");\\n   const projection=projections[name];if(!projection.present)throw Object.assign(new Error(\\"absent\\"),{code:\\"ENOENT\\"});\\n   return JSON.stringify({profiles:projection.profiles});\\n }},path);\\n}\\nfunction validateSelectedState(value,kind,ids){\\n need(plain(value)&&typeof value.present===\\"boolean\\"&&plain(value.profiles)&&Object.keys(value.profiles).every(id=>ids.includes(id)),\\"selected_state_projection_scope\\");\\n if(!value.present)need(Object.keys(value.profiles).length===0,\\"absent_state_has_no_selected_entries\\");\\n for(const row of Object.values(value.profiles)){\\n  need(plain(row)&&typeof row.digest===\\"string\\"&&/^[0-9a-f]{64}$/.test(row.digest),\\"typed_selected_state_generation\\");\\n  if(kind===\\"quarantine\\")need(typeof row.provider===\\"string\\"&&typeof row.reason===\\"string\\"&&Number.isFinite(row.firstDetectedAt)&&Number.isFinite(row.lastDetectedAt),\\"typed_selected_quarantine_entry\\");\\n  else need(Number.isFinite(row.failures)&&Number.isFinite(row.nextAttemptAt),\\"typed_selected_backoff_entry\\");\\n }\\n}\\nasync function kernelProbes(){\\n for(const [name,flag]of [[\\"protected-read\\",fs.constants.O_RDONLY],[\\"protected-write\\",fs.constants.O_WRONLY]]){\\n  let fd,denied=false;try{fd=fs.openSync(ROOT+\\"/\\"+name,flag|fs.constants.O_NOFOLLOW);}catch(e){denied=[\\"EPERM\\",\\"EACCES\\"].includes(e.code);}\\n  finally{if(fd!==undefined)fs.closeSync(fd);}need(denied,\\"owned_kernel_data_refusal\\");\\n }\\n const denied=await new Promise(resolve=>{\\n  const socket=new net.Socket();let code=null,connected=false;\\n  const timer=setTimeout(()=>socket.destroy(),Math.min(750,Math.max(1,Number((until-process.hrtime.bigint())/1000000n))));\\n  socket.once(\\"error\\",e=>{code=e.code;socket.destroy();});socket.once(\\"connect\\",()=>{connected=true;socket.destroy();});\\n  socket.once(\\"close\\",()=>{clearTimeout(timer);resolve(!connected&&[\\"EACCES\\",\\"EPERM\\"].includes(code));});socket.connect(9,\\"127.0.0.1\\");\\n });need(denied,\\"owned_kernel_network_refusal\\");report.kernelReadWriteNetworkRefusalsObserved=true;\\n}\\ntry{\\n need(process.platform===\\"darwin\\"&&process.getuid()===501&&Number.isFinite(budget)&&budget>0&&budget<=45000,\\"actual_mac_refresh_flags_runtime\\");\\n await kernelProbes();\\n need(process.env.TMPDIR===ROOT+\\"/output/tmp\\",\\"exact_owned_sdk_temp\\");\\n const tmp=fs.lstatSync(ROOT+\\"/output/tmp/openclaw-501\\");\\n need(tmp.isDirectory()&&!tmp.isSymbolicLink()&&tmp.uid===501&&(tmp.mode&511)===448,\\"precreated_owned_sdk_temp\\");\\n fs.accessSync(ROOT+\\"/output/tmp/openclaw-501\\",fs.constants.W_OK|fs.constants.X_OK);\\n const input=JSON.parse(read(ROOT+\\"/input.private.json\\",1048576,true));\\n need(input.schema===\\"heptabao.current-main3-refresh-flags-input.private.r1\\"&&input.host===\\"mac\\"&&\\n   input.selectionAuthorityJob===\\"1a1b197fa0e-fc05-79c0\\"&&input.currentConfigurationSameAsOriginal===true,\\"exact_refresh_flags_authority\\");\\n const ids=input.selectedOwners?.map(row=>row.profileId);\\n need(Array.isArray(ids)&&ids.length===3&&new Set(ids).size===3&&input.selectedOwners.every(row=>\\n   row.ownerAgent===\\"main\\"&&row.ownerAgentDir===LIVE+\\"/agents/main/agent\\"&&row.actualProvider===\\"openai\\"&&\\n   typeof row.profileId===\\"string\\"&&row.profileId.length>0&&row.profileId.length<=256),\\"exact_previously_selected_three_main_owners\\");\\n for(const [relative,pin]of Object.entries(input.sdkPins))need(sha(read(SDK+\\"/\\"+relative))===pin,\\"current_sdk_source_pin\\");\\n const index=read(PLUGIN+\\"/index.js\\");\\n need(sha(index)===input.pluginPins[\\"index.js\\"]&&sha(read(PLUGIN+\\"/bad-refresh-quarantine.js\\"))===input.pluginPins[\\"bad-refresh-quarantine.js\\"],\\"current_plugin_pure_source_pins\\");\\n const configBefore=read(LIVE+\\"/openclaw.json\\",1048576,true);\\n need(sha(configBefore)===input.configurationSha256,\\"original_config_generation_still_current\\");\\n const current=JSON.parse(configBefore),entry=current.plugins?.entries?.[\\"openclaw-authbus\\"];\\n need(plain(entry)&&plain(entry.config)&&isDeepStrictEqual(entry.config,input.pluginRawConfig)&&\\n   (entry.enabled??null)===input.pluginEntryEnabled,\\"exact_current_plugin_configuration\\");\\n validateSelectedState(input.states[\\"bad-refresh-quarantine.json\\"],\\"quarantine\\",ids);\\n validateSelectedState(input.states[\\"refresh-backoff.json\\"],\\"backoff\\",ids);\\n const pure=purePlugin(index.toString(\\"utf8\\"))(input.states),normalized=pure.normalizedConfig(entry.config);\\n // Pure-source synthetic gates prove raw opt-in/default and generation matching\\n // semantics without service registration or provider requests.\\n need(pure.normalizedConfig({}).leader===false&&pure.normalizedConfig({leader:true}).leader===true&&\\n   pure.normalizedConfig({leader:\\"true\\"}).leader===false&&pure.normalizedConfig({enforceRefreshLeases:true}).enforceRefreshLeases===true&&\\n   pure.normalizedConfig({enforceRefreshLeases:\\"true\\"}).enforceRefreshLeases===false,\\"actual_pure_flag_semantics\\");\\n sqlGuard=installSqlite();restore=protectReadPhase(diagnostics);\\n const sdk=await import(pathToFileURL(SDK+\\"/dist/store-DH33UrUj.js\\").href);\\n const quarantineApi=await import(pathToFileURL(PLUGIN+\\"/bad-refresh-quarantine.js\\").href);\\n const q=pure.readBadRefreshQuarantine(LIVE),b=pure.readRefreshBackoff(LIVE),now=Date.now();\\n need(q.size===Object.keys(input.states[\\"bad-refresh-quarantine.json\\"].profiles).length&&\\n   b.size===Object.keys(input.states[\\"refresh-backoff.json\\"].profiles).length,\\"actual_plugin_selected_state_parser_accepts_all_selected_entries\\");\\n const counts={selectedOwnerCount:3,actualSdkCredentialLookups:0,oauthCount:0,expiredAccessCount:0,refreshFieldPresentCount:0,\\n   quarantineSelectedEntryCount:q.size,quarantineCurrentGenerationMatchCount:0,quarantineOtherGenerationCount:0,\\n   backoffSelectedEntryCount:b.size,backoffCurrentGenerationMatchCount:0,backoffOtherGenerationCount:0,\\n   currentBackoffDeferredCount:0,currentBackoffElapsedCount:0,quarantineReasonCounts:{}};\\n const reasons=new Set([\\"refresh_token_reused\\",\\"invalid_refresh_token\\",\\"token_invalidated\\",\\"invalid_grant\\",\\"revoked\\"]);\\n for(const id of ids){\\n   remaining();sdk.t();const credential=sdk.a({agentDir:LIVE+\\"/agents/main/agent\\",profileId:id});\\n   need(plain(credential)&&credential.type===\\"oauth\\"&&credential.provider===\\"openai\\"&&\\n     typeof credential.access===\\"string\\"&&credential.access.length>0&&typeof credential.refresh===\\"string\\"&&credential.refresh.length>0&&\\n     Number.isFinite(credential.expires)&&![\\"keyRef\\",\\"tokenRef\\",\\"accessRef\\",\\"refreshRef\\",\\"oauthRef\\"].some(key=>key in credential),\\"actual_main_selected_oauth_credential\\");\\n   counts.actualSdkCredentialLookups++;counts.oauthCount++;counts.refreshFieldPresentCount++;\\n   if(credential.expires<=now)counts.expiredAccessCount++;\\n   const digest=pure.credentialDigest(credential),quarantine=q.get(id),backoff=b.get(id);\\n   if(quarantine){\\n     if(quarantineApi.isDigestQuarantined(q,id,digest))counts.quarantineCurrentGenerationMatchCount++;\\n     else counts.quarantineOtherGenerationCount++;\\n     const reason=reasons.has(quarantine.reason)?quarantine.reason:\\"other\\";\\n     counts.quarantineReasonCounts[reason]=(counts.quarantineReasonCounts[reason]??0)+1;\\n   }\\n   if(backoff){\\n     if(backoff.digest===digest){counts.backoffCurrentGenerationMatchCount++;\\n       if(backoff.nextAttemptAt>now)counts.currentBackoffDeferredCount++;else counts.currentBackoffElapsedCount++;}\\n     else counts.backoffOtherGenerationCount++;\\n   }\\n }\\n sdk.t();need(diagnostics.blockedAttempts===0&&sqlGuard.ledger.denied===0&&\\n   sqlGuard.ledger.connections.every(x=>x.closed&&x.closeAttempts===1),\\"readonly_sdk_no_effects_and_all_handles_closed\\");\\n restore();restore=null;sqlGuard.restore();\\n need(sha(read(LIVE+\\"/openclaw.json\\",1048576,true))===input.configurationSha256,\\"current_config_unchanged_after_sdk\\");\\n for(const [relative,pin]of Object.entries(input.sdkPins))need(sha(read(SDK+\\"/\\"+relative))===pin,\\"sdk_source_after\\");\\n for(const [name,pin]of Object.entries(input.pluginPins))need(sha(read(PLUGIN+\\"/\\"+name))===pin,\\"plugin_source_after\\");\\n report.configuredFlags={pluginEntryEnabled:typeof entry.enabled===\\"boolean\\"?entry.enabled:null,pluginsGloballyDisabled:current.plugins?.enabled===false,\\n   leader:normalized.leader,enforceRefreshLeases:normalized.enforceRefreshLeases,publishNew:normalized.publishNew,\\n   manageOrder:normalized.manageOrder,schedulerMode:normalized.schedulerMode};\\n report.selectedCurrentState=counts;\\n report.stateFilePresence=Object.fromEntries(Object.entries(input.states).map(([name,value])=>[name,value.present]));\\n report.purePluginFlagGatesPassed=5;report.actualPluginPureReadersExecuted=true;report.actualSdkCurrentOwnerLookupExecuted=true;\\n report.pluginRefreshBranchDependsOnConfiguredLeader=true;report.configurationDoesNotProveAlreadyRunningServiceFlags=true;\\n report.providerValidityQualified=false;remaining();report.ok=true;\\n}catch(error){\\n report.errorCode=errors.has(error?.code)?error.code:\\"current_refresh_flags_refused\\";\\n report.errorType=[\\"Error\\",\\"TypeError\\",\\"RangeError\\",\\"SyntaxError\\"].includes(error?.name)?error.name:\\"Other\\";\\n}finally{\\n if(restore)restore();\\n if(sqlGuard){sqlGuard.restore();const l=sqlGuard.ledger;report.sqliteReadScope={memoryOpenCount:l.memory,readOnlyFileOpenCount:l.readonly,\\n   returnedHandleCount:l.connections.length,deniedOpenCount:l.denied,allReturnedHandlesClosedOnce:l.connections.every(x=>x.closed&&x.closeAttempts===1)};}\\n report.guardDeniedAttempts=diagnostics.blockedAttempts;report.capturedDiagnosticBytes=diagnostics.bytes;\\n diagnostics.stdout.length=0;diagnostics.stderr.length=0;report.elapsedSeconds=Number(process.hrtime.bigint()-started)/1e9;\\n process.stdout.write(JSON.stringify(report)+\\"\\\\n\\");\\n}\\nprocess.exitCode=report.ok?0:1;\\n"}}')
PINS={
 'authbus_current_auth_wal.py':'ad443869e259da06de2be71131e5d1854680477d1cf77248e05a3c1704160f8c',
 'mac_guarded_current_capture_r3.py':'606b5df58909ebedc035ebbff6a4aa5e754d19c6a7e0f5e4e88c9ddfc57c2693',
 'mac_registry_readonly_wal_r1.py':'60d5e5874c281af2e19fee55bc4b2242627f69b500f1af1d6b5b22e16120bfed',
 'kv2_dr_process_custody.py':'669e2cd1d9ee597529c08b88f3fc21c813d4ff7b57f3792381baa44fbdbe7008',
 'owned_process.py':'0ee96c9f43b50ebd57ee8f0ef95f2431c441ec02c1799992588dbf50768745d0'}
report={'schema':'heptabao.current-main3-refresh-flags-owned.r2','ok':False,
 'providerCalled':False,'refreshDispatched':False,'productionWrites':0,'productionMutexAcquired':False,
 'j3160Contacted':False,'serviceActions':0,'credentialValuesOrDigestsPublished':False,
 'profileIdsPublished':False,'rawConfigurationHashPublished':False,'wholeCacheFileCopied':False,
 'registryDatabaseOpened':False,'selectionOrderReexecuted':False,
 'sharedSeconds':45,'supervisorSeconds':70,'automaticRetry':False,
 'configuredFlagsDoNotProveRunningServiceConfiguration':True}
errors=set();created=False;owner=None;source=None;bundle=None;state_guard=None;children=[]
def need(value,code):
 if not value:errors.add(code);raise RuntimeError(code)
def remaining(cap=45):
 left=UNTIL-time.monotonic();need(left>0,'original_refresh_flags_deadline');return min(left,cap)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def ident(s):return tuple(str(getattr(s,k)) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def read(path,cap=1048576,private=False):
 remaining();fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_uid in (0,501) and before.st_nlink==1
    and not stat.S_IMODE(before.st_mode)&0o022 and 0<=before.st_size<=cap,'bounded_public_or_owned_input')
  if private:need(before.st_uid==501 and stat.S_IMODE(before.st_mode)==0o600,'private_scope_input_custody')
  out=bytearray()
  while len(out)<=cap:
   remaining();part=os.read(fd,min(65536,cap+1-len(out)))
   if not part:break
   out.extend(part)
  need(len(out)==before.st_size and ident(before)==ident(os.fstat(fd))==ident(Path(path).lstat()),'stable_whole_input')
  return bytes(out)
 finally:os.close(fd)
def new(path,data):
 raw=data if isinstance(data,bytes) else data.encode();need(len(raw)<=1048576,'bounded_owned_projection')
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  view=memoryview(raw)
  while view:
   remaining();n=os.write(fd,view);need(n>0,'owned_projection_write_progress');view=view[n:]
  os.fsync(fd)
 finally:os.close(fd)
 fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
def validate_authority(value,job):
 need(value['job_id']==job and value['state']=='succeeded' and value['exit_code']==0
   and all(value[k] is True for k in ('output_complete','output_durable','terminal_publication_confirmed'))
   and all(value[k] is False for k in ('timed_out','cancelled','automatic_retry')),'original_known_public_authority')
class StateInputs:
 """Only two named state files; held no-follow parents and whole-file full9."""
 def __init__(self):self.rows=[];self.absent=set();self.opened=0;self.closed=0;self.finished=False;self.close_errors=[];self.observations=[];self.changes=[];self.verification_count=0
 def hold_parent(self,name,parent=None):
  remaining();fd=os.open(name if parent is None else Path(name).name,
   os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,**({} if parent is None else {'dir_fd':parent}))
  self.opened+=1
  try:
   s=os.fstat(fd);need(stat.S_ISDIR(s.st_mode) and s.st_uid in (0,501) and not stat.S_IMODE(s.st_mode)&0o022,'state_parent_custody')
  except BaseException:os.close(fd);self.closed+=1;raise
  self.rows.append({'path':str(name),'fd':fd,'expected':ident(s)});return fd
 def get(self,name):
  need(name in STATES,'only_two_known_state_paths');pathname=LIVE/'authbus'/name
  parent=self.hold_parent(Path('/'))
  for part in (Path('/Users'),Path('/Users/qianqi'),LIVE,LIVE/'authbus'):
   try:parent=self.hold_parent(part,parent)
   except FileNotFoundError:
    need(part==LIVE/'authbus','only_known_optional_state_directory');self.absent.update((str(part),str(pathname)));return None
  try:fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
  except FileNotFoundError:self.absent.add(str(pathname));return None
  self.opened+=1;s=os.fstat(fd)
  self.rows.append({'path':str(pathname),'fd':fd,'expected':ident(s)})
  need(stat.S_ISREG(s.st_mode) and s.st_uid==501 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600
    and 0<s.st_size<=1048576,'selected_state_file_custody')
  data=bytearray()
  while len(data)<=1048576:
   remaining();part=os.read(fd,min(65536,1048577-len(data)))
   if not part:break
   data.extend(part)
  need(len(data)==s.st_size and ident(s)==ident(os.fstat(fd))==ident(pathname.lstat()),'state_full_file_unchanged')
  return bytes(data)
 def verify(self):
  self.verification_count+=1;changed=False
  fields=('dev','ino','uid','gid','mode','nlink','size','mtime_ns','ctime_ns')
  def role(name):
   if name==str(LIVE/'authbus'):return 'state_directory'
   if name in {str(LIVE/'authbus'/item) for item in STATES}:return 'state_file'
   return 'ancestor_directory'
  for ordinal,row in enumerate(self.rows,1):
   remaining();current=None;held=None;unavailable=False
   try:current=ident(Path(row['path']).lstat())
   except OSError:unavailable=True
   if not self.finished:
    try:held=ident(os.fstat(row['fd']))
    except OSError:unavailable=True
   changed_fields=[]
   if unavailable:changed_fields.append('metadata_unavailable')
   for index,field in enumerate(fields):
    if (current is not None and current[index]!=row['expected'][index]) or (held is not None and held[index]!=row['expected'][index]):changed_fields.append(field)
   self.observations.append({'verificationOrdinal':self.verification_count,'sourceOrdinal':ordinal,
    'sourceRole':role(row['path']),'expectedFull9':row['expected'],'currentFull9':current,
    'heldFull9':held,'descriptorsAlreadyClosed':self.finished})
   if changed_fields:
    changed=True;self.changes.append({'verificationOrdinal':self.verification_count,
      'sourceOrdinal':ordinal,'sourceRole':role(row['path']),'changedFields':changed_fields})
  for ordinal,name in enumerate(sorted(self.absent),len(self.rows)+1):
   remaining();current=None;absent=False
   try:current=ident(Path(name).lstat())
   except FileNotFoundError:absent=True
   except OSError:pass
   self.observations.append({'verificationOrdinal':self.verification_count,'sourceOrdinal':ordinal,
    'sourceRole':role(name),'expectedAbsence':True,'currentFull9':current,'currentAbsence':absent})
   if not absent:
    changed=True;self.changes.append({'verificationOrdinal':self.verification_count,
      'sourceOrdinal':ordinal,'sourceRole':role(name),'changedFields':['absence']})
  need(not changed,'state_full9_name_or_absence_unchanged')
 def close(self):
  if self.finished:return
  self.finished=True
  for row in reversed(self.rows):
   try:os.close(row['fd']);self.closed+=1
   except OSError:self.close_errors.append('original_descriptor_close_unknown')
 def public(self):return {'openedDescriptors':self.opened,'closedDescriptors':self.closed,
   'allOwnedDescriptorsClosed':self.finished and self.opened==self.closed and not self.close_errors,
   'closeErrors':list(self.close_errors),'full9ComparisonWeakened':False,
   'verificationCount':self.verification_count,'changedRows':list(self.changes)}
def fence():
 remaining();source.verify();auth.verify_auth_bundle(source,bundle,until=UNTIL);state_guard.verify()
def code_fence():
 for name,pin in PINS.items():need(sha(read(QUAL/'qa'/name))==pin,'qualified_capture_source_pin')
 for relative,pin in {**PAYLOAD['sdkPins'],**PAYLOAD['additionalSdkPins']}.items():need(sha(read(SDK/relative))==pin,'current_sdk_public_source_pin')
 for name,pin in PAYLOAD['pluginPins'].items():need(sha(read(PLUGIN/name))==pin,'current_plugin_public_source_pin')
 need(sha(read(Path(NODE),2097152))=='a46ed02589ca3af795237111ff854262064f8ff5c5b58d75c1509f37311eb15e','exact_node_runtime')
 need(sha(read(Path(PYTHON),2097152))=='cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13','exact_python_runtime')
def close_streams(child):
 for stream in (child.stdin,child.stdout,child.stderr):
  if stream is not None and not stream.closed:stream.close()
try:
 os.umask(0o077)
 need(sys.platform=='darwin' and os.getuid()==501 and os.path.realpath(sys.executable)==PYTHON,'actual_mac_refresh_flags_owner')
 validate_authority(PAYLOAD['custodyAuthority'],'1a1b141ef40-fc05-7750')
 proof=read(QUAL/'result.public.json',65536)
 need(len(proof)==58701 and sha(proof)=='67cb6bb6804c7285f13f373f6af607405ada39ab734423bf328ffe27915cee4e','original_18_case_qualification')
 q=json.loads(proof);need(q['ok'] and q['allCasesMatched'] and q['allOwnedClosed'] and q['custody']['passed_process_custody'],'original_qualified_readonly_capture')
 validate_authority(PAYLOAD['configAuthority'],'1a1b137a21d-fc05-76f8')
 validate_authority(PAYLOAD['orderAuthority'],'1a1b197fa0e-fc05-79c0')
 for path,pin in [(CONFIG_ROOT/'result.public.json',PAYLOAD['configResult']),(ORDER_ROOT/'result.public.json',PAYLOAD['orderResult'])]:
  raw=read(path,65536);need(len(raw)==pin['bytes'] and sha(raw)==pin['sha256'],'original_scope_public_receipt_exact')
 code_fence();sys.path.insert(0,str(QUAL/'qa'))
 import authbus_current_auth_wal as auth
 import kv2_dr_process_custody as custody
 ROOT.mkdir(mode=0o700,exist_ok=False);created=True
 for name in ('code','output','output/tmp','output/tmp/openclaw-501'):(ROOT/name).mkdir(mode=0o700,exist_ok=False)
 new(ROOT/'protected-read',b'owned synthetic protected read probe\n');new(ROOT/'protected-write',b'owned synthetic protected write probe\n')
 for name,raw in PAYLOAD['sources'].items():
  need(name in ('mac_current_refresh_flags_r2.mjs','authbus_sdk_read_guard.mjs') and sha(raw.encode())==PAYLOAD['sourcePins'][name],'prepared_readonly_worker_source')
  new(ROOT/'code'/name,raw)
 binding=auth.strict_json(read(BINDING,262144,True));mapping=auth.strict_json(read(MAPPING,1048576,True))
 need(binding['schema']=='heptabao.authbus-current-source-allowlist.private.r1' and binding['sourceRoot']==str(LIVE)
   and mapping['schema']=='heptabao.actual-sdk-owned-profile-mapping.private.r1' and mapping['host']=='mac'
   and mapping['configurationSha256']==binding['configurationSha256'] and mapping['configurationIdentity']==binding['configurationIdentity']
   and mapping['sdkSourcePins']==PAYLOAD['sdkPins'] and mapping['constraints']['selectionOrderExecuted'] is True,'original_selected_owner_scope')
 selected=mapping['selectedOwners'];need(isinstance(selected,list) and len(selected)==3
   and len({r['profileId'] for r in selected})==3 and all(r['ownerAgent']=='main' and r['ownerAgentDir']==str(LIVE/'agents/main/agent')
     and r['actualProvider']=='openai' and isinstance(r['profileId'],str) and 0<len(r['profileId'])<=256 for r in selected),'exact_three_selected_main_owners')
 source=auth.AuthInputs(until=UNTIL,critical=contextlib.nullcontext,cancelled=lambda:False)
 raw=source.read(LIVE/'openclaw.json');cfg=auth.strict_json(raw)
 need(sha(raw)==binding['configurationSha256'] and list(source.files[str(LIVE/'openclaw.json')]['expected'])==binding['configurationIdentity'],
   'original_configuration_still_current_full9')
 need(set(cfg.get('auth',{}).get('profiles',{}))=={row['profileId'] for row in binding['registeredProfiles']},'same_current_registered_configuration')
 entry=cfg.get('plugins',{}).get('entries',{}).get('openclaw-authbus')
 need(isinstance(entry,dict) and isinstance(entry.get('config'),dict),'current_authbus_config_entry')
 bundle=auth.auth_wal_database(source,'main');state_guard=StateInputs();states={}
 selected_ids={r['profileId'] for r in selected}
 for name in STATES:
  raw_state=state_guard.get(name)
  if raw_state is None:states[name]={'present':False,'profiles':{}};continue
  value=auth.strict_json(raw_state)
  need(isinstance(value,dict) and isinstance(value.get('profiles'),dict),'known_state_file_structure_not_silently_ignored')
  states[name]={'present':True,'profiles':{key:item for key,item in value['profiles'].items() if key in selected_ids}}
 input={'schema':'heptabao.current-main3-refresh-flags-input.private.r1','host':'mac',
  'selectionAuthorityJob':'1a1b197fa0e-fc05-79c0','currentConfigurationSameAsOriginal':True,
  'configurationSha256':binding['configurationSha256'],'selectedOwners':selected,
  'pluginRawConfig':entry['config'],'pluginEntryEnabled':entry.get('enabled'),
  'states':states,'sdkPins':{**PAYLOAD['sdkPins'],**PAYLOAD['additionalSdkPins']},'pluginPins':PAYLOAD['pluginPins']}
 new(ROOT/'input.private.json',json.dumps(input,sort_keys=True).encode()+b'\n')
 paths={ROOT,ROOT/'input.private.json',LIVE/'openclaw.json',PLUGIN/'index.js',PLUGIN/'bad-refresh-quarantine.js'}
 for pathname in tuple(paths):paths.update(pathname.parents)
 database=LIVE/'agents/main/agent/openclaw-agent.sqlite'
 for suffix in ('','-wal','-shm','-journal'):
  pathname=Path(str(database)+suffix);paths.add(pathname);paths.update(pathname.parents)
 lines=['(version 1)','(deny default)','(allow process*)','(allow signal (target children))',
  '(allow sysctl-read)','(allow mach-lookup)','(allow file-read-metadata)']
 for name in ('/System','/usr','/bin','/sbin','/Library','/private/etc','/opt/homebrew','/dev/fd'):
  lines.append('(allow file-read* (subpath '+json.dumps(name)+'))')
 for name in (ROOT/'code',ROOT/'output'):lines.append('(allow file-read* (subpath '+json.dumps(str(name))+'))')
 for name in sorted(paths,key=str):lines.append('(allow file-read* (literal '+json.dumps(str(name))+'))')
 for name in ('/dev/null','/dev/urandom','/dev/random'):lines.append('(allow file-read* (literal '+json.dumps(name)+'))')
 lines.extend(['(allow file-write* (subpath '+json.dumps(str(ROOT/'output'))+'))','(allow file-write* (literal "/dev/null"))'])
 policy='\n'.join(lines)+'\n';new(ROOT/'reader.sb',policy)
 env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','HOME':'/Users/qianqi','NODE_NO_WARNINGS':'1',
  'TMPDIR':str(ROOT/'output/tmp'),'OPENCLAW_STATE_DIR':str(LIVE),
  'OPENCLAW_CONFIG_PATH':str(LIVE/'openclaw.json'),'OPENCLAW_AUTH_STORE_READONLY':'1'}
 original_popen=subprocess.Popen;original_killpg=os.killpg;fence()
 with custody.activated() as owner:
  child=subprocess.Popen([NODE,'--check',str(ROOT/'code/mac_current_refresh_flags_r2.mjs')],
   stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=str(ROOT),env=env)
  children.append(child);out,err=child.communicate(timeout=remaining(5));close_streams(child)
  need(child.returncode==0 and not out and not err,'actual_readonly_worker_syntax')
  fence()
  child=subprocess.Popen(['/usr/bin/sandbox-exec','-f',str(ROOT/'reader.sb'),NODE,'--no-warnings',
    str(ROOT/'code/mac_current_refresh_flags_r2.mjs'),str(int(remaining(30)*1000))],stdin=subprocess.DEVNULL,
    stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=str(ROOT),env=env)
  children.append(child);out,err=child.communicate(timeout=remaining(30));close_streams(child)
  need(len(out)<=65536 and len(err)<=16384,'bounded_readonly_worker_output')
  new(ROOT/'output/child.stdout.public.json',out);new(ROOT/'output/child.stderr.private',err)
  value=json.loads(out);report['observation']=value;report['stderrBytes']=len(err);report['childExitCode']=child.returncode
  need(child.returncode==0 and not err and value.get('ok') is True,'actual_current_refresh_flags_complete')
  owner.assert_retired()
 report['custody']=owner.receipt()
 need(report['custody']['passed_process_custody'] and report['custody']['original_count']==2
   and subprocess.Popen is original_popen and os.killpg is original_killpg,'all_original_flags_children_closed')
 fence();closed_names=[(name,tuple(item['expected'])) for name,item in source.files.items()];closed_absences=list(source.absent)
 source.close();state_guard.close();state_guard.verify()
 need(source.public()['allOwnedDescriptorsClosed'] and state_guard.public()['allOwnedDescriptorsClosed'],'all_source_state_descriptors_closed')
 for name,expected in closed_names:remaining();need(ident(Path(name).lstat())==expected,'closed_current_auth_full9_unchanged')
 for name in closed_absences:
  remaining()
  try:Path(name).lstat()
  except FileNotFoundError:continue
  raise RuntimeError('closed_current_auth_absence_changed')
 code_fence()
 for name,pin in PAYLOAD['sourcePins'].items():need(sha(read(ROOT/'code'/name))==pin,'owned_worker_source_after')
 remaining();report.update(ok=True,currentConfigurationWholeBytesAndFull9Exact=True,
   currentMainAuthFull9Exact=True,currentTwoKnownStateFilesFull9OrAbsenceExact=True,
   allSourceDescriptorsClosed=True,sourcePins=PAYLOAD['sourcePins'],sdkSourcePins={**PAYLOAD['sdkPins'],**PAYLOAD['additionalSdkPins']},
   pluginSourcePins=PAYLOAD['pluginPins'],sandboxProfileSha256=sha(policy.encode()),
   actualCurrentMainCredentialLookupCount=3,providerValidityQualified=False)
except BaseException as error:
 report['errorCode']=str(error) if str(error) in errors else 'current_refresh_flags_refused'
 report['errorType']=type(error).__name__
finally:
 for child in children:close_streams(child)
 if owner is not None:report['custody']=owner.receipt()
 if source is not None:source.close();report['sourceGuardClosure']=source.public()
 if state_guard is not None:
  state_guard.close();report['stateGuardClosure']=state_guard.public()
  try:
   new(ROOT/'output/state-generation-observations.private.json',json.dumps({
    'schema':'heptabao.current-two-state-private-generation-diagnostics.r2',
    'containsCredentialValues':False,'containsCredentialDigests':False,
    'observations':state_guard.observations},sort_keys=True).encode()+b'\n')
   report['privateFull9DiagnosticSaved']=True
  except BaseException:
   report['privateFull9DiagnosticSaved']=False;report['ok']=False
 report['elapsedSeconds']=round(time.monotonic()-START,6)
 if created:
  try:new(ROOT/'result.public.json',json.dumps(report,sort_keys=True).encode()+b'\n')
  except BaseException:report['ok']=False;report['resultPublicationFailed']=True
 print(json.dumps(report,sort_keys=True))
raise SystemExit(0 if report['ok'] else 1)
