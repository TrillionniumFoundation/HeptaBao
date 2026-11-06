#!/usr/bin/env node
/** Actual configured model-route counts; no auth database query, runtime session read, provider call or credential export. */
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import net from "node:net";
import childProcess from "node:child_process";
import {createRequire} from "node:module";
import {pathToFileURL} from "node:url";
import {isDeepStrictEqual} from "node:util";
import {protectReadPhase} from "./authbus_sdk_read_guard.mjs";
const ROOT="/Users/qianqi/heptabao-authbus-current-sdk-model-routes-20261106-r1";
const LIVE="/Users/qianqi/.openclaw";
const SDK="/opt/homebrew/lib/node_modules/openclaw";
const AGENTS=["main","trnm","hepta-ui","hepta","hepta-backend"];
const started=process.hrtime.bigint();
const budgetMs=Number(process.argv[2]);
const until=started+BigInt(Math.trunc(budgetMs*1e6));
const report={schema:"heptabao.current-sdk-configured-model-routes-readonly.r1",ok:false,
  productionConfigurationChanged:false,productionDatabaseChanged:false,
  credentialValuesOrDigestsIncluded:false,rawClientConfigHashIncluded:false,profileIdsPublished:false,
  j3160Contacted:false,providerCalled:false,refreshDispatched:false,
  aliasResolutionExecuted:false,authProfileOrderExecuted:false,modelRouteFunctionsExecuted:false,
  credentialDatabaseOpened:false,runtimeSessionDataRead:false,sessionOrMessageOverridesExecuted:false,
  activeGatewayCredentialBindingProven:false,migrationAllowlistAuthorized:false,
  credentialExported:false,privateModelRoutingProjectionPublished:false,kernelDenials:[],agents:[]};
const diagnostics={stdout:[],stderr:[],bytes:0,blockedAttempts:0};
const errorCodes=new Set();
function need(value,code){if(!value){errorCodes.add(code);const e=new Error(code);e.code=code;throw e;}}
function remaining(){need(process.hrtime.bigint()<until,"original_sdk_owner_deadline");}
function sha(data){return crypto.createHash("sha256").update(data).digest("hex");}
function identity(stat){return ["dev","ino","uid","gid","mode","nlink","size","mtimeNs","ctimeNs"].map(key=>String(stat[key]));}
function read(pathname,cap=1048576,privateFile=false){
  remaining();const fd=fs.openSync(pathname,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
  try{
    const before=fs.fstatSync(fd,{bigint:true});
    need(before.isFile()&&before.nlink===1n&&before.size>=0n&&before.size<=BigInt(cap),"bounded_sdk_input_file");
    if(privateFile)need(before.uid===501n&&(before.mode&511n)===384n,"private_sdk_input_custody");
    const buf=Buffer.alloc(Number(before.size)+1);let count=0;
    while(count<buf.length){remaining();const got=fs.readSync(fd,buf,count,buf.length-count,null);if(!got)break;count+=got;}
    need(count===Number(before.size)&&isDeepStrictEqual(identity(before),identity(fs.fstatSync(fd,{bigint:true})))
      &&isDeepStrictEqual(identity(before),identity(fs.lstatSync(pathname,{bigint:true}))),"same_sdk_input_file");
    return buf.subarray(0,count);
  }finally{fs.closeSync(fd);}
}
function bucket(value,allowed){return allowed.includes(value)?value:"other";}
function increment(object,key){object[key]=(object[key]??0)+1;}
function writePrivate(filename,value){
  const raw=Buffer.from(JSON.stringify(value)+"\n");
  need(raw.length<=1048576,"bounded_private_sdk_owner_mapping");
  const fd=fs.openSync(filename,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
  try{fs.writeFileSync(fd,raw);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
  const directory=fs.openSync(path.dirname(filename),fs.constants.O_RDONLY|fs.constants.O_DIRECTORY|fs.constants.O_NOFOLLOW);
  try{fs.fsyncSync(directory);}finally{fs.closeSync(directory);}
}
function installSqliteGuard(allowed){
  const sqlite=createRequire(import.meta.url)("node:sqlite"),Original=sqlite.DatabaseSync;
  const ledger={opens:0,memoryOpens:0,readOnlyFileOpens:0,denials:0,connections:[]};
  sqlite.DatabaseSync=new Proxy(Original,{construct(target,args){
    const [filename,options]=args;
    const memory=filename===":memory:";
    if(!memory&&!(typeof filename==="string"&&allowed.has(path.resolve(filename))&&options?.readOnly===true)){
      ledger.denials++;need(false,"sqlite_open_outside_exact_readonly_auth_scope");
    }
    ledger.opens++;
    if(memory)ledger.memoryOpens++;else ledger.readOnlyFileOpens++;
    const db=Reflect.construct(target,args,target),record={memory,closeAttempts:0,closed:false};
    ledger.connections.push(record);
    const close=db.close.bind(db);
    Object.defineProperty(db,"close",{value:(...closeArgs)=>{record.closeAttempts++;const value=close(...closeArgs);record.closed=true;return value;}});
    return db;
  }});
  return {ledger,restore(){sqlite.DatabaseSync=Original;}};
}
let restore=null,sqlGuard=null,privateMapping=null,input=null;
try{
  need(process.platform==="darwin"&&process.getuid()===501&&Number.isFinite(budgetMs)&&budgetMs>0&&budgetMs<=45000,"exact_actual_mac_sdk_owner");
  for(const [name,target,flags]of[
    ["owned_probe_write",ROOT+"/write-fence",fs.constants.O_WRONLY],
    ["owned_sidecar_create",ROOT+"/write-fence-sidecar",fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL]]){
    let denied=false;
    try{const fd=fs.openSync(target,flags,0o600);fs.closeSync(fd);}catch(e){denied=["EPERM","EACCES"].includes(e.code);}
    need(denied,"kernel_write_fence_required");report.kernelDenials.push({case:name,denied:true});
  }
  const network=await new Promise(resolve=>{
    let finished=false;const socket=new net.Socket();
    const done=value=>{if(finished)return;finished=true;clearTimeout(timer);socket.destroy();resolve(value);};
    const timer=setTimeout(()=>done(false),750);
    socket.once("error",e=>done(["EPERM","EACCES"].includes(e.code)));
    socket.once("connect",()=>done(false));socket.connect(9,"127.0.0.1");
  });
  need(network,"kernel_network_fence_required");report.kernelDenials.push({case:"loopback_connect",denied:true});
  const ownedTmp=ROOT+"/output/tmp";
  need(process.env.TMPDIR===ownedTmp,"exact_owned_sdk_temp_override");
  const tmpStat=fs.lstatSync(ownedTmp+"/openclaw-501");
  need(tmpStat.isDirectory()&&!tmpStat.isSymbolicLink()&&tmpStat.uid===501&&(tmpStat.mode&0o777)===0o700,"owned_sdk_temp_precreated");
  fs.accessSync(ownedTmp+"/openclaw-501",fs.constants.W_OK|fs.constants.X_OK);
  report.ownedTempFallbackPrecreated=true;
  input=JSON.parse(read(ROOT+"/input.private.json",1048576,true));
  need(input.schema==="heptabao.current-sdk-owner-input.private.r1"&&input.host==="mac"
    &&isDeepStrictEqual(input.agents.map(x=>x.agent),AGENTS),"exact_private_owner_input");
  const rawConfig=read(LIVE+"/openclaw.json",1048576,true);
  need(sha(rawConfig)===input.configurationSha256,"current_config_matches_private_binding");
  const cfg=JSON.parse(rawConfig);
  need(isDeepStrictEqual(Object.keys(cfg.auth?.profiles??{}).sort(),[...input.registeredProfileIds].sort()),"same_current_registered_profile_ids");
  const sourcePins={};
  for(const [relative,expected]of Object.entries(input.sdkPins)){
    const value=sha(read(path.join(SDK,relative),1048576));
    need(value===expected,"actual_sdk_source_pin_before");sourcePins[relative]=value;
  }
  const pkg=JSON.parse(read(path.join(SDK,"package.json"),262144));
  need(pkg.version==="2026.7.1-2","actual_installed_sdk_version");
  const allowedDirs=new Map(input.agents.map(x=>[path.resolve(x.agentDir),x.agent]));
  need(allowedDirs.size===5,"exact_five_owner_directories");
  sqlGuard=installSqliteGuard(new Set());
  restore=protectReadPhase(diagnostics);
  const expectDenied=action=>{let blocked=false;try{action();}catch{blocked=true;}need(blocked,"js_read_guard_negative_case");};
  expectDenied(()=>fs.writeFileSync(ROOT+"/output/guard-must-not-exist","probe"));
  expectDenied(()=>globalThis.fetch("http://127.0.0.1:9"));
  expectDenied(()=>childProcess.spawn("/usr/bin/true",[]));
  const sqlite=createRequire(import.meta.url)("node:sqlite");
  expectDenied(()=>new sqlite.DatabaseSync(ROOT+"/output/guard-must-not-exist.sqlite"));
  need(diagnostics.blockedAttempts===3&&sqlGuard.ledger.denials===1,"all_four_js_sqlite_guards_exercised");
  const baseDenials=diagnostics.blockedAttempts,baseSqlDenials=sqlGuard.ledger.denials;
  report.guardNegativeCasesPassed=4;
  report.phase="import_agent_scope";
  const scope=await import(pathToFileURL(path.join(SDK,"dist/agent-scope-config-BxAUeF6t.js")).href);
  report.phase="import_actual_model_scope";
  const higher=await import(pathToFileURL(path.join(SDK,"dist/agent-scope-B2Pk_xhT.js")).href);
  const modelRefs=await import(pathToFileURL(path.join(SDK,"dist/model-selection-shared-iHJcI8fT.js")).href);
  const providerIds=await import(pathToFileURL(path.join(SDK,"dist/provider-id-Dq06Bcx6.js")).href);
  const aliasApi=await import(pathToFileURL(path.join(SDK,"dist/provider-auth-aliases-Cp2PXhsh.js")).href);
  const indexApi=await import(pathToFileURL(path.join(SDK,"dist/installed-plugin-index-store-CWgFGnm0.js")).href);
  const metadataApi=await import(pathToFileURL(path.join(SDK,"dist/plugin-metadata-snapshot-rpSrEgGf.js")).href);
  const currentMetadata=await import(pathToFileURL(path.join(SDK,"dist/current-plugin-metadata-snapshot-CmOpmveB.js")).href);
  const record=Object.fromEntries(input.registry.columns.map((name,index)=>[name,input.registry.row[index]]));
  need(record.index_key==="installed-plugin-index","actual_fixed_registry_key");
  const indexValue={version:Number(record.version),hostContractVersion:record.host_contract_version,
    compatRegistryVersion:record.compat_registry_version,migrationVersion:Number(record.migration_version),
    policyHash:record.policy_hash,generatedAtMs:Number(record.generated_at_ms),
    installRecords:JSON.parse(record.install_records_json),plugins:JSON.parse(record.plugins_json),
    diagnostics:JSON.parse(record.diagnostics_json),
    ...(record.warning?{warning:record.warning}:{}),...(record.refresh_reason?{refreshReason:record.refresh_reason}:{})};
  const index=indexApi.n(indexValue);
  need(index&&index.plugins.length===input.registryPluginCount,"actual_sdk_accepts_captured_registry");
  report.phase="actual_provided_registry_metadata";
  const metadata=metadataApi.i({config:cfg,index,env:process.env,stateDir:LIVE});
  need(metadata?.registrySource==="provided"&&metadata.index.plugins.length===index.plugins.length,
    "actual_sdk_uses_provided_source_registry");
  currentMetadata.o(metadata,{config:cfg,env:process.env});
  need(currentMetadata.r({config:cfg,env:process.env})===metadata,"actual_sdk_current_config_metadata_match");
  const providerOwners=metadata.owners?.providers?.get("openai");
  need(Array.isArray(providerOwners)&&providerOwners.length>0,"actual_openai_provider_metadata_present");
  report.registryMetadata={mode:"actual_sdk_provided_index_from_current_readonly_wal",
    indexPluginCount:index.plugins.length,manifestPluginCount:metadata.plugins.length,
    openaiProviderOwnerCount:providerOwners.length,
    diagnosticsCount:metadata.diagnostics.length,registryDiagnosticsCount:metadata.registryDiagnostics.length,
    actualSdkCurrentConfigSnapshotAccepted:true};
  report.phase="actual_configured_model_routes";
  const cfgBefore=structuredClone(cfg),privateRoutes=[];
  const primaryValue=value=>typeof value==="string"?value.trim():value&&typeof value==="object"&&
    typeof value.primary==="string"?value.primary.trim():undefined;
  const providerBucket=value=>bucket(value,["openai","openai-codex","google","anthropic","ollama","openrouter","github-copilot","azure-openai"]);
  const defaultPrimary=primaryValue(cfg.agents?.defaults?.model);
  const defaultModule="dist/defaults-mDjiWzE5.js";
  sourcePins[defaultModule]=sha(read(path.join(SDK,defaultModule),65536));
  const actualDefaults=await import(pathToFileURL(path.join(SDK,defaultModule)).href);
  need(typeof actualDefaults.r==="string"&&actualDefaults.r.length>0,"actual_sdk_default_provider_export");
  const defaultProvider=defaultPrimary?.includes("/")?providerIds.i(defaultPrimary.split("/",1)[0]):actualDefaults.r;
  const aliasIndex=modelRefs.i({cfg,defaultProvider,manifestPlugins:metadata.plugins,allowPluginNormalization:false});
  const parseRef=raw=>{
    need(typeof raw==="string"&&raw.length>0&&raw.length<=4096,"bounded_configured_model_reference");
    const parsed=modelRefs.b({cfg,raw,defaultProvider,aliasIndex,manifestPlugins:metadata.plugins,allowPluginNormalization:false});
    need(parsed?.ref&&typeof parsed.ref.provider==="string","actual_sdk_model_reference_resolved");
    return {raw,provider:parsed.ref.provider,authProvider:aliasApi.r(parsed.ref.provider,{config:cfg}),alias:!!parsed.alias};
  };
  const fallbackValues=value=>{
    const out=value&&typeof value==="object"&&Array.isArray(value.fallbacks)?value.fallbacks:[];
    need(out.length<=128&&out.every(x=>typeof x==="string"&&x.trim().length>0),"bounded_configured_fallbacks");
    return out;
  };
  const counts=values=>{const out={};for(const value of values)increment(out,providerBucket(value.authProvider));return out;};
  const defaultFallbacks=fallbackValues(cfg.agents?.defaults?.model);
  const defaultFallbackRefs=defaultFallbacks.map(parseRef);
  report.defaultPrimaryConfigured=!!defaultPrimary;
  report.defaultPrimaryAuthProvider=defaultPrimary?providerBucket(parseRef(defaultPrimary).authProvider):null;
  report.modelReferenceBaseProvider=providerBucket(defaultProvider);
  report.defaultFallbackCount=defaultFallbackRefs.length;
  report.defaultFallbackProviderCounts=counts(defaultFallbackRefs);
  const primaryRefs=[],fallbackRefs=[],subagentRefs=[],utilityRefs=[],heartbeatRefs=[];
  for(const [ordinal,item]of input.agents.entries()){
    remaining();
    const entry=scope.r(cfg,item.agent);
    need(entry&&path.resolve(scope.a(cfg,item.agent))===item.agentDir,"same_five_current_model_scope_agents");
    const primary=higher.o(cfg,item.agent);
    need(primary===primaryValue(item.declaredModel),"actual_sdk_primary_matches_original_current_private_observation");
    const primaryRef=parseRef(primary);primaryRefs.push(primaryRef);
    const override=higher.d(cfg,item.agent);
    need(override===undefined||Array.isArray(override)&&override.length<=128,"sdk_fallback_override_shape");
    const effectiveFallbacks=override??defaultFallbacks;
    need(higher.r({cfg,agentId:item.agent})===(effectiveFallbacks.length>0),"actual_sdk_configured_fallback_presence_matches");
    const refs=effectiveFallbacks.map(parseRef);fallbackRefs.push(...refs);
    const subSelection=higher.x({cfg,agentId:item.agent});
    const subRaw=subSelection?primaryValue(subSelection.raw):undefined;
    const subRef=subRaw?parseRef(subRaw):null;if(subRef)subagentRefs.push(subRef);
    const subFallbacks=higher.S(cfg,item.agent);
    need(subFallbacks===undefined||Array.isArray(subFallbacks)&&subFallbacks.length<=128,"sdk_subagent_fallback_shape");
    const subFallbackRefs=(subFallbacks??[]).map(parseRef);
    const utilityRaw=entry.utilityModel??cfg.agents?.defaults?.utilityModel;
    const utility=typeof utilityRaw==="string"&&utilityRaw.trim()?parseRef(utilityRaw):null;
    if(utility)utilityRefs.push(utility);
    const heartbeatRaw=entry.heartbeat?.model??cfg.agents?.defaults?.heartbeat?.model;
    const heartbeat=typeof heartbeatRaw==="string"&&heartbeatRaw.trim()?parseRef(heartbeatRaw):null;
    if(heartbeat)heartbeatRefs.push(heartbeat);
    const row={agentOrdinal:ordinal+1,primaryModelDerivedFromActualSdk:true,
      primaryProvider:providerBucket(primaryRef.provider),primaryAuthProvider:providerBucket(primaryRef.authProvider),
      explicitAgentPrimary:Boolean(higher.c(cfg,item.agent)),primaryUsedConfiguredAlias:primaryRef.alias,
      fallbackOverrideKind:override===undefined?"inherit_default":override.length?"explicit_nonempty":"explicit_empty",
      configuredEffectiveFallbackCount:refs.length,configuredEffectiveFallbackProviderCounts:counts(refs),
      actualSdkConfiguredFallbackPresence:higher.r({cfg,agentId:item.agent}),
      subagentConfiguredSelectionSource:subSelection?.source??"none",
      subagentConfiguredPrimaryProvider:subRef?providerBucket(subRef.authProvider):null,
      subagentFallbackOverrideDefined:subFallbacks!==undefined,
      subagentFallbackOverrideCount:subFallbackRefs.length,subagentFallbackProviderCounts:counts(subFallbackRefs),
      utilityModelDeclared:!!utility,utilityModelProvider:utility?providerBucket(utility.authProvider):null,
      heartbeatModelDeclared:!!heartbeat,heartbeatModelProvider:heartbeat?providerBucket(heartbeat.authProvider):null};
    report.agents.push(row);
    privateRoutes.push({agent:item.agent,primary:primaryRef,effectiveFallbacks:refs,
      subagentSelection:subSelection??null,subagentFallbacks:subFallbackRefs,utility,heartbeat});
  }
  need(isDeepStrictEqual(cfg,cfgBefore),"actual_sdk_route_observation_keeps_config_object_unchanged");
  need(diagnostics.blockedAttempts===baseDenials&&sqlGuard.ledger.denials===baseSqlDenials,
    "actual_model_routes_no_guarded_side_effects");
  need(sqlGuard.ledger.readOnlyFileOpens===0&&sqlGuard.ledger.connections.every(x=>x.closed&&x.closeAttempts===1),
    "actual_model_routes_no_auth_or_other_file_database_open");
  report.unexpectedJsMutationNetworkChildAttempts=diagnostics.blockedAttempts-baseDenials;
  report.unexpectedSqliteOpenAttempts=sqlGuard.ledger.denials-baseSqlDenials;
  report.currentRegistrationCount=input.registeredProfileIds.length;
  report.registrationResolvedAuthProviderCounts={};
  for(const definition of Object.values(cfg.auth.profiles))
    increment(report.registrationResolvedAuthProviderCounts,providerBucket(aliasApi.r(definition.provider,{config:cfg})));
  report.configuredAgentCount=input.agents.length;
  report.configuredPrimaryProviderCounts=counts(primaryRefs);
  report.configuredNormalFallbackReferenceCount=fallbackRefs.length;
  report.configuredNormalFallbackProviderCounts=counts(fallbackRefs);
  report.configuredSubagentPrimaryCounts=counts(subagentRefs);
  report.configuredUtilityModelCounts=counts(utilityRefs);
  report.configuredHeartbeatModelCounts=counts(heartbeatRefs);
  report.primaryRoutesMatchPreviousOpenaiBranch=primaryRefs.every(x=>x.authProvider==="openai");
  report.aliasResolutionExecuted=true;report.modelRouteFunctionsExecuted=true;
  report.providerAvailabilityQualified=false;
  report.modelProviderResolutionMode="actual_sdk_configured_alias_and_manifest_normalization";
  report.providerModelIdRuntimePluginHooksExecuted=false;
  report.activeGatewayOrSessionRoutesClaimed=false;
  report.allConfiguredProviderRegistrationsQualified=false;
  report.noNewCredentialSourceSelected=true;
  report.actualSdkVersion=pkg.version;
  report.nodeVersion=process.versions.node;report.nodeSqliteVersion=process.versions.sqlite;
  report.sdkSourcePins=sourcePins;
  report.sdkImportDiagnosticBytes=diagnostics.bytes;
  privateMapping={schema:"heptabao.actual-sdk-configured-model-routes.private.r1",host:"mac",
    configurationSha256:input.configurationSha256,configurationIdentity:input.configurationIdentity,
    sdkSourcePins:sourcePins,defaultPrimary,defaultFallbacks,agents:privateRoutes,
    constraints:{containsCredentialValues:false,containsCredentialDigests:false,activeGatewayBindingProven:false,
      sessionStoresRead:false,providerRequests:0,refreshRequests:0}};
  restore();restore=null;sqlGuard.restore();
  need(sha(read(LIVE+"/openclaw.json",1048576,true))===input.configurationSha256,"current_configuration_unchanged_after_sdk");
  for(const [relative,expected]of Object.entries(sourcePins))
    need(sha(read(path.join(SDK,relative),1048576))===expected,"actual_sdk_source_pin_after");
  writePrivate(ROOT+"/output/model-routes.private.json",privateMapping);
  need(sha(read(LIVE+"/openclaw.json",1048576,true))===input.configurationSha256,"configuration_unchanged_through_private_mapping");
  remaining();report.privateModelRoutingProjectionPublished=true;report.ok=true;
}catch(error){
  report.errorType=["Error","TypeError","RangeError","SyntaxError"].includes(error?.name)?error.name:"Other";
  report.errorCode=errorCodes.has(error?.code)?error.code:"actual_sdk_read_failed";
  const safeCodes=new Set(["ERR_MODULE_NOT_FOUND","ERR_PACKAGE_PATH_NOT_EXPORTED","ERR_UNKNOWN_FILE_EXTENSION","ERR_REQUIRE_ESM","ENOENT","EACCES","EPERM","ENOTDIR","sdk_attempted_mutation_or_network","sdk_attempted_writable_open","sdk_diagnostic_bound_exceeded"]);
  report.safeRuntimeErrorCode=safeCodes.has(error?.code)?error.code:null;
  const frames=String(error?.stack??"").split("\n").slice(1).flatMap(line=>{
    const match=line.match(/(?:file:\/\/)?(\/opt\/homebrew\/lib\/node_modules\/openclaw\/(?:dist|node_modules)\/[A-Za-z0-9_./@-]+\.(?:js|mjs|cjs):\d+:\d+)/);
    return match?[match[1]]:[];
  }).slice(0,10);
  report.publicSdkErrorFrames=frames;
}finally{
  if(restore)restore();
  if(sqlGuard){
    sqlGuard.restore();
    const ledger=sqlGuard.ledger;
    report.sqliteReadScope={memoryOpenCount:ledger.memoryOpens,readOnlyFileOpenCount:ledger.readOnlyFileOpens,
      totalGuardDeniedOpenCount:ledger.denials,returnedHandleCount:ledger.connections.length,
      allReturnedHandlesClosedOnce:ledger.connections.every(x=>x.closed&&x.closeAttempts===1)};
  }
  report.jsGuardBlockedAttemptCount=diagnostics.blockedAttempts;
  report.capturedSdkDiagnosticBytes=diagnostics.bytes;
  diagnostics.stdout.length=0;diagnostics.stderr.length=0;
  report.elapsedSeconds=Number(process.hrtime.bigint()-started)/1e9;
  process.stdout.write(JSON.stringify(report)+"\n");
}
process.exitCode=report.ok?0:1;
