#!/usr/bin/env node
/** Actual SDK-selected three-owner credential capsule; private local values only, no provider or refresh. */
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import net from "node:net";
import childProcess from "node:child_process";
import {createRequire} from "node:module";
import {pathToFileURL} from "node:url";
import {isDeepStrictEqual} from "node:util";
import {protectReadPhase} from "./authbus_sdk_read_guard.mjs";
import {bindFreshCloneReader} from "./mac_sdk_private_clone_reader_r1.mjs";
const ROOT="/Users/qianqi/heptabao-authbus-writer-maintenance-20261106-r1/captures/owner-03";
const LIVE="/Users/qianqi/.openclaw";
const SDK="/opt/homebrew/lib/node_modules/openclaw";
const AGENTS=["main","trnm","hepta-ui","hepta","hepta-backend"];
const started=process.hrtime.bigint();
const budgetMs=Number(process.argv[2]);
const until=started+BigInt(Math.trunc(budgetMs*1e6));
const report={schema:"heptabao.current-sdk-selected-capsule-readonly.sdk-r4",ok:false,
  productionConfigurationChanged:false,productionDatabaseChanged:false,
  credentialValuesOrDigestsIncluded:false,rawClientConfigHashIncluded:false,profileIdsPublished:false,
  j3160Contacted:false,providerCalled:false,refreshDispatched:false,
  aliasResolutionExecuted:false,selectionOrderExecuted:false,
  activeGatewayCredentialBindingProven:false,migrationAllowlistAuthorized:false,
  credentialExportedOffHost:false,privateSelectedCredentialCapsulePublished:false,privateOwnerMappingPublished:false,kernelDenials:[],agents:[]};
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
function validateSelectedOwnerAllowlist(value){
  need(Array.isArray(value)&&value.length===3&&value.every(x=>x&&typeof x==="object"&&
    x.ownerAgent==="main"&&x.ownerAgentDir===LIVE+"/agents/main/agent"&&x.actualProvider==="openai"&&
    typeof x.profileId==="string"&&x.profileId.length>0&&x.profileId.length<=256),
    "exact_previous_actual_sdk_three_main_owner_allowlist");
  need(new Set(value.map(x=>x.ownerAgentDir+"\0"+x.profileId)).size===3,
    "three_unique_authorized_owner_profiles");
}
function qualifySelectedAllowlist(){
  const valid=["fixture-one","fixture-two","fixture-three"].map(profileId=>({profileId,
    ownerAgent:"main",ownerAgentDir:LIVE+"/agents/main/agent",actualProvider:"openai"}));
  validateSelectedOwnerAllowlist(valid);
  const changed=(index,patch)=>valid.map((x,i)=>i===index?{...x,...patch}:{...x});
  const rejected=[null,{},valid.slice(0,2),[...valid,{...valid[0],profileId:"fixture-four"}],
    [valid[0],valid[0],valid[2]],changed(0,{ownerAgent:"trnm"}),
    changed(0,{ownerAgentDir:LIVE+"/agents/trnm/agent"}),changed(0,{actualProvider:"anthropic"}),
    changed(0,{profileId:""}),changed(0,{profileId:"x".repeat(257)}),[null,valid[1],valid[2]]];
  for(const value of rejected){let denied=false;try{validateSelectedOwnerAllowlist(value);}catch{denied=true;}
    need(denied,"synthetic_allowlist_negative_failed");}
  return 1+rejected.length;
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
    const physicalArgs=memory?args:[cloneReader.route(filename,options),options];
    const db=Reflect.construct(target,physicalArgs,target),record={memory,closeAttempts:0,closed:false};
    ledger.connections.push(record);
    const close=db.close.bind(db);
    Object.defineProperty(db,"close",{value:(...closeArgs)=>{record.closeAttempts++;const value=close(...closeArgs);record.closed=true;return value;}});
    return db;
  }});
  return {ledger,restore(){sqlite.DatabaseSync=Original;}};
}
let restore=null,sqlGuard=null,cloneReader=null,privateMapping=null,privateCapsule=null,input=null;
report.actualSdkLogicalPathsReadThroughFreshPrivateClone=false;
report.productionGatewayConsumptionQualified=false;
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
  report.selectedOwnerAllowlistSyntheticCasesPassed=qualifySelectedAllowlist();
  validateSelectedOwnerAllowlist(input.selectedOwnerAllowlist);
  const ownerKey=x=>x.ownerAgentDir+"\0"+x.profileId;
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
  report.privateCloneReader={};
  cloneReader=bindFreshCloneReader({root:ROOT,binding:input.cloneReadBinding,until},report.privateCloneReader);
  for(const item of input.agents){
    let denied=false;
    try{const fd=fs.openSync(path.join(item.agentDir,"openclaw-agent.sqlite"),fs.constants.O_RDONLY);fs.closeSync(fd);}
    catch(error){denied=["EPERM","EACCES"].includes(error.code);}
    need(denied,"kernel_original_database_read_denied_for_clone_sdk");
  }
  report.originalFiveDatabaseKernelReadRefusalsObserved=true;
  sqlGuard=installSqliteGuard(new Set(input.agents.map(x=>path.join(x.agentDir,"openclaw-agent.sqlite"))));
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
  report.phase="import_store";
  const sdk=await import(pathToFileURL(path.join(SDK,"dist/store-DH33UrUj.js")).href);
  report.phase="import_persisted";
  const persisted=await import(pathToFileURL(path.join(SDK,"dist/source-check-ZSz5NzGW.js")).href);
  report.phase="import_credential_state";
  const state=await import(pathToFileURL(path.join(SDK,"dist/credential-state-BY-oz-QV.js")).href);
  report.phase="import_actual_alias_order";
  const orderApi=await import(pathToFileURL(path.join(SDK,"dist/order-CeBlX0NH.js")).href);
  const aliasApi=await import(pathToFileURL(path.join(SDK,"dist/provider-auth-aliases-Cp2PXhsh.js")).href);
  const providerIds=await import(pathToFileURL(path.join(SDK,"dist/provider-id-Dq06Bcx6.js")).href);
  const usage=await import(pathToFileURL(path.join(SDK,"dist/usage-state-BFMjBJsu.js")).href);
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
  report.registryMetadata={mode:"actual_sdk_provided_index_from_current_source_transaction",
    sourceRoute:input.registryRoute,
    indexPluginCount:index.plugins.length,manifestPluginCount:metadata.plugins.length,
    openaiProviderOwnerCount:providerOwners.length,
    diagnosticsCount:metadata.diagnostics.length,registryDiagnosticsCount:metadata.registryDiagnostics.length,
    actualSdkCurrentConfigSnapshotAccepted:true};
  report.phase="resolve_default_owner";
  const defaultDir=path.resolve(scope.s({}));
  need(defaultDir===path.join(LIVE,"agents/main/agent")&&path.resolve(scope.s(cfg))===defaultDir,"actual_sdk_default_owner_is_main");
  const registered=new Set(input.registeredProfileIds),rows=[],uniqueOwners=new Set(),uniqueProfiles=new Set(),selectedOwners=new Map(),selectedCredentials=new Map();
  const now=Date.now();
  for(const item of input.agents){
    remaining();
    const agentDir=path.resolve(scope.a(cfg,item.agent));
    need(agentDir===item.agentDir&&allowedDirs.has(agentDir),"actual_sdk_directory_matches_current_registration");
    report.phase="load_actual_agent_source";
    sdk.t();
    const local=persisted.c(agentDir);
    const effective=sdk.u(agentDir,{allowKeychainPrompt:false});
    need(local&&typeof local.profiles==="object"&&effective&&typeof effective.profiles==="object","actual_sdk_persisted_store_present");
    const localIds=Object.keys(local.profiles),entries=Object.entries(effective.profiles);
    need(localIds.length<=128&&entries.length<=128,"bounded_sdk_profile_counts");
    const row={agent:item.agent,localProfileCount:localIds.length,effectiveProfileCount:entries.length,
      effectiveWithLocalRecordCount:0,persistedOwnerMatchesEffectiveCount:0,
      inheritedFromMainCount:0,ownedByRequestedAgentCount:0,
      configuredProfileIdIntersectionCount:0,providerCounts:{},typeCounts:{},
      storedShapeEligibilityCounts:{},oauthExpiryStateCounts:{},
      oauthRefreshFieldPresentCount:0,hasSecretReferenceCount:0,providerValidityQualified:false};
    for(const [profileId,credential]of entries){
      need(typeof profileId==="string"&&profileId.length>0&&profileId.length<=256,"bounded_actual_sdk_profile_id");
      const ownerDir=path.resolve(sdk.f({agentDir,profileId})??defaultDir);
      need(allowedDirs.has(ownerDir),"actual_sdk_owner_within_five_registered_agents");
      const own=sdk.a({agentDir:ownerDir,profileId});
      const matches=!!own&&isDeepStrictEqual(own,credential);
      row.persistedOwnerMatchesEffectiveCount+=Number(matches);
      row.effectiveWithLocalRecordCount+=Number(Object.hasOwn(local.profiles,profileId));
      row.inheritedFromMainCount+=Number(ownerDir===defaultDir&&ownerDir!==agentDir);
      row.ownedByRequestedAgentCount+=Number(ownerDir===agentDir);
      row.configuredProfileIdIntersectionCount+=Number(registered.has(profileId));
      increment(row.providerCounts,bucket(credential.provider,["openai","openai-codex","google","anthropic","ollama"]));
      increment(row.typeCounts,bucket(credential.type,["oauth","token","api_key"]));
      const eligible=state.n({credential,now});
      need(["ok","missing_credential","malformed_api_key","invalid_expires","expired","unresolved_ref"].includes(eligible.reasonCode),"closed_actual_sdk_eligibility_reason");
      increment(row.storedShapeEligibilityCounts,eligible.reasonCode);
      if(credential.type==="oauth"){
        increment(row.oauthExpiryStateCounts,state.a(credential.expires,now,{expiringWithinMs:300000}));
        row.oauthRefreshFieldPresentCount+=Number(typeof credential.refresh==="string"&&credential.refresh.length>0);
      }
      row.hasSecretReferenceCount+=Number(["keyRef","tokenRef","accessRef","refreshRef","oauthRef"].some(key=>credential[key]!==undefined));
      rows.push({scopeAgent:item.agent,scopeAgentDir:agentDir,profileId,ownerAgent:allowedDirs.get(ownerDir),
        ownerAgentDir:ownerDir,persistedOwnerMatchesEffective:matches,
        configuredProfileId:registered.has(profileId),selectionOrMigrationAuthorized:false});
      uniqueOwners.add(ownerDir+"\0"+profileId);uniqueProfiles.add(profileId);
    }
    report.phase="actual_configured_provider_order";
    const mergedAgent=scope.r(cfg,item.agent);
    const model=mergedAgent?.model??cfg.agents?.defaults?.model;
    const primary=typeof model==="string"?model:model?.primary;
    need(typeof primary==="string"&&primary.includes("/"),"actual_configured_model_provider");
    const provider=primary.split("/",1)[0],providerKey=providerIds.i(provider);
    const providerAuthKey=aliasApi.r(provider,{config:cfg});
    need(providerKey==="openai"&&providerAuthKey==="openai","actual_current_openai_model_and_auth_provider");
    const compatibleConfigured=Object.entries(cfg.auth.profiles).filter(([,definition])=>
      aliasApi.r(definition.provider,{config:cfg})===providerAuthKey).map(([id])=>id);
    const compatibleStore=Object.entries(effective.profiles).filter(([,credential])=>
      orderApi.n({cfg,provider,credential})).map(([id])=>id);
    const directStored=providerIds.n(effective.order,providerAuthKey)??providerIds.n(effective.order,providerKey);
    const directConfigured=providerIds.n(cfg.auth?.order,providerAuthKey)??providerIds.n(cfg.auth?.order,providerKey);
    const explicit=directStored??directConfigured;
    for(const candidate of [directStored,directConfigured])need(candidate===undefined||
      Array.isArray(candidate)&&candidate.length<=128&&candidate.every(x=>typeof x==="string"),
      "bounded_actual_sdk_order_input");
    const base=explicit??(compatibleConfigured.length?compatibleConfigured:compatibleStore);
    const baseEligible=base.filter(profileId=>orderApi.r({cfg,store:effective,provider,profileId,now}).eligible);
    const allBaseMissing=base.every(profileId=>!effective.profiles[profileId]);
    const fallbackPredicate=baseEligible.length===0&&allBaseMissing&&(directStored!==undefined||compatibleConfigured.length>0);
    const originalObject=structuredClone(effective),orderCopy=structuredClone(effective);
    const ordered=orderApi.i({cfg,store:orderCopy,provider});
    need(Array.isArray(ordered)&&ordered.length<=128&&new Set(ordered).size===ordered.length
      &&ordered.every(profileId=>Object.hasOwn(effective.profiles,profileId)),"actual_sdk_order_is_existing_profile_subset");
    need(isDeepStrictEqual(effective,originalObject),"source_store_object_unchanged_by_order");
    const localRows=rows.filter(value=>value.scopeAgent===item.agent);
    for(const value of localRows){
      const rank=ordered.indexOf(value.profileId);
      value.selectedByActualSdkOrder=rank>=0;value.actualSdkOrderRank=rank>=0?rank:null;
      if(rank>=0){
        need(value.persistedOwnerMatchesEffective,"selected_profile_effective_owner_bound");
        const key=value.ownerAgentDir+"\0"+value.profileId,selectedCredential=effective.profiles[value.profileId];
        need(!selectedCredentials.has(key)||isDeepStrictEqual(selectedCredentials.get(key),selectedCredential),
          "all_selected_consumer_references_have_same_owner_credential");
        selectedCredentials.set(key,structuredClone(selectedCredential));
        selectedOwners.set(value.ownerAgentDir+"\0"+value.profileId,{profileId:value.profileId,
          ownerAgent:value.ownerAgent,ownerAgentDir:value.ownerAgentDir,actualProvider:providerAuthKey});
      }
    }
    row.selection={actualSdkFunctionExecuted:true,modelProvider:"openai",resolvedAuthProvider:"openai",
      compatibleConfiguredProfileCount:compatibleConfigured.length,
      configuredCompatibleIdIntersectionCount:compatibleConfigured.filter(id=>Object.hasOwn(effective.profiles,id)).length,
      compatibleStoreProfileCount:compatibleStore.length,
      storedExplicitOrderPresent:directStored!==undefined,configuredExplicitOrderPresent:directConfigured!==undefined,
      baseCandidateCount:base.length,baseEligibleCount:baseEligible.length,allBaseCandidatesMissing:allBaseMissing,
      repairedFallbackPredicateSatisfied:fallbackPredicate,
      orderedProfileCount:ordered.length,orderedConfiguredIdIntersectionCount:ordered.filter(id=>registered.has(id)).length,
      orderedCooldownCount:ordered.filter(id=>usage.o(orderCopy,id)).length,
      sourceStoreObjectUnchanged:true,providerAvailabilityQualified:false};
    row.allEffectiveOwnersMatch=row.persistedOwnerMatchesEffectiveCount===row.effectiveProfileCount;
    report.agents.push(row);
  }
  const sortOwners=values=>values.map(x=>({...x})).sort((a,b)=>ownerKey(a).localeCompare(ownerKey(b)));
  need(isDeepStrictEqual(sortOwners([...selectedOwners.values()]),sortOwners(input.selectedOwnerAllowlist)),
    "current_actual_sdk_selection_matches_exact_authorized_three_owners");
  const capturedEntries=[];
  for(const selected of input.selectedOwnerAllowlist){
    remaining();sdk.t();
    const credential=sdk.a({agentDir:selected.ownerAgentDir,profileId:selected.profileId});
    need(credential&&isDeepStrictEqual(credential,selectedCredentials.get(ownerKey(selected)))&&
      credential.type==="oauth"&&credential.provider==="openai"&&
      typeof credential.access==="string"&&credential.access.length>0&&
      typeof credential.refresh==="string"&&credential.refresh.length>0&&
      !["keyRef","tokenRef","accessRef","refreshRef","oauthRef"].some(key=>credential[key]!==undefined),
      "exact_owned_current_oauth_credential_for_private_projection");
    capturedEntries.push({...selected,credential:structuredClone(credential)});
  }
  privateCapsule={schema:"heptabao.actual-sdk-selected-owner-credentials.private.r1",host:"mac",
    createdWallMs:Date.now(),configurationSha256:input.configurationSha256,
    configurationIdentity:input.configurationIdentity,sourceGenerations:input.sourceGenerations,
    registryGeneration:input.registryGeneration,registeredMetadataFileBindings:input.registeredMetadataFileBindings,
    sdkSourcePins:sourcePins,sourceSelectionAuthority:input.sourceSelectionAuthority,
    sdkPhysicalReadProvenance:{schema:"heptabao.actual-sdk-fresh-clone-provenance.private.r1",
      logicalAgentPathsUnchanged:true,directProductionDatabaseRead:false,
      physicalSource:"fresh_double_sqlite_backup",binding:input.cloneReadBinding},
    ownerEntries:capturedEntries,consumerBindings:rows,
    freshness:{currentGenerationReadThroughActualSdk:true,previousGenerationPromoted:false,
      scopeFromPriorObservedOwnerSelection:true},
    constraints:{containsCredentialValues:true,containsCredentialDigests:false,selectedOwnerCount:3,
      containsUnselectedCredentials:false,productionChanged:false,providerLivenessVerified:false,
      oauthRefreshAttempted:false,productionCutover:false}};
  report.privateSelectedOwnerCredentialCount=capturedEntries.length;
  report.privateSelectedCredentialExpiryStateCounts={};
  for(const entry of capturedEntries)increment(report.privateSelectedCredentialExpiryStateCounts,
    state.a(entry.credential.expires,Date.now(),{expiringWithinMs:300000}));
  report.exactPreviousSdkSelectedAllowlistRetained=true;
  report.currentGenerationRecapturedAndSdkSelectionRevalidated=true;
  report.previousFrozenGenerationPromotedToLatest=false;
  sdk.t();
  cloneReader.verify();
  need(report.privateCloneReader.cloneDatabaseConstructorsRouted>0
    &&report.agents.length===5,"actual_five_sdk_scope_reads_used_fresh_clones");
  report.actualSdkLogicalPathsReadThroughFreshPrivateClone=true;
  cloneReader.close();
  need(diagnostics.blockedAttempts===baseDenials&&sqlGuard.ledger.denials===baseSqlDenials,"sdk_attempted_no_guarded_writes_network_children_or_other_database");
  need(sqlGuard.ledger.connections.every(x=>x.closed&&x.closeAttempts===1),"actual_sdk_all_sqlite_handles_closed_once");
  report.unexpectedJsMutationNetworkChildAttempts=diagnostics.blockedAttempts-baseDenials;
  report.unexpectedSqliteOpenAttempts=sqlGuard.ledger.denials-baseSqlDenials;
  report.allEffectiveOwnersMatch=report.agents.every(x=>x.allEffectiveOwnersMatch);
  report.effectiveProfileReferenceCount=rows.length;
  report.uniquePersistedOwnerProfileCount=uniqueOwners.size;
  report.uniqueEffectiveProfileIdCount=uniqueProfiles.size;
  report.currentRegistrationCount=registered.size;
  report.actualSdkOwnershipFunctionsExecuted=true;
  report.aliasResolutionExecuted=true;report.selectionOrderExecuted=true;
  report.actualSdkSelectedOwnerCount=selectedOwners.size;
  report.allAgentsHaveOrderedCandidates=report.agents.every(x=>x.selection.orderedProfileCount>0);
  report.allAgentsRepairedMissingBaseOrder=report.agents.every(x=>x.selection.repairedFallbackPredicateSatisfied);
  report.allSelectedOwnersAreMain=[...selectedOwners.values()].every(x=>x.ownerAgent==="main");
  report.actualSdkVersion=pkg.version;
  report.nodeVersion=process.versions.node;report.nodeSqliteVersion=process.versions.sqlite;
  report.sdkSourcePins=sourcePins;
  report.sdkImportDiagnosticBytes=diagnostics.bytes;
  privateMapping={schema:"heptabao.actual-sdk-owned-profile-mapping.private.r1",host:"mac",
    createdWallMs:Date.now(),selectedOwners:[...selectedOwners.values()],configurationSha256:input.configurationSha256,
    configurationIdentity:input.configurationIdentity,sourceGenerations:input.sourceGenerations,
    sdkSourcePins:sourcePins,profiles:rows,
    constraints:{containsCredentialValues:false,containsCredentialDigests:false,
      selectionOrderExecuted:true,providerLivenessVerified:false,oauthRefreshAttempted:false,
      migrationAllowlistAuthorized:false,productionCutover:false}};
  restore();restore=null;sqlGuard.restore();
  need(sha(read(LIVE+"/openclaw.json",1048576,true))===input.configurationSha256,"current_configuration_unchanged_after_sdk");
  for(const [relative,expected]of Object.entries(sourcePins))
    need(sha(read(path.join(SDK,relative),1048576))===expected,"actual_sdk_source_pin_after");
  writePrivate(ROOT+"/output/owner-mapping.private.json",privateMapping);
  writePrivate(ROOT+"/output/selected-owner-credentials.private.json",privateCapsule);
  report.privateSelectedCredentialCapsulePublished=true;
  need(sha(read(LIVE+"/openclaw.json",1048576,true))===input.configurationSha256,"configuration_unchanged_through_private_mapping");
  remaining();report.privateOwnerMappingPublished=true;report.ok=true;
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
  if(cloneReader){try{cloneReader.close();}catch{report.ok=false;report.cloneReaderCloseUnknown=true;}}
  if(report.privateCloneReader?.allOriginalDescriptorsClosedOnce!==true)report.ok=false;
  report.jsGuardBlockedAttemptCount=diagnostics.blockedAttempts;
  report.capturedSdkDiagnosticBytes=diagnostics.bytes;
  diagnostics.stdout.length=0;diagnostics.stderr.length=0;
  report.elapsedSeconds=Number(process.hrtime.bigint()-started)/1e9;
  process.stdout.write(JSON.stringify(report)+"\n");
}
process.exitCode=report.ok?0:1;
