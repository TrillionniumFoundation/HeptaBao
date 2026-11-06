#!/usr/bin/env node
/** Actual current SDK ownership only. No provider, OAuth refresh, alias/order or credential export. */
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import net from "node:net";
import childProcess from "node:child_process";
import {createRequire} from "node:module";
import {pathToFileURL} from "node:url";
import {isDeepStrictEqual} from "node:util";
import {protectReadPhase} from "./authbus_sdk_read_guard.mjs";
const ROOT="/Users/qianqi/heptabao-authbus-current-sdk-owner-20261106-r3";
const LIVE="/Users/qianqi/.openclaw";
const SDK="/opt/homebrew/lib/node_modules/openclaw";
const AGENTS=["main","trnm","hepta-ui","hepta","hepta-backend"];
const started=process.hrtime.bigint();
const budgetMs=Number(process.argv[2]);
const until=started+BigInt(Math.trunc(budgetMs*1e6));
const report={schema:"heptabao.current-sdk-owner-readonly.r1",ok:false,
  productionConfigurationChanged:false,productionDatabaseChanged:false,
  credentialValuesOrDigestsIncluded:false,rawClientConfigHashIncluded:false,profileIdsPublished:false,
  j3160Contacted:false,providerCalled:false,refreshDispatched:false,
  aliasResolutionExecuted:false,selectionOrderExecuted:false,
  activeGatewayCredentialBindingProven:false,migrationAllowlistAuthorized:false,
  credentialExported:false,privateOwnerMappingPublished:false,kernelDenials:[],agents:[]};
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
  report.phase="resolve_default_owner";
  const defaultDir=path.resolve(scope.s({}));
  need(defaultDir===path.join(LIVE,"agents/main/agent")&&path.resolve(scope.s(cfg))===defaultDir,"actual_sdk_default_owner_is_main");
  const registered=new Set(input.registeredProfileIds),rows=[],uniqueOwners=new Set(),uniqueProfiles=new Set();
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
    row.allEffectiveOwnersMatch=row.persistedOwnerMatchesEffectiveCount===row.effectiveProfileCount;
    report.agents.push(row);
  }
  sdk.t();
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
  report.actualSdkVersion=pkg.version;
  report.nodeVersion=process.versions.node;report.nodeSqliteVersion=process.versions.sqlite;
  report.sdkSourcePins=sourcePins;
  report.sdkImportDiagnosticBytes=diagnostics.bytes;
  privateMapping={schema:"heptabao.actual-sdk-owned-profile-mapping.private.r1",host:"mac",
    createdWallMs:Date.now(),configurationSha256:input.configurationSha256,
    configurationIdentity:input.configurationIdentity,sourceGenerations:input.sourceGenerations,
    sdkSourcePins:sourcePins,profiles:rows,
    constraints:{containsCredentialValues:false,containsCredentialDigests:false,
      selectionOrderExecuted:false,providerLivenessVerified:false,oauthRefreshAttempted:false,
      migrationAllowlistAuthorized:false,productionCutover:false}};
  restore();restore=null;sqlGuard.restore();
  need(sha(read(LIVE+"/openclaw.json",1048576,true))===input.configurationSha256,"current_configuration_unchanged_after_sdk");
  for(const [relative,expected]of Object.entries(sourcePins))
    need(sha(read(path.join(SDK,relative),1048576))===expected,"actual_sdk_source_pin_after");
  writePrivate(ROOT+"/output/owner-mapping.private.json",privateMapping);
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
  report.jsGuardBlockedAttemptCount=diagnostics.blockedAttempts;
  report.capturedSdkDiagnosticBytes=diagnostics.bytes;
  diagnostics.stdout.length=0;diagnostics.stderr.length=0;
  report.elapsedSeconds=Number(process.hrtime.bigint()-started)/1e9;
  process.stdout.write(JSON.stringify(report)+"\n");
}
process.exitCode=report.ok?0:1;
