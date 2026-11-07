#!/usr/bin/env python3
"""One bounded synthetic Mac WAL lifecycle; no live config, credentials, or service."""
import hashlib,json,os,sqlite3,stat,subprocess,sys,time
from pathlib import Path
START=time.monotonic();UNTIL=START+45.0
ROOT=Path('/Users/qianqi/heptabao-authbus-wal-keeper-lifecycle-20261106-r1')
QUAL=Path('/Users/qianqi/heptabao-authbus-auth-wal-qualification-20261106-r2')
SDK=Path('/opt/homebrew/lib/node_modules/openclaw')
PYTHON='/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14'
NODE='/opt/homebrew/Cellar/node/25.9.0_1/bin/node'
PAYLOAD={'sources': {'mac_sdk_raw_owner_cas_r1.mjs': '/**\n * Explicit-handle adapter for the installed SDK\'s raw auth store functions.\n *\n * The caller owns the once ledger, durable provider response, cooperative mutex,\n * exact current owner/namespace admission, and original absolute deadline.\n * This adapter never calls the upper agent/registry lifecycle, refreshes OAuth,\n * retries a write or COMMIT, or claims to invalidate another process\'s cache.\n */\nimport fs from "node:fs";\nimport path from "node:path";\nimport crypto from "node:crypto";\nimport {createRequire} from "node:module";\nimport {pathToFileURL} from "node:url";\nimport {isDeepStrictEqual} from "node:util";\n\nexport const SDK_ROOT="/opt/homebrew/lib/node_modules/openclaw";\nexport const SDK_PINS=Object.freeze({\n  "dist/sqlite-B1ze-fre.js":"ed940f0ba0877eea0f00b2da30e727714993db60156fefc6fe80ac8564984c50",\n  "dist/openclaw-state-db-DzSsA9Ji.js":"ba920b2e6f63293a27c34615fc31dcb16a20a68a1e1e34fbccdcac56a9608149",\n  "dist/openclaw-agent-db-DKpxi-Ll.js":"5c99ab6de1ccc1419ed1bdbc783b79203afc34e564f794df4d91bf10e0b53360",\n  "dist/runtime-snapshots-D6VA-VN8.js":"a1b70fb7664f40fd0a7e6a62f8d1215bca7d6aa465360a5762424100d0dafa4f"\n});\nexport class CasRefused extends Error {\n  constructor(code){super(code);this.name="CasRefused";this.code=code;}\n}\nfunction need(value,code){if(!value)throw new CasRefused(code);}\nconst plain=value=>value!==null&&typeof value==="object"&&!Array.isArray(value)&&Object.getPrototypeOf(value)===Object.prototype;\nfunction jsonValue(value){\n  let raw;\n  try{raw=JSON.stringify(value);}catch{throw new CasRefused("bounded_json_owner_value");}\n  need(typeof raw==="string"&&Buffer.byteLength(raw)<=1048576&&isDeepStrictEqual(JSON.parse(raw),value),"bounded_json_owner_value");\n  return raw;\n}\nfunction identity(s){return ["dev","ino","uid","gid","mode","nlink","size","mtimeNs","ctimeNs"].map(k=>String(s[k]));}\nfunction sourceRead(filename){\n  const fd=fs.openSync(filename,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);\n  try{\n    const before=fs.fstatSync(fd,{bigint:true});\n    need(before.isFile()&&before.nlink===1n&&before.size>0n&&before.size<=1048576n&&\n      (before.mode&18n)===0n,"sdk_source_custody");\n    const bytes=Buffer.alloc(Number(before.size)+1);let offset=0;\n    while(offset<bytes.length){const n=fs.readSync(fd,bytes,offset,bytes.length-offset,null);if(n===0)break;offset+=n;}\n    need(offset===Number(before.size)&&isDeepStrictEqual(identity(before),identity(fs.fstatSync(fd,{bigint:true})))&&\n      isDeepStrictEqual(identity(before),identity(fs.lstatSync(filename,{bigint:true}))),"sdk_source_stable");\n    return bytes.subarray(0,offset);\n  }finally{fs.closeSync(fd);}\n}\nexport async function loadActualMacRawSdk(){\n  need(process.platform==="darwin"&&process.getuid()===501,"actual_mac_sdk_runtime");\n  const sourceFence=()=>{\n    for(const [relative,expected]of Object.entries(SDK_PINS)){\n      const digest=crypto.createHash("sha256").update(sourceRead(path.join(SDK_ROOT,relative))).digest("hex");\n      need(digest===expected,"sdk_source_pin");\n    }\n  };\n  sourceFence();\n  const raw=await import(pathToFileURL(path.join(SDK_ROOT,"dist/sqlite-B1ze-fre.js")).href);\n  const state=await import(pathToFileURL(path.join(SDK_ROOT,"dist/openclaw-state-db-DzSsA9Ji.js")).href);\n  const snapshots=await import(pathToFileURL(path.join(SDK_ROOT,"dist/runtime-snapshots-D6VA-VN8.js")).href);\n  const sqlite=state.m();\n  need(sqlite===createRequire(import.meta.url)("node:sqlite")&&\n    typeof sqlite.DatabaseSync.prototype.setAuthorizer==="function","actual_node_sqlite_authorizer_required");\n  sourceFence();\n  return Object.freeze({\n    sqlite,sourceFence,snapshots,\n    sdk:Object.freeze({\n      readStore:raw.r,readState:raw.n,writeStore:raw.c,transaction:state.d,\n      clearConnectionCache:state.h,clearSnapshots:snapshots.t\n    })\n  });\n}\n\n/** Closed authorizer; no row, credential, SQL text, or identifier is recorded. */\nexport function makeAuthStoreAuthorizer(constants,context,receipt){\n  const C=constants;\n  for(const name of ["SQLITE_OK","SQLITE_DENY","SQLITE_SELECT","SQLITE_READ","SQLITE_INSERT","SQLITE_UPDATE","SQLITE_TRANSACTION","SQLITE_PRAGMA"])\n    need(Number.isInteger(C[name]),"sqlite_authorizer_constants_required");\n  const readable={\n    auth_profile_store:new Set(["store_key","store_json","updated_at"]),\n    auth_profile_state:new Set(["state_key","state_json","updated_at"]),\n    sqlite_master:new Set(["type","name","tbl_name","sql"]),\n    sqlite_schema:new Set(["type","name","tbl_name","sql"])\n  };\n  return (action,first,second,database,trigger)=>{\n    let allowed=false;\n    const cleanup=action===C.SQLITE_TRANSACTION&&first==="ROLLBACK"&&second===null&&database===null&&trigger===null;\n    if(cleanup)allowed=true;\n    else if(trigger===null&&context.live()&&context.withinDeadline()){\n      if(action===C.SQLITE_SELECT)allowed=first===null&&second===null&&database===null;\n      else if(action===C.SQLITE_READ)allowed=database==="main"&&readable[first]?.has(second)===true;\n      else if(action===C.SQLITE_INSERT)allowed=context.writing()&&database==="main"&&first==="auth_profile_store"&&second===null;\n      else if(action===C.SQLITE_UPDATE)allowed=context.writing()&&database==="main"&&first==="auth_profile_store"&&["store_json","updated_at"].includes(second);\n      else if(action===C.SQLITE_TRANSACTION)allowed=context.transactions()&&["BEGIN","COMMIT"].includes(first)&&second===null&&database===null;\n      else if(action===C.SQLITE_PRAGMA&&context.schema())allowed=\n        (first==="table_info"&&["auth_profile_store","auth_profile_state"].includes(second)&&[null,"main"].includes(database))||\n        (first==="database_list"&&second===null&&database===null);\n    }\n    if(!allowed)receipt.authorizerDeniedCount++;\n    return allowed?C.SQLITE_OK:C.SQLITE_DENY;\n  };\n}\n\n/**\n * The factory is dependency-injected for isolated fault qualification. Production\n * admission must use loadActualMacRawSdk() and bind its sourceFence unchanged.\n * admit(stage, databasePath) checks the caller\'s exact private namespace before\n * opening / before BEGIN and stable owner identity after our own expected write.\n * assertResponse(witness,newCredential) checks a private, fsynced response record.\n */\nexport function bindSdkRawOwnerCas({sdk,sqlite,sourceFence,ownerDir,admit,assertResponse,clock=()=>process.hrtime.bigint()}){\n  need(typeof ownerDir==="string"&&path.isAbsolute(ownerDir)&&path.basename(ownerDir)==="agent"&&\n    path.basename(path.dirname(ownerDir))==="main","fixed_main_owner_directory");\n  for(const f of [sdk.readStore,sdk.readState,sdk.writeStore,sdk.transaction,sdk.clearConnectionCache,sdk.clearSnapshots,sourceFence,admit,assertResponse])\n    need(typeof f==="function","complete_sdk_adapter_binding");\n  need(typeof sqlite.DatabaseSync.prototype.setAuthorizer==="function","actual_node_sqlite_authorizer_required");\n  const databasePath=path.join(ownerDir,"openclaw-agent.sqlite");\n  let active=false;\n  function initialize(receipt){\n    Object.assign(receipt,{\n      schema:"heptabao.sdk-raw-owner-cas.public.r1",ok:false,upperSdkLifecycleUsed:false,\n      providerCalls:0,writeDispatches:0,beginDispatches:0,commitDispatches:0,rollbackDispatches:0,\n      readonlyTransactionBegins:0,readonlyTransactionEnds:0,\n      preventedCommitRetries:0,openedConnections:0,closeAttempts:0,knownClosedConnections:0,\n      connectionCacheClears:0,snapshotClears:0,authorizerDeniedCount:0,\n      inTransactionFullReadback:false,independentPostCommitReadback:false,\n      ownerStateRowUnchanged:false,otherProfilesAndOrderUnchanged:false,\n      commitKnown:false,rollbackKnown:false,outcomeUnknown:false,\n      credentialValuesOrDigestsPublished:false,otherProcessCachesInvalidated:false\n    });\n  }\n  function checkTime(until){need(typeof until==="bigint"&&clock()<until,"original_cas_absolute_deadline");}\n  function manage(until,receipt,{readOnly}){\n    checkTime(until);\n    const db=new sqlite.DatabaseSync(databasePath,{readOnly,timeout:0});\n    receipt.openedConnections++;\n    const state={db,readOnly,closed:false,closeAttempted:false,cacheCleared:false,live:true,writing:false,schema:true,transactions:true,activeTransaction:false,ended:false};\n    const close=db.close.bind(db),exec=db.exec.bind(db),prepare=db.prepare.bind(db);\n    const closeOnce=()=>{\n      need(!state.closeAttempted,"database_close_not_replayed");state.closeAttempted=true;receipt.closeAttempts++;\n      try{const result=close();state.closed=true;state.live=false;receipt.knownClosedConnections++;return result;}\n      catch{state.live=false;receipt.outcomeUnknown=true;throw new CasRefused("database_close_unknown");}\n    };\n    try{\n    Object.defineProperty(db,"close",{value:closeOnce});\n    Object.defineProperty(db,"exec",{value:sql=>{\n      need(!state.closeAttempted&&typeof sql==="string","live_transaction_handle");\n      if(sql==="ROLLBACK"){\n        if(readOnly){\n          need(state.activeTransaction&&!state.ended,"single_readonly_transaction_end");receipt.readonlyTransactionEnds++;\n          const result=exec(sql);state.activeTransaction=false;state.ended=true;return result;\n        }\n        need(state.activeTransaction&&receipt.rollbackDispatches===0,"single_rollback_dispatch");receipt.rollbackDispatches++;\n        const result=exec(sql);state.activeTransaction=false;receipt.rollbackKnown=true;return result;\n      }\n      checkTime(until);\n      if(sql==="BEGIN"){\n        need(readOnly&&!state.activeTransaction&&!state.ended,"single_readonly_snapshot_transaction");receipt.readonlyTransactionBegins++;\n        const result=exec(sql);state.activeTransaction=true;return result;\n      }\n      if(sql==="BEGIN IMMEDIATE"){\n        need(!readOnly&&receipt.beginDispatches===0,"single_immediate_transaction");receipt.beginDispatches++;\n        const result=exec(sql);state.activeTransaction=true;return result;\n      }\n      if(sql==="COMMIT"){\n        if(receipt.commitDispatches!==0){receipt.preventedCommitRetries++;throw new CasRefused("commit_not_replayed");}\n        need(!readOnly&&state.activeTransaction,"commit_requires_original_transaction");receipt.commitDispatches++;\n        const result=exec(sql);state.activeTransaction=false;receipt.commitKnown=true;return result;\n      }\n      throw new CasRefused("only_fixed_sdk_transaction_commands");\n    }});\n    Object.defineProperty(db,"prepare",{value:(...args)=>{checkTime(until);need(state.live&&!state.closeAttempted,"live_query_handle");return prepare(...args);}});\n    db.setAuthorizer(makeAuthStoreAuthorizer(sqlite.constants,{\n      live:()=>state.live,withinDeadline:()=>clock()<until,writing:()=>state.writing,\n      schema:()=>state.schema,transactions:()=>state.transactions\n    },receipt));\n    return state;\n    }catch{\n      try{if(!state.closeAttempted)closeOnce();}\n      finally{sdk.clearConnectionCache(db);state.cacheCleared=true;receipt.connectionCacheClears++;}\n      throw new CasRefused("owned_sqlite_handle_setup_refused");\n    }\n  }\n  function finish(connection,receipt){\n    if(!connection)return;\n    try{\n      try{if(connection.readOnly&&connection.activeTransaction&&!connection.closeAttempted)connection.db.exec("ROLLBACK");}\n      finally{if(!connection.closeAttempted)connection.db.close();}\n    }\n    finally{if(!connection.cacheCleared){sdk.clearConnectionCache(connection.db);connection.cacheCleared=true;receipt.connectionCacheClears++;}}\n  }\n  function schema(connection){\n    const db=connection.db;\n    const databases=db.prepare("PRAGMA database_list").all();\n    need(databases.length===1&&databases[0].name==="main"&&path.resolve(databases[0].file)===databasePath,"one_exact_main_database");\n    const structures=db.prepare("SELECT type, name, tbl_name FROM main.sqlite_schema WHERE tbl_name IN (?, ?)").all("auth_profile_store","auth_profile_state");\n    need(structures.filter(x=>x.type==="table").length===2&&structures.every(x=>["table","index"].includes(x.type)),"auth_tables_without_triggers_or_views");\n    for(const [table,key,json]of [["auth_profile_store","store_key","store_json"],["auth_profile_state","state_key","state_json"]]){\n      const columns=db.prepare("PRAGMA main.table_info("+table+")").all();\n      need(columns.length===3&&columns.map(x=>x.name).join(",")===[key,json,"updated_at"].join(",")&&\n        columns[0].pk===1&&columns[1].notnull===1&&columns[2].notnull===1&&\n        columns.map(x=>x.type.toUpperCase()).join(",")==="TEXT,TEXT,INTEGER","exact_auth_table_shape");\n    }\n    connection.schema=false;\n  }\n  function snapshot(connection){\n    const database={db:connection.db};\n    const store=sdk.readStore(ownerDir,database),state=sdk.readState(ownerDir,database);\n    const storeRows=connection.db.prepare("SELECT store_key, store_json, updated_at FROM auth_profile_store WHERE store_key = ?").all("primary");\n    const stateRows=connection.db.prepare("SELECT state_key, state_json, updated_at FROM auth_profile_state WHERE state_key = ?").all("primary");\n    need(storeRows.length===1&&stateRows.length<=1&&plain(store)&&plain(store.profiles)&&(state===null||plain(state)),"complete_primary_owner_rows");\n    const storeRow={...storeRows[0]},stateRow=stateRows.length?{...stateRows[0]}:null;\n    need(isDeepStrictEqual(JSON.parse(storeRow.store_json),store)&&\n      (stateRow===null?state===null:isDeepStrictEqual(JSON.parse(stateRow.state_json),state)),"sdk_raw_values_match_original_row_bytes");\n    jsonValue(store);if(state!==null)jsonValue(state);\n    return {store,state,storeRow,stateRow};\n  }\n  function readBefore(until,receipt={}){\n    initialize(receipt);need(!active,"single_adapter_operation");active=true;let connection;\n    try{\n      checkTime(until);sourceFence();admit("before-read",databasePath);\n      connection=manage(until,receipt,{readOnly:true});schema(connection);\n      connection.db.exec("BEGIN");const result=snapshot(connection);finish(connection,receipt);connection=null;\n      admit("after-read",databasePath);sourceFence();checkTime(until);receipt.ok=true;return result;\n    }catch(error){receipt.errorCode=error instanceof CasRefused?error.code:"sdk_raw_read_refused";throw new CasRefused(receipt.errorCode);}\n    finally{try{finish(connection,receipt);}finally{\n      active=false;receipt.allReturnedConnectionsClosedOnce=receipt.openedConnections===receipt.closeAttempts&&receipt.closeAttempts===receipt.knownClosedConnections;\n      if(!receipt.allReturnedConnectionsClosedOnce)receipt.ok=false;\n    }}\n  }\n  function apply({before,targetProfileId,newCredential,authorizedProfileIds,responseWitness,until},receipt={}){\n    initialize(receipt);need(!active,"single_adapter_operation");active=true;let connection,readback;\n    try{\n      checkTime(until);sourceFence();\n      need(plain(before)&&plain(before.store)&&plain(before.store.profiles)&&plain(before.storeRow)&&\n        (before.state===null||plain(before.state))&&(before.stateRow===null||plain(before.stateRow)),"private_complete_owner_before_image");\n      jsonValue(before);\n      need(Array.isArray(authorizedProfileIds)&&authorizedProfileIds.length===3&&new Set(authorizedProfileIds).size===3&&\n        authorizedProfileIds.every(x=>typeof x==="string"&&x.length>0&&x.length<=256)&&authorizedProfileIds.includes(targetProfileId),"exact_three_selected_owner_scope");\n      const old=before.store.profiles[targetProfileId];\n      need(plain(old)&&plain(newCredential)&&old.provider==="openai"&&old.type==="oauth"&&\n        newCredential.provider==="openai"&&newCredential.type==="oauth"&&\n        ["access","refresh"].every(k=>typeof newCredential[k]==="string"&&newCredential[k].length>0&&newCredential[k].length<=131072)&&\n        typeof newCredential.expires==="number"&&Number.isFinite(newCredential.expires)&&newCredential.expires>Date.now(),"compatible_refreshed_oauth_shape");\n      for(const key of ["accountId","email","clientId","tenantId","projectId","enterpriseUrl"])\n        need(isDeepStrictEqual(old[key],newCredential[key]),"same_selected_owner_identity");\n      const retained=value=>Object.fromEntries(Object.entries(value).filter(([key])=>!["access","refresh","expires","idToken"].includes(key)));\n      need(isDeepStrictEqual(retained(old),retained(newCredential)),"target_nonrotation_fields_preserved");\n      for(const key of ["keyRef","tokenRef","accessRef","refreshRef","oauthRef"])\n        need(!(key in old)&&!(key in newCredential),"no_external_credential_reference");\n      const expectedStore=structuredClone(before.store);expectedStore.profiles[targetProfileId]=structuredClone(newCredential);jsonValue(expectedStore);\n      assertResponse(responseWitness,newCredential);checkTime(until);admit("before-write-open",databasePath);\n      connection=manage(until,receipt,{readOnly:false});schema(connection);admit("before-begin",databasePath);sourceFence();checkTime(until);\n      sdk.transaction(connection.db,()=>{\n        need(isDeepStrictEqual(snapshot(connection),before),"complete_owner_compare_and_swap_before");\n        assertResponse(responseWitness,newCredential);checkTime(until);\n        receipt.writeDispatches++;need(receipt.writeDispatches===1,"single_raw_writer_dispatch");\n        connection.writing=true;\n        try{sdk.writeStore(expectedStore,ownerDir,{db:connection.db});}finally{connection.writing=false;}\n        const after=snapshot(connection);\n        need(isDeepStrictEqual(after.store,expectedStore)&&isDeepStrictEqual(after.state,before.state)&&\n          isDeepStrictEqual(after.stateRow,before.stateRow)&&after.storeRow.store_key===before.storeRow.store_key&&\n          after.storeRow.store_json===JSON.stringify(expectedStore)&&Number.isSafeInteger(after.storeRow.updated_at),"complete_owner_in_transaction_readback");\n        receipt.inTransactionFullReadback=true;checkTime(until);\n      });\n      need(receipt.commitKnown&&!connection.activeTransaction,"original_commit_completed");\n      finish(connection,receipt);connection=null;\n      sdk.clearSnapshots();receipt.snapshotClears++;\n      admit("after-commit",databasePath);checkTime(until);\n      readback=manage(until,receipt,{readOnly:true});schema(readback);\n      readback.db.exec("BEGIN");\n      const actual=snapshot(readback);\n      need(isDeepStrictEqual(actual.store,expectedStore)&&isDeepStrictEqual(actual.state,before.state)&&\n        isDeepStrictEqual(actual.stateRow,before.stateRow)&&actual.storeRow.store_json===JSON.stringify(expectedStore),"independent_complete_commit_readback");\n      finish(readback,receipt);readback=null;\n      admit("after-readback",databasePath);sourceFence();checkTime(until);\n      receipt.independentPostCommitReadback=true;receipt.ownerStateRowUnchanged=true;\n      receipt.otherProfilesAndOrderUnchanged=true;receipt.ok=true;\n      return actual;\n    }catch(error){\n      if(receipt.commitDispatches>0&&!receipt.commitKnown&&!receipt.rollbackKnown)receipt.outcomeUnknown=true;\n      receipt.errorCode=error instanceof CasRefused?error.code:"sdk_raw_cas_refused";\n      throw new CasRefused(receipt.errorCode);\n    }finally{\n      try{try{finish(readback,receipt);}finally{finish(connection,receipt);}}\n      finally{try{sdk.clearSnapshots();receipt.snapshotClears++;}finally{active=false;}}\n      receipt.allReturnedConnectionsClosedOnce=receipt.openedConnections===receipt.closeAttempts&&receipt.closeAttempts===receipt.knownClosedConnections;\n      if(!receipt.allReturnedConnectionsClosedOnce)receipt.ok=false;\n    }\n  }\n  return Object.freeze({readBefore,apply});\n}\n', 'mac_wal_keeper_sdk_worker_r1.mjs': '#!/usr/bin/env node\n/** Five isolated phases using the unchanged, qualified installed-SDK raw adapter. */\nimport fs from "node:fs";\nimport path from "node:path";\nimport net from "node:net";\nimport childProcess from "node:child_process";\nimport {createRequire,syncBuiltinESMExports} from "node:module";\nimport {isDeepStrictEqual as same} from "node:util";\nimport {bindSdkRawOwnerCas,CasRefused,loadActualMacRawSdk,SDK_PINS} from "./mac_sdk_raw_owner_cas_r1.mjs";\n\nconst ROOT="/Users/qianqi/heptabao-authbus-wal-keeper-lifecycle-20261106-r1";\nconst modes=["read-cold","read-held","write-held","read-committed","read-after-close"];\nconst mode=process.argv[2],budget=Number(process.argv[3]);\nconst started=process.hrtime.bigint();\nconst until=started+BigInt(Number.isFinite(budget)&&budget>0?Math.trunc(budget*1000000):0);\nconst output=process.stdout.write.bind(process.stdout),originalStderr=process.stderr.write;\nconst sqlite=createRequire(import.meta.url)("node:sqlite");\nconst ids=["synthetic-main-one","synthetic-main-two","synthetic-main-three"];\nconst ownerDir=ROOT+"/output/fixtures/"+(mode==="read-cold"?"cold":"held")+"/agents/main/agent";\nconst dbPath=ownerDir+"/openclaw-agent.sqlite";\nconst responsePath=ROOT+"/output/responses/held-response.private.json";\nconst report={schema:"heptabao.actual-sdk-synthetic-wal-phase.r1",ok:false,mode,\n actualInstalledSdk:true,syntheticCredentialsOnly:true,productionReads:0,productionWrites:0,\n providerCalls:0,serviceMutations:0,upperSdkLifecycleUsed:false,keeperOwnedByParent:true,\n keeperUsedAsLatestSource:false,readOutcome:null,admissionStages:[],receipts:[],sqliteErrors:[]};\nlet actual=null,sqlOriginal=null,fsOriginal=null,childOriginals=null,netOriginal=null,fetchOriginal=null;\nlet diagnostics=0,childAttempts=0,networkAttempts=0;\nconst sqlRows=[],fdRows=[];\nconst sqlLedger={attempts:0,opened:0,readOnly:0,writable:0,memory:0,denied:0};\nfunction need(v,c){if(!v)throw new CasRefused(c);}\nfunction time(){need(process.hrtime.bigint()<until,"original_wal_phase_deadline");}\nfunction clone(v){return structuredClone(v);}\nfunction ident(s){return ["dev","ino","uid","gid","mode","nlink","size","mtimeNs","ctimeNs"].map(k=>String(s[k]));}\nfunction synthetic(n){return {type:"oauth",provider:"openai",access:"synthetic-access-"+n,\n refresh:"synthetic-refresh-"+n,expires:1,accountId:"synthetic-account-"+n,\n email:"synthetic-"+n+"@invalid.example",retainedExtension:{purpose:"wal-lifecycle-only",value:7}};}\nfunction expectedStore(){\n const value={version:1,profiles:Object.fromEntries(ids.map((id,i)=>[id,synthetic(String(i+1))])),\n  preservedUnknown:{nested:[1,"unchanged",{flag:true}]},order:{openai:[ids[2],ids[0],ids[1]]},\n  usageStats:{[ids[0]]:{lastUsed:123,errorCount:2}},lastGood:{openai:ids[1]}};\n value.profiles["synthetic-other-provider"]={type:"api_key",provider:"anthropic",key:"synthetic-other-key"};\n return value;\n}\nconst expectedState={version:1,order:{openai:[ids[2],ids[0],ids[1]]},usageStats:{[ids[1]]:{lastUsed:27}},lastGood:{openai:ids[2]}};\nfunction checkSnapshot(value,after){\n const expected=expectedStore();\n if(after){\n  const found=value.store.profiles[ids[0]];\n  need(typeof found.expires==="number"&&found.expires>Date.now(),"synthetic_committed_expiry");\n  expected.profiles[ids[0]]={...expected.profiles[ids[0]],access:"synthetic-access-after",refresh:"synthetic-refresh-after",expires:found.expires};\n }\n need(same(value.store,expected)&&same(value.state,expectedState)&&\n  value.stateRow?.updated_at===1700000000002&&value.storeRow?.store_key==="primary",\n  "actual_sdk_complete_synthetic_owner");\n}\nfunction observeSqliteError(error){\n const code=["ERR_SQLITE_ERROR","SQLITE_READONLY","SQLITE_CANTOPEN"].includes(error?.code)?error.code:"other";\n const number=Number.isSafeInteger(error?.errcode)&&error.errcode>=0&&error.errcode<65536?error.errcode:null;\n if(report.sqliteErrors.length<8)report.sqliteErrors.push({code,number});\n}\nfunction installSqlite(){\n sqlOriginal=sqlite.DatabaseSync;\n sqlite.DatabaseSync=new Proxy(sqlOriginal,{construct(target,args){\n  const [file,options]=args,memory=file===":memory:",readOnly=options?.readOnly===true;\n  if(!memory&&!(file===dbPath&&typeof options==="object"&&options!==null&&\n    (readOnly||mode==="write-held"))){sqlLedger.denied++;throw new CasRefused("synthetic_exact_database_scope");}\n  sqlLedger.attempts++;let db;\n  try{db=Reflect.construct(target,args,target);}catch(error){observeSqliteError(error);throw error;}\n  const row={closeAttempts:0,closed:false};sqlRows.push(row);sqlLedger.opened++;\n  if(memory)sqlLedger.memory++;else if(readOnly)sqlLedger.readOnly++;else sqlLedger.writable++;\n  const close=db.close.bind(db);\n  Object.defineProperty(db,"close",{configurable:true,value:()=>{\n   need(row.closeAttempts===0,"one_original_sqlite_close");row.closeAttempts++;\n   const result=close();row.closed=true;return result;\n  }});\n  for(const key of ["prepare","exec"]){const original=db[key].bind(db);\n   Object.defineProperty(db,key,{configurable:true,value:(...values)=>{\n    try{return original(...values);}catch(error){observeSqliteError(error);throw error;}\n   }});\n  }\n  return db;\n }});\n}\nfunction installFdLedger(){\n fsOriginal={openSync:fs.openSync,closeSync:fs.closeSync};\n fs.openSync=function(...args){const fd=fsOriginal.openSync(...args);fdRows.push({fd,closeAttempts:0,closed:false});return fd;};\n fs.closeSync=function(fd){const row=fdRows.findLast(x=>x.fd===fd&&!x.closed);\n  need(row&&row.closeAttempts===0,"one_original_recorded_fd_close");row.closeAttempts++;\n  const result=fsOriginal.closeSync(fd);row.closed=true;return result;\n };\n}\nasync function kernelGuards(){\n for(const [name,flag]of [["protected-read",fs.constants.O_RDONLY],["protected-write",fs.constants.O_WRONLY]]){\n  let fd,denied=false;\n  try{fd=fs.openSync(ROOT+"/"+name,flag|fs.constants.O_NOFOLLOW);}catch(e){denied=["EPERM","EACCES"].includes(e.code);}\n  finally{if(fd!==undefined)fs.closeSync(fd);}\n  need(denied,"kernel_protected_synthetic_file_refused");\n }\n if(mode!=="write-held"){\n  let fd,denied=false;\n  try{fd=fs.openSync(dbPath,fs.constants.O_WRONLY|fs.constants.O_NOFOLLOW);}catch(e){denied=["EPERM","EACCES"].includes(e.code);}\n  finally{if(fd!==undefined)fs.closeSync(fd);}\n  need(denied,"kernel_database_write_refused_in_read_phase");\n }\n const refused=await new Promise(resolve=>{\n  const socket=new net.Socket();let code=null,connected=false;\n  const timer=setTimeout(()=>socket.destroy(),Math.min(500,Math.max(1,Number((until-process.hrtime.bigint())/1000000n))));\n  socket.once("error",error=>{code=error.code;socket.destroy();});\n  socket.once("connect",()=>{connected=true;socket.destroy();});\n  socket.once("close",()=>{clearTimeout(timer);resolve(!connected&&["EPERM","EACCES"].includes(code));});\n  socket.connect(9,"127.0.0.1");\n });\n need(refused,"kernel_network_refusal_and_socket_close");\n report.kernelProtectedFileAndNetworkRefusalsObserved=true;\n childOriginals=Object.fromEntries(["spawn","spawnSync","exec","execSync","execFile","execFileSync","fork"].map(k=>[k,childProcess[k]]));\n for(const k of Object.keys(childOriginals))childProcess[k]=()=>{childAttempts++;throw new CasRefused("no_worker_child");};\n netOriginal=net.Socket.prototype.connect;net.Socket.prototype.connect=function(){networkAttempts++;throw new CasRefused("no_worker_network");};\n fetchOriginal=globalThis.fetch;globalThis.fetch=()=>{networkAttempts++;throw new CasRefused("no_worker_fetch");};\n syncBuiltinESMExports();\n}\nfunction fsyncedResponse(value){\n const fd=fs.openSync(responsePath,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);\n try{fs.writeFileSync(fd,JSON.stringify({synthetic:true,credential:value}));fs.fsyncSync(fd);}finally{fs.closeSync(fd);}\n const directory=fs.openSync(path.dirname(responsePath),fs.constants.O_RDONLY|fs.constants.O_DIRECTORY|fs.constants.O_NOFOLLOW);\n try{fs.fsyncSync(directory);}finally{fs.closeSync(directory);}\n const token=Object.freeze({}),identity=ident(fs.lstatSync(responsePath,{bigint:true}));\n return {token,assert(provided,credential){\n  need(provided===token&&same(credential,value)&&same(identity,ident(fs.lstatSync(responsePath,{bigint:true}))),"exact_fsynced_synthetic_response_witness");\n }};\n}\ntry{\n process.umask(0o077);\n need(process.platform==="darwin"&&process.getuid()===501&&modes.includes(mode)&&Number.isFinite(budget)&&budget>0&&budget<=10000,"fixed_actual_wal_worker_scope");\n need(process.env.OPENCLAW_STATE_DIR===ROOT+"/output/state/initial"&&process.env.OPENCLAW_CONFIG_PATH===ROOT+"/output/config.json"&&\n  process.env.TMPDIR===ROOT+"/output/tmp","synthetic_wal_environment");\n await kernelGuards();installFdLedger();installSqlite();syncBuiltinESMExports();\n process.stderr.write=function(data,...args){diagnostics+=Buffer.byteLength(data);const cb=args.find(x=>typeof x==="function");if(cb)cb();return true;};\n actual=await loadActualMacRawSdk();process.stderr.write=originalStderr;\n const initial=fs.lstatSync(dbPath,{bigint:true}),fixed=ident(initial).slice(0,6);\n need(initial.isFile()&&initial.uid===501n&&initial.nlink===1n&&(initial.mode&511n)===384n,"owned_synthetic_database_identity");\n let witness=null;\n const adapter=bindSdkRawOwnerCas({...actual,ownerDir,\n  admit:(stage,file)=>{time();need(file===dbPath&&same(fixed,ident(fs.lstatSync(file,{bigint:true})).slice(0,6)),"held_synthetic_database_identity");report.admissionStages.push(stage);},\n  assertResponse:(token,value)=>{need(witness!==null,"synthetic_response_precedes_cas");witness.assert(token,value);}});\n const readReceipt={};let before;\n try{before=adapter.readBefore(until,readReceipt);}catch(error){\n  const expected=["read-cold","read-after-close"].includes(mode)&&error instanceof CasRefused&&\n   readReceipt.errorCode==="sdk_raw_read_refused"&&report.sqliteErrors.some(x=>\n    x.code!=="other"&&(x.number!==null?[8,14].includes(x.number&255):["SQLITE_READONLY","SQLITE_CANTOPEN"].includes(x.code)));\n  need(expected,"only_observed_sqlite_readonly_refusal_is_diagnostic");report.readOutcome="known-readonly-refusal";\n }\n report.receipts.push({phase:"read",...readReceipt});\n if(before){\n  checkSnapshot(before,["read-committed","read-after-close"].includes(mode));\n  need(readReceipt.ok&&readReceipt.allReturnedConnectionsClosedOnce&&readReceipt.readonlyTransactionBegins===1&&readReceipt.readonlyTransactionEnds===1,\n   "original_sdk_read_and_close_known");report.readOutcome="complete";\n }\n if(mode==="write-held"){\n  need(before!==undefined,"original_synthetic_before_required");\n  const next={...clone(before.store.profiles[ids[0]]),access:"synthetic-access-after",refresh:"synthetic-refresh-after",expires:Date.now()+3600000};\n  witness=fsyncedResponse(next);report.syntheticResponseFsyncedBeforeCas=true;\n  const r={},after=adapter.apply({before,targetProfileId:ids[0],newCredential:next,authorizedProfileIds:ids,responseWitness:witness.token,until},r);\n  report.receipts.push({phase:"cas",...r});checkSnapshot(after,true);\n  need(r.ok&&r.commitKnown&&r.commitDispatches===1&&r.writeDispatches===1&&r.rollbackDispatches===0&&r.independentPostCommitReadback&&\n   r.allReturnedConnectionsClosedOnce&&r.otherProfilesAndOrderUnchanged&&r.ownerStateRowUnchanged,"one_original_sdk_cas_complete");\n  report.actualRawCasCommitted=true;\n }\n time();actual.sourceFence();need(diagnostics===0,"no_unclassified_sdk_diagnostics");\n report.nodeVersion=process.versions.node;report.sqliteVersion=process.versions.sqlite;report.sdkSourcePins=SDK_PINS;\n report.ok=true;\n}catch(error){report.errorCode=error instanceof CasRefused?error.code:"synthetic_wal_phase_failed";report.errorType=error?.constructor?.name??"Error";}\nfinally{\n process.stderr.write=originalStderr;\n report.sqliteScope={...sqlLedger,allReturnedOriginalHandlesClosedOnce:sqlRows.every(x=>x.closed&&x.closeAttempts===1)};\n report.recordedSourceAndResponseFds={opened:fdRows.length,allReturnedDescriptorsClosedOnce:fdRows.every(x=>x.closed&&x.closeAttempts===1)};\n if(!report.sqliteScope.allReturnedOriginalHandlesClosedOnce||!report.recordedSourceAndResponseFds.allReturnedDescriptorsClosedOnce||sqlLedger.denied)report.ok=false;\n if(sqlOriginal)sqlite.DatabaseSync=sqlOriginal;\n if(fsOriginal){fs.openSync=fsOriginal.openSync;fs.closeSync=fsOriginal.closeSync;}\n if(childOriginals)for(const [k,v]of Object.entries(childOriginals))childProcess[k]=v;\n if(netOriginal)net.Socket.prototype.connect=netOriginal;\n if(fetchOriginal)globalThis.fetch=fetchOriginal;\n syncBuiltinESMExports();\n report.childAttempts=childAttempts;report.networkAttempts=networkAttempts;report.capturedDiagnosticBytes=diagnostics;\n report.installedGuardsRestored=(!sqlOriginal||sqlite.DatabaseSync===sqlOriginal)&&(!fsOriginal||fs.openSync===fsOriginal.openSync&&fs.closeSync===fsOriginal.closeSync)&&\n  (!netOriginal||net.Socket.prototype.connect===netOriginal)&&(!fetchOriginal||globalThis.fetch===fetchOriginal)&&\n  (!childOriginals||Object.entries(childOriginals).every(([k,v])=>childProcess[k]===v));\n if(childAttempts||networkAttempts||!report.installedGuardsRestored)report.ok=false;\n report.elapsedSeconds=Number(process.hrtime.bigint()-started)/1e9;\n}\noutput(JSON.stringify(report)+"\\n");process.exitCode=report.ok?0:1;\n'}, 'sourcePins': {'mac_sdk_raw_owner_cas_r1.mjs': '73af96757ba8e012c94543eb03f188b75bb3de572061abcd9388f06a1fd21833', 'mac_wal_keeper_sdk_worker_r1.mjs': 'a7034e187f341a28667515979451576b30a4e480849a57705384ac57bffb6320'}, 'sdkPins': {'dist/sqlite-B1ze-fre.js': 'ed940f0ba0877eea0f00b2da30e727714993db60156fefc6fe80ac8564984c50', 'dist/openclaw-state-db-DzSsA9Ji.js': 'ba920b2e6f63293a27c34615fc31dcb16a20a68a1e1e34fbccdcac56a9608149', 'dist/openclaw-agent-db-DKpxi-Ll.js': '5c99ab6de1ccc1419ed1bdbc783b79203afc34e564f794df4d91bf10e0b53360', 'dist/runtime-snapshots-D6VA-VN8.js': 'a1b70fb7664f40fd0a7e6a62f8d1215bca7d6aa465360a5762424100d0dafa4f'}, 'custodyQualificationAuthority': {'at_unix_ms': 1793975259508, 'audit_recorded': True, 'automatic_retry': False, 'cancelled': False, 'exit_code': 0, 'job_id': '1a1b141ef40-fc05-7750', 'launch_nonce': '6ee37ff3af8195a8d1bef14099a8e948', 'log_bytes': {'stderr': {'seen': 0, 'stored': 0}, 'stdout': {'seen': 58701, 'stored': 58701}}, 'log_errors': {'stderr': None, 'stdout': None}, 'log_synced': {'stderr': True, 'stdout': True}, 'log_truncated': {'stderr': False, 'stdout': False}, 'output_complete': True, 'output_durable': True, 'state': 'succeeded', 'terminal_publication_confirmed': True, 'terminal_publication_protocol': 1, 'timed_out': False}}
CUSTODY_PINS={
 'kv2_dr_process_custody.py':'669e2cd1d9ee597529c08b88f3fc21c813d4ff7b57f3792381baa44fbdbe7008',
 'owned_process.py':'0ee96c9f43b50ebd57ee8f0ef95f2431c441ec02c1799992588dbf50768745d0'}
RUNTIME_PINS={
 PYTHON:'cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13',
 NODE:'a46ed02589ca3af795237111ff854262064f8ff5c5b58d75c1509f37311eb15e',
 '/usr/bin/sandbox-exec':'abc5bb136d6b5cce8fa85d789f78e3326c51ca60cae637b2064adfb67a1dcd9a'}
PHASES=('read-cold','read-held','write-held','read-committed','read-after-close')
SOURCE_NAMES=('mac_sdk_raw_owner_cas_r1.mjs','mac_wal_keeper_sdk_worker_r1.mjs')
FIELDS=('dev','ino','uid','gid','mode','nlink','size','mtime_ns','ctime_ns')
SUFFIXES=('','-wal','-shm','-journal')
IDS=['synthetic-main-one','synthetic-main-two','synthetic-main-three']
report={'schema':'heptabao.actual-mac-synthetic-wal-keeper-lifecycle.r1','ok':False,
 'sharedSeconds':45,'supervisorSeconds':70,'automaticRetry':False,'providerCalls':0,
 'productionCredentialReads':0,'productionWrites':0,'productionMutexAcquired':False,
 'nativeServiceStarted':False,'syntheticStateOnly':True,'originalChildrenExpected':7,
 'keeperUsedAsLatestSource':False,'productionKeeperOrRefreshControllerQualified':False,
 'children':[],'namespaceObservations':[],'phases':[],
 'candidateCommit':'4bde9aee03fcd27c59e13607e529b1cee594b249'}
owner=None;created=False;children=[];connections=[];namespace_records=[];error_codes=set()
def need(value,code):
 if not value:error_codes.add(code);raise RuntimeError(code)
def remaining(cap=45):
 value=UNTIL-time.monotonic();need(value>0,'original_wal_lifecycle_deadline');return min(cap,value)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def ident(s):return (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def read(path,cap=1048576):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  s=os.fstat(fd);need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_uid in (0,501)
    and not stat.S_IMODE(s.st_mode)&0o022 and 0<=s.st_size<=cap,'bounded_public_wal_source')
  out=bytearray()
  while len(out)<=cap:
   remaining();part=os.read(fd,min(65536,cap+1-len(out)))
   if not part:break
   out.extend(part)
  need(len(out)==s.st_size and ident(s)==ident(os.fstat(fd))==ident(Path(path).lstat()),'stable_public_wal_source')
  return bytes(out)
 finally:os.close(fd)
def private(path,data):
 raw=data if isinstance(data,bytes) else data.encode();need(len(raw)<=262144,'bounded_owned_wal_artifact')
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  view=memoryview(raw)
  while view:
   remaining();n=os.write(fd,view);need(n>0,'owned_wal_write_progress');view=view[n:]
  os.fsync(fd)
 finally:os.close(fd)
 fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
def fence():
 for name,pin in CUSTODY_PINS.items():need(sha(read(QUAL/'qa'/name))==pin,'qualified_custody_source_unchanged')
 for path,pin in RUNTIME_PINS.items():need(sha(read(Path(path),2*1048576))==pin,'qualified_wal_runtime_unchanged')
 for name,pin in PAYLOAD['sdkPins'].items():need(sha(read(SDK/name))==pin,'qualified_raw_sdk_source_unchanged')
def database(which):
 need(which in ('cold','held'),'fixed_synthetic_database_slot')
 return ROOT/'output/fixtures'/which/'agents/main/agent/openclaw-agent.sqlite'
def namespace(which,label,prior=None):
 found={};changes={}
 for suffix in SUFFIXES:
  key='db' if not suffix else suffix[1:]
  try:s=Path(str(database(which))+suffix).lstat()
  except FileNotFoundError:found[key]=None
  else:
   need(stat.S_ISREG(s.st_mode) and s.st_uid==501 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600,
    'owned_synthetic_sqlite_namespace')
   found[key]=ident(s)
  if prior is not None:
   a,b=prior[key],found[key]
   changes[key]=['presence'] if (a is None)!=(b is None) else [] if a is None else [FIELDS[i] for i in range(9) if a[i]!=b[i]]
 need(found['db'] is not None and found['journal'] is None,'fixed_synthetic_wal_database')
 namespace_records.append({'phase':label,'slot':which,'full9':found})
 report['namespaceObservations'].append({'phase':label,'slot':which,
  'present':{k:v is not None for k,v in found.items()},'changedFields':changes})
 return found
def open_sql(which,role,readonly=False,immutable=False):
 remaining();need(not immutable or readonly,'synthetic_immutable_read_only')
 p=database(which);target=p.as_uri()+'?mode=ro'+('&immutable=1' if immutable else '') if readonly else str(p)
 db=sqlite3.connect(target,uri=readonly,timeout=0,isolation_level=None)
 row={'role':role,'readOnly':readonly,'immutableControlOnly':immutable,'closeAttempts':0,'closed':False,
  'cursorOpened':0,'cursorClosed':0,'beginDispatches':0,'rollbackDispatches':0,'transactionActive':False,'unknown':False}
 item={'db':db,'row':row};connections.append(item);return item
def query(item,sql,parameters=(),fetch='none'):
 row=item['row'];need(not row['closeAttempts'],'live_original_parent_sqlite_handle')
 cursor=item['db'].execute(sql,parameters);row['cursorOpened']+=1
 try:
  if fetch=='one':return cursor.fetchone()
  if fetch=='all':return cursor.fetchall()
  need(fetch=='none','fixed_parent_query_mode')
 finally:cursor.close();row['cursorClosed']+=1
def begin_keeper(item):
 row=item['row'];need(row['readOnly'] and not row['immutableControlOnly'] and not row['beginDispatches'],'single_actual_keeper_begin')
 query(item,'PRAGMA query_only=ON');need(query(item,'PRAGMA query_only',fetch='one')==(1,),'keeper_query_only_enabled')
 row['beginDispatches']+=1;query(item,'BEGIN');row['transactionActive']=True
 value=query(item,'SELECT store_json FROM auth_profile_store WHERE store_key = ?',('primary',),'one')
 need(value is not None and json.loads(value[0])==store(),'keeper_established_actual_read_snapshot')
 report['keeperReadTransactionEstablished']=True
 return value[0]
def close_sql(item):
 row=item['row']
 if row['closeAttempts']:return
 try:
  if row['transactionActive']:
   need(row['rollbackDispatches']==0,'keeper_rollback_not_replayed');row['rollbackDispatches']+=1
   try:query(item,'ROLLBACK');row['transactionActive']=False
   except BaseException:row['unknown']=True;raise
 finally:
  row['closeAttempts']+=1
  try:item['db'].close();row['closed']=True
  except BaseException:row['unknown']=True;raise
def credential(n):
 return {'type':'oauth','provider':'openai','access':'synthetic-access-'+n,'refresh':'synthetic-refresh-'+n,
  'expires':1,'accountId':'synthetic-account-'+n,'email':'synthetic-'+n+'@invalid.example',
  'retainedExtension':{'purpose':'wal-lifecycle-only','value':7}}
def store():
 value={'version':1,'profiles':{key:credential(str(i+1)) for i,key in enumerate(IDS)},
  'preservedUnknown':{'nested':[1,'unchanged',{'flag':True}]},'order':{'openai':[IDS[2],IDS[0],IDS[1]]},
  'usageStats':{IDS[0]:{'lastUsed':123,'errorCount':2}},'lastGood':{'openai':IDS[1]}}
 value['profiles']['synthetic-other-provider']={'type':'api_key','provider':'anthropic','key':'synthetic-other-key'}
 return value
STATE={'version':1,'order':{'openai':[IDS[2],IDS[0],IDS[1]]},'usageStats':{IDS[1]:{'lastUsed':27}},'lastGood':{'openai':IDS[2]}}
def setup(which,checkpoint_control=False):
 item=open_sql(which,which+'-original-rw')
 need(query(item,'PRAGMA journal_mode=WAL',fetch='one')==('wal',),'actual_synthetic_wal_mode')
 query(item,'PRAGMA wal_autocheckpoint=0')
 query(item,'CREATE TABLE auth_profile_store(store_key TEXT PRIMARY KEY, store_json TEXT NOT NULL, updated_at INTEGER NOT NULL)')
 query(item,'CREATE TABLE auth_profile_state(state_key TEXT PRIMARY KEY, state_json TEXT NOT NULL, updated_at INTEGER NOT NULL)')
 value=store()
 if checkpoint_control:value['profiles'][IDS[0]]['access']='synthetic-access-checkpointed'
 query(item,'INSERT INTO auth_profile_store VALUES (?,?,?)',('primary',json.dumps(value,separators=(',',':')),1700000000001))
 query(item,'INSERT INTO auth_profile_state VALUES (?,?,?)',('primary',json.dumps(STATE,separators=(',',':')),1700000000002))
 if checkpoint_control:
  need(query(item,'PRAGMA wal_checkpoint(TRUNCATE)',fetch='one')==(0,0,0),'synthetic_checkpoint_control_completed')
  query(item,'UPDATE auth_profile_store SET store_json=? WHERE store_key=?',(json.dumps(store(),separators=(',',':')),'primary'))
 return item
def close_streams(child):
 for stream in (child.stdin,child.stdout,child.stderr):
  if stream is not None and not stream.closed:stream.close()
def record(label,child,out,err):
 close_streams(child);need(len(out)<=65536 and len(err)<=65536,'bounded_wal_worker_output')
 private(ROOT/'output'/(label+'.stdout.public.json'),out);private(ROOT/'output'/(label+'.stderr.private'),err)
 report['children'].append({'label':label,'exitCode':child.returncode,'stdoutBytes':len(out),
  'stderrBytes':len(err),'stdoutSha256':sha(out),'streamsClosed':True})
 need(child.returncode==0 and not err,'actual_wal_child_complete_zero')
def run_phase(mode,environment):
 need(mode in PHASES and mode not in [x['mode'] for x in report['phases']],'one_original_wal_phase')
 policy=ROOT/('write.sb' if mode=='write-held' else 'read.sb')
 child=subprocess.Popen(['/usr/bin/sandbox-exec','-f',str(policy),NODE,'--no-warnings',
   str(ROOT/'code/mac_wal_keeper_sdk_worker_r1.mjs'),mode,str(int(remaining(8)*1000))],
   stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=str(ROOT),env=environment)
 children.append(child);out,err=child.communicate(timeout=remaining(8));record(mode,child,out,err)
 value=json.loads(out);report['phases'].append(value)
 need(value.get('ok') is True and value.get('mode')==mode and value.get('actualInstalledSdk') is True
  and value.get('syntheticCredentialsOnly') is True and value.get('kernelProtectedFileAndNetworkRefusalsObserved') is True
  and value.get('installedGuardsRestored') is True
  and value.get('sqliteScope',{}).get('allReturnedOriginalHandlesClosedOnce') is True
  and value.get('recordedSourceAndResponseFds',{}).get('allReturnedDescriptorsClosedOnce') is True
  and all(value.get(k)==0 for k in ('productionReads','productionWrites','providerCalls','serviceMutations','childAttempts','networkAttempts')),
  'actual_original_sdk_wal_phase_complete')
 if mode in ('read-held','write-held','read-committed'):need(value.get('readOutcome')=='complete','held_keeper_permits_actual_sdk_read')
 else:need(value.get('readOutcome') in ('complete','known-readonly-refusal'),'bounded_cold_or_retired_keeper_observation')
 if mode=='write-held':need(value.get('actualRawCasCommitted') is True and value.get('syntheticResponseFsyncedBeforeCas') is True,'single_original_raw_cas_known')
 return value
try:
 os.umask(0o077)
 need(sys.platform=='darwin' and os.getuid()==501 and os.path.realpath(sys.executable)==PYTHON,'exact_mac_wal_lifecycle_runtime')
 authority=PAYLOAD['custodyQualificationAuthority']
 need(authority['job_id']=='1a1b141ef40-fc05-7750' and authority['state']=='succeeded' and authority['exit_code']==0
   and all(authority[k] is True for k in ('output_complete','output_durable','terminal_publication_confirmed'))
   and all(authority[k] is False for k in ('timed_out','cancelled','automatic_retry')),'original_custody_qualification_authority')
 q=read(QUAL/'result.public.json',65536)
 need(len(q)==58701 and sha(q)=='67cb6bb6804c7285f13f373f6af607405ada39ab734423bf328ffe27915cee4e','same_original_custody_qualification')
 proof=json.loads(q)
 need(proof['ok'] and proof['allCasesMatched'] and proof['allOwnedClosed']
   and proof['custody']['passed_process_custody'] and proof['custody']['original_count']==18,'complete_original_18_custody_cases')
 need(tuple(PAYLOAD['sources'])==SOURCE_NAMES and set(PAYLOAD['sourcePins'])==set(SOURCE_NAMES),'exact_two_prepared_wal_sources')
 fence();home=ROOT.parent.lstat()
 need(stat.S_ISDIR(home.st_mode) and home.st_uid==501 and not stat.S_IMODE(home.st_mode)&0o022,'owned_mac_home_parent')
 ROOT.mkdir(mode=0o700,exist_ok=False);created=True
 for name in ('code','output','output/tmp','output/tmp/openclaw-501','output/state','output/state/initial','output/responses','output/fixtures'):
  (ROOT/name).mkdir(mode=0o700,exist_ok=False)
 for which in ('cold','held'):
  for tail in ('','/agents','/agents/main','/agents/main/agent'):(ROOT/('output/fixtures/'+which+tail)).mkdir(mode=0o700,exist_ok=False)
 private(ROOT/'protected-read',b'synthetic kernel read refusal probe\n');private(ROOT/'protected-write',b'synthetic kernel write refusal probe\n')
 private(ROOT/'output/config.json',b'{"synthetic":"wal-lifecycle-only"}\n')
 for name,raw in PAYLOAD['sources'].items():
  need(sha(raw.encode())==PAYLOAD['sourcePins'][name],'prepared_wal_source_pin');private(ROOT/'code'/name,raw)
 private(ROOT/'plan.public.json',json.dumps({'schema':'heptabao.synthetic-wal-keeper-plan.r1','sharedSeconds':45,
  'supervisorSeconds':70,'originalChildren':7,'originalPythonSqliteConnections':4,'phases':PHASES,
  'sourcePins':PAYLOAD['sourcePins'],'sdkPins':PAYLOAD['sdkPins'],'onlySyntheticPaths':True,
  'productionReadAuthorized':False,'productionMutationAuthorized':False,'providerCallAuthorized':False},sort_keys=True).encode()+b'\n')
 lines=['(version 1)','(deny default)','(allow process*)','(allow signal (target children))',
   '(allow sysctl-read)','(allow mach-lookup)','(allow file-read-metadata)']
 for name in ('/System','/usr','/bin','/sbin','/Library','/private/etc','/opt/homebrew','/dev/fd'):
  lines.append('(allow file-read* (subpath '+json.dumps(name)+'))')
 for name in (ROOT/'code',ROOT/'output'):lines.append('(allow file-read* (subpath '+json.dumps(str(name))+'))')
 for name in [ROOT,*ROOT.parents]:lines.append('(allow file-read* (literal '+json.dumps(str(name))+'))')
 for name in ('/dev/null','/dev/urandom','/dev/random'):lines.append('(allow file-read* (literal '+json.dumps(name)+'))')
 lines.extend(['(allow file-write* (subpath '+json.dumps(str(ROOT/'output/tmp'))+'))','(allow file-write* (literal "/dev/null"))'])
 read_policy='\n'.join(lines)+'\n';private(ROOT/'read.sb',read_policy)
 write_policy=read_policy+'(allow file-write* (subpath '+json.dumps(str(database('held').parent))+'))\n'+\
  '(allow file-write* (subpath '+json.dumps(str(ROOT/'output/responses'))+'))\n';private(ROOT/'write.sb',write_policy)
 environment={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','HOME':'/Users/qianqi','NODE_NO_WARNINGS':'1',
  'TMPDIR':str(ROOT/'output/tmp'),'OPENCLAW_STATE_DIR':str(ROOT/'output/state/initial'),
  'OPENCLAW_CONFIG_PATH':str(ROOT/'output/config.json'),'OPENCLAW_AUTH_STORE_READONLY':'1'}
 sys.path.insert(0,str(QUAL/'qa'));import kv2_dr_process_custody as custody
 original_popen=subprocess.Popen;original_killpg=os.killpg
 with custody.activated() as owner:
  for number,name in enumerate(SOURCE_NAMES):
   child=subprocess.Popen([NODE,'--check',str(ROOT/'code'/name)],stdin=subprocess.DEVNULL,
     stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=str(ROOT),env=environment)
   children.append(child);out,err=child.communicate(timeout=remaining(4));record('syntax-'+str(number),child,out,err)
  cold=setup('cold');close_sql(cold)
  cold_before=namespace('cold','cold-original-rw-closed')
  need(cold_before['wal'] is None and cold_before['shm'] is None,'actual_cold_fixture_has_no_sidecars')
  cold_result=run_phase('read-cold',environment)
  need(namespace('cold','cold-read-complete',cold_before)==cold_before,'cold_read_did_not_mutate_namespace')
  original=setup('held',True)
  first=namespace('held','original-rw-and-committed-wal')
  need(first['wal'] is not None and first['wal'][6]>32 and first['shm'] is not None,'actual_committed_wal_and_shm_exist')
  control=open_sql('held','checkpointed-main-control',True,True)
  try:
   value=query(control,'SELECT store_json FROM auth_profile_store WHERE store_key = ?',('primary',),'one')
   need(value is not None and json.loads(value[0])['profiles'][IDS[0]]['access']=='synthetic-access-checkpointed',
    'main_control_excludes_uncheckpointed_wal_commit')
  finally:close_sql(control)
  keeper=open_sql('held','readonly-keeper',True)
  original_snapshot=begin_keeper(keeper);before_close=namespace('held','keeper-transaction-established',first)
  close_sql(original);held=namespace('held','original-rw-closed-keeper-held',before_close)
  need(held['wal'] is not None and held['shm'] is not None and all(held[k][:6]==before_close[k][:6] for k in ('db','wal','shm')),
   'keeper_retains_exact_existing_sqlite_names')
  run_phase('read-held',environment)
  need(namespace('held','independent-sdk-read-before-cas',held)==held,'held_independent_read_preserved_full9')
  run_phase('write-held',environment);committed=namespace('held','original-sdk-cas-closed',held)
  need(all(committed[k] is not None and committed[k][:6]==held[k][:6] for k in ('db','wal','shm')),
   'original_cas_preserves_keeper_held_names')
  need(query(keeper,'SELECT store_json FROM auth_profile_store WHERE store_key = ?',('primary',),'one')==(original_snapshot,),
   'keeper_remains_old_snapshot_not_latest_source')
  report['keeperSnapshotStayedOldAfterKnownCommit']=True
  run_phase('read-committed',environment)
  need(namespace('held','independent-sdk-read-new-commit',committed)==committed,'new_commit_read_preserved_full9')
  close_sql(keeper);after_close=namespace('held','keeper-finally-closed-new-observation',committed)
  report['freshNamespaceAfterKeeperCloseObserved']=True
  retired=run_phase('read-after-close',environment)
  need(namespace('held','post-keeper-read-complete',after_close)==after_close,'post_keeper_read_preserved_full9')
 report['custody']=owner.receipt()
 need(report['custody']['passed_process_custody'] and report['custody']['original_count']==7
   and subprocess.Popen is original_popen and os.killpg is original_killpg,'seven_original_wal_children_closed')
 need(len(connections)==4 and all(x['row']['closed'] and x['row']['closeAttempts']==1 and not x['row']['transactionActive']
   and not x['row']['unknown'] and x['row']['cursorOpened']==x['row']['cursorClosed'] for x in connections),
   'four_original_parent_sqlite_connections_and_cursors_closed')
 for name,pin in PAYLOAD['sourcePins'].items():need(sha(read(ROOT/'code'/name))==pin,'owned_wal_source_unchanged')
 fence();remaining()
 report.update(ok=True,actualKeeperLifecycleObserved=True,heldKeeperAllowsIndependentActualSdkReadAndCas=True,
  coldReadonlyOutcome=cold_result['readOutcome'],afterKeeperCloseReadonlyOutcome=retired['readOutcome'],
  allOriginalConnectionsAndChildrenClosed=True,sourcePins=PAYLOAD['sourcePins'],sdkSourcePins=PAYLOAD['sdkPins'],
  runtimePins=RUNTIME_PINS,pythonSqliteVersion=sqlite3.sqlite_version,
  sandboxProfileSha256={'read':sha(read_policy.encode()),'write':sha(write_policy.encode())},
  nextProductionCaptureStillRequiresFreshGeneration=True,dynamicLibraryDependencyClosureClaimed=False)
except BaseException as error:
 report['errorCode']=str(error) if str(error) in error_codes else 'wal_lifecycle_qualification_refused'
 report['errorType']=type(error).__name__
finally:
 for item in reversed(connections):
  if not item['row']['closeAttempts']:
   try:close_sql(item)
   except BaseException:report['ok']=False;report['parentSqliteCleanupUnknown']=True
 for child in children:close_streams(child)
 if owner is not None:report['custody']=owner.receipt()
 report['parentSqliteConnections']=[x['row'] for x in connections]
 report['allOriginalParentSqliteConnectionsClosed']=all(x['row']['closed'] and x['row']['closeAttempts']==1
  and not x['row']['transactionActive'] and not x['row']['unknown'] and x['row']['cursorOpened']==x['row']['cursorClosed'] for x in connections)
 if not report['allOriginalParentSqliteConnectionsClosed']:report['ok']=False
 report['elapsedSeconds']=round(time.monotonic()-START,6)
 if created:
  try:
   private(ROOT/'output/namespace-generations.private.json',json.dumps(namespace_records,sort_keys=True).encode()+b'\n')
   private(ROOT/'result.public.json',json.dumps(report,sort_keys=True).encode()+b'\n')
  except BaseException:report['ok']=False;report['resultPublicationFailed']=True
 print(json.dumps(report,sort_keys=True))
raise SystemExit(0 if report['ok'] else 1)
