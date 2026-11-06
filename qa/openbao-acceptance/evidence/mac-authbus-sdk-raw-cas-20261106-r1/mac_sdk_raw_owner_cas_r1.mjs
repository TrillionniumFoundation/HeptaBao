/**
 * Explicit-handle adapter for the installed SDK's raw auth store functions.
 *
 * The caller owns the once ledger, durable provider response, cooperative mutex,
 * exact current owner/namespace admission, and original absolute deadline.
 * This adapter never calls the upper agent/registry lifecycle, refreshes OAuth,
 * retries a write or COMMIT, or claims to invalidate another process's cache.
 */
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import {createRequire} from "node:module";
import {pathToFileURL} from "node:url";
import {isDeepStrictEqual} from "node:util";

export const SDK_ROOT="/opt/homebrew/lib/node_modules/openclaw";
export const SDK_PINS=Object.freeze({
  "dist/sqlite-B1ze-fre.js":"ed940f0ba0877eea0f00b2da30e727714993db60156fefc6fe80ac8564984c50",
  "dist/openclaw-state-db-DzSsA9Ji.js":"ba920b2e6f63293a27c34615fc31dcb16a20a68a1e1e34fbccdcac56a9608149",
  "dist/openclaw-agent-db-DKpxi-Ll.js":"5c99ab6de1ccc1419ed1bdbc783b79203afc34e564f794df4d91bf10e0b53360",
  "dist/runtime-snapshots-D6VA-VN8.js":"a1b70fb7664f40fd0a7e6a62f8d1215bca7d6aa465360a5762424100d0dafa4f"
});
export class CasRefused extends Error {
  constructor(code){super(code);this.name="CasRefused";this.code=code;}
}
function need(value,code){if(!value)throw new CasRefused(code);}
const plain=value=>value!==null&&typeof value==="object"&&!Array.isArray(value)&&Object.getPrototypeOf(value)===Object.prototype;
function jsonValue(value){
  let raw;
  try{raw=JSON.stringify(value);}catch{throw new CasRefused("bounded_json_owner_value");}
  need(typeof raw==="string"&&Buffer.byteLength(raw)<=1048576&&isDeepStrictEqual(JSON.parse(raw),value),"bounded_json_owner_value");
  return raw;
}
function identity(s){return ["dev","ino","uid","gid","mode","nlink","size","mtimeNs","ctimeNs"].map(k=>String(s[k]));}
function sourceRead(filename){
  const fd=fs.openSync(filename,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
  try{
    const before=fs.fstatSync(fd,{bigint:true});
    need(before.isFile()&&before.nlink===1n&&before.size>0n&&before.size<=1048576n&&
      (before.mode&18n)===0n,"sdk_source_custody");
    const bytes=Buffer.alloc(Number(before.size)+1);let offset=0;
    while(offset<bytes.length){const n=fs.readSync(fd,bytes,offset,bytes.length-offset,null);if(n===0)break;offset+=n;}
    need(offset===Number(before.size)&&isDeepStrictEqual(identity(before),identity(fs.fstatSync(fd,{bigint:true})))&&
      isDeepStrictEqual(identity(before),identity(fs.lstatSync(filename,{bigint:true}))),"sdk_source_stable");
    return bytes.subarray(0,offset);
  }finally{fs.closeSync(fd);}
}
export async function loadActualMacRawSdk(){
  need(process.platform==="darwin"&&process.getuid()===501,"actual_mac_sdk_runtime");
  const sourceFence=()=>{
    for(const [relative,expected]of Object.entries(SDK_PINS)){
      const digest=crypto.createHash("sha256").update(sourceRead(path.join(SDK_ROOT,relative))).digest("hex");
      need(digest===expected,"sdk_source_pin");
    }
  };
  sourceFence();
  const raw=await import(pathToFileURL(path.join(SDK_ROOT,"dist/sqlite-B1ze-fre.js")).href);
  const state=await import(pathToFileURL(path.join(SDK_ROOT,"dist/openclaw-state-db-DzSsA9Ji.js")).href);
  const snapshots=await import(pathToFileURL(path.join(SDK_ROOT,"dist/runtime-snapshots-D6VA-VN8.js")).href);
  const sqlite=state.m();
  need(sqlite===createRequire(import.meta.url)("node:sqlite")&&
    typeof sqlite.DatabaseSync.prototype.setAuthorizer==="function","actual_node_sqlite_authorizer_required");
  sourceFence();
  return Object.freeze({
    sqlite,sourceFence,snapshots,
    sdk:Object.freeze({
      readStore:raw.r,readState:raw.n,writeStore:raw.c,transaction:state.d,
      clearConnectionCache:state.h,clearSnapshots:snapshots.t
    })
  });
}

/** Closed authorizer; no row, credential, SQL text, or identifier is recorded. */
export function makeAuthStoreAuthorizer(constants,context,receipt){
  const C=constants;
  for(const name of ["SQLITE_OK","SQLITE_DENY","SQLITE_SELECT","SQLITE_READ","SQLITE_INSERT","SQLITE_UPDATE","SQLITE_TRANSACTION","SQLITE_PRAGMA"])
    need(Number.isInteger(C[name]),"sqlite_authorizer_constants_required");
  const readable={
    auth_profile_store:new Set(["store_key","store_json","updated_at"]),
    auth_profile_state:new Set(["state_key","state_json","updated_at"]),
    sqlite_master:new Set(["type","name","tbl_name","sql"]),
    sqlite_schema:new Set(["type","name","tbl_name","sql"])
  };
  return (action,first,second,database,trigger)=>{
    let allowed=false;
    const cleanup=action===C.SQLITE_TRANSACTION&&first==="ROLLBACK"&&second===null&&database===null&&trigger===null;
    if(cleanup)allowed=true;
    else if(trigger===null&&context.live()&&context.withinDeadline()){
      if(action===C.SQLITE_SELECT)allowed=first===null&&second===null&&database===null;
      else if(action===C.SQLITE_READ)allowed=database==="main"&&readable[first]?.has(second)===true;
      else if(action===C.SQLITE_INSERT)allowed=context.writing()&&database==="main"&&first==="auth_profile_store"&&second===null;
      else if(action===C.SQLITE_UPDATE)allowed=context.writing()&&database==="main"&&first==="auth_profile_store"&&["store_json","updated_at"].includes(second);
      else if(action===C.SQLITE_TRANSACTION)allowed=context.transactions()&&["BEGIN","COMMIT"].includes(first)&&second===null&&database===null;
      else if(action===C.SQLITE_PRAGMA&&context.schema())allowed=
        (first==="table_info"&&["auth_profile_store","auth_profile_state"].includes(second)&&[null,"main"].includes(database))||
        (first==="database_list"&&second===null&&database===null);
    }
    if(!allowed)receipt.authorizerDeniedCount++;
    return allowed?C.SQLITE_OK:C.SQLITE_DENY;
  };
}

/**
 * The factory is dependency-injected for isolated fault qualification. Production
 * admission must use loadActualMacRawSdk() and bind its sourceFence unchanged.
 * admit(stage, databasePath) checks the caller's exact private namespace before
 * opening / before BEGIN and stable owner identity after our own expected write.
 * assertResponse(witness,newCredential) checks a private, fsynced response record.
 */
export function bindSdkRawOwnerCas({sdk,sqlite,sourceFence,ownerDir,admit,assertResponse,clock=()=>process.hrtime.bigint()}){
  need(typeof ownerDir==="string"&&path.isAbsolute(ownerDir)&&path.basename(ownerDir)==="agent"&&
    path.basename(path.dirname(ownerDir))==="main","fixed_main_owner_directory");
  for(const f of [sdk.readStore,sdk.readState,sdk.writeStore,sdk.transaction,sdk.clearConnectionCache,sdk.clearSnapshots,sourceFence,admit,assertResponse])
    need(typeof f==="function","complete_sdk_adapter_binding");
  need(typeof sqlite.DatabaseSync.prototype.setAuthorizer==="function","actual_node_sqlite_authorizer_required");
  const databasePath=path.join(ownerDir,"openclaw-agent.sqlite");
  let active=false;
  function initialize(receipt){
    Object.assign(receipt,{
      schema:"heptabao.sdk-raw-owner-cas.public.r1",ok:false,upperSdkLifecycleUsed:false,
      providerCalls:0,writeDispatches:0,beginDispatches:0,commitDispatches:0,rollbackDispatches:0,
      readonlyTransactionBegins:0,readonlyTransactionEnds:0,
      preventedCommitRetries:0,openedConnections:0,closeAttempts:0,knownClosedConnections:0,
      connectionCacheClears:0,snapshotClears:0,authorizerDeniedCount:0,
      inTransactionFullReadback:false,independentPostCommitReadback:false,
      ownerStateRowUnchanged:false,otherProfilesAndOrderUnchanged:false,
      commitKnown:false,rollbackKnown:false,outcomeUnknown:false,
      credentialValuesOrDigestsPublished:false,otherProcessCachesInvalidated:false
    });
  }
  function checkTime(until){need(typeof until==="bigint"&&clock()<until,"original_cas_absolute_deadline");}
  function manage(until,receipt,{readOnly}){
    checkTime(until);
    const db=new sqlite.DatabaseSync(databasePath,{readOnly,timeout:0});
    receipt.openedConnections++;
    const state={db,readOnly,closed:false,closeAttempted:false,cacheCleared:false,live:true,writing:false,schema:true,transactions:true,activeTransaction:false,ended:false};
    const close=db.close.bind(db),exec=db.exec.bind(db),prepare=db.prepare.bind(db);
    const closeOnce=()=>{
      need(!state.closeAttempted,"database_close_not_replayed");state.closeAttempted=true;receipt.closeAttempts++;
      try{const result=close();state.closed=true;state.live=false;receipt.knownClosedConnections++;return result;}
      catch{state.live=false;receipt.outcomeUnknown=true;throw new CasRefused("database_close_unknown");}
    };
    try{
    Object.defineProperty(db,"close",{value:closeOnce});
    Object.defineProperty(db,"exec",{value:sql=>{
      need(!state.closeAttempted&&typeof sql==="string","live_transaction_handle");
      if(sql==="ROLLBACK"){
        if(readOnly){
          need(state.activeTransaction&&!state.ended,"single_readonly_transaction_end");receipt.readonlyTransactionEnds++;
          const result=exec(sql);state.activeTransaction=false;state.ended=true;return result;
        }
        need(state.activeTransaction&&receipt.rollbackDispatches===0,"single_rollback_dispatch");receipt.rollbackDispatches++;
        const result=exec(sql);state.activeTransaction=false;receipt.rollbackKnown=true;return result;
      }
      checkTime(until);
      if(sql==="BEGIN"){
        need(readOnly&&!state.activeTransaction&&!state.ended,"single_readonly_snapshot_transaction");receipt.readonlyTransactionBegins++;
        const result=exec(sql);state.activeTransaction=true;return result;
      }
      if(sql==="BEGIN IMMEDIATE"){
        need(!readOnly&&receipt.beginDispatches===0,"single_immediate_transaction");receipt.beginDispatches++;
        const result=exec(sql);state.activeTransaction=true;return result;
      }
      if(sql==="COMMIT"){
        if(receipt.commitDispatches!==0){receipt.preventedCommitRetries++;throw new CasRefused("commit_not_replayed");}
        need(!readOnly&&state.activeTransaction,"commit_requires_original_transaction");receipt.commitDispatches++;
        const result=exec(sql);state.activeTransaction=false;receipt.commitKnown=true;return result;
      }
      throw new CasRefused("only_fixed_sdk_transaction_commands");
    }});
    Object.defineProperty(db,"prepare",{value:(...args)=>{checkTime(until);need(state.live&&!state.closeAttempted,"live_query_handle");return prepare(...args);}});
    db.setAuthorizer(makeAuthStoreAuthorizer(sqlite.constants,{
      live:()=>state.live,withinDeadline:()=>clock()<until,writing:()=>state.writing,
      schema:()=>state.schema,transactions:()=>state.transactions
    },receipt));
    return state;
    }catch{
      try{if(!state.closeAttempted)closeOnce();}
      finally{sdk.clearConnectionCache(db);state.cacheCleared=true;receipt.connectionCacheClears++;}
      throw new CasRefused("owned_sqlite_handle_setup_refused");
    }
  }
  function finish(connection,receipt){
    if(!connection)return;
    try{
      try{if(connection.readOnly&&connection.activeTransaction&&!connection.closeAttempted)connection.db.exec("ROLLBACK");}
      finally{if(!connection.closeAttempted)connection.db.close();}
    }
    finally{if(!connection.cacheCleared){sdk.clearConnectionCache(connection.db);connection.cacheCleared=true;receipt.connectionCacheClears++;}}
  }
  function schema(connection){
    const db=connection.db;
    const databases=db.prepare("PRAGMA database_list").all();
    need(databases.length===1&&databases[0].name==="main"&&path.resolve(databases[0].file)===databasePath,"one_exact_main_database");
    const structures=db.prepare("SELECT type, name, tbl_name FROM main.sqlite_schema WHERE tbl_name IN (?, ?)").all("auth_profile_store","auth_profile_state");
    need(structures.filter(x=>x.type==="table").length===2&&structures.every(x=>["table","index"].includes(x.type)),"auth_tables_without_triggers_or_views");
    for(const [table,key,json]of [["auth_profile_store","store_key","store_json"],["auth_profile_state","state_key","state_json"]]){
      const columns=db.prepare("PRAGMA main.table_info("+table+")").all();
      need(columns.length===3&&columns.map(x=>x.name).join(",")===[key,json,"updated_at"].join(",")&&
        columns[0].pk===1&&columns[1].notnull===1&&columns[2].notnull===1&&
        columns.map(x=>x.type.toUpperCase()).join(",")==="TEXT,TEXT,INTEGER","exact_auth_table_shape");
    }
    connection.schema=false;
  }
  function snapshot(connection){
    const database={db:connection.db};
    const store=sdk.readStore(ownerDir,database),state=sdk.readState(ownerDir,database);
    const storeRows=connection.db.prepare("SELECT store_key, store_json, updated_at FROM auth_profile_store WHERE store_key = ?").all("primary");
    const stateRows=connection.db.prepare("SELECT state_key, state_json, updated_at FROM auth_profile_state WHERE state_key = ?").all("primary");
    need(storeRows.length===1&&stateRows.length<=1&&plain(store)&&plain(store.profiles)&&(state===null||plain(state)),"complete_primary_owner_rows");
    const storeRow={...storeRows[0]},stateRow=stateRows.length?{...stateRows[0]}:null;
    need(isDeepStrictEqual(JSON.parse(storeRow.store_json),store)&&
      (stateRow===null?state===null:isDeepStrictEqual(JSON.parse(stateRow.state_json),state)),"sdk_raw_values_match_original_row_bytes");
    jsonValue(store);if(state!==null)jsonValue(state);
    return {store,state,storeRow,stateRow};
  }
  function readBefore(until,receipt={}){
    initialize(receipt);need(!active,"single_adapter_operation");active=true;let connection;
    try{
      checkTime(until);sourceFence();admit("before-read",databasePath);
      connection=manage(until,receipt,{readOnly:true});schema(connection);
      connection.db.exec("BEGIN");const result=snapshot(connection);finish(connection,receipt);connection=null;
      admit("after-read",databasePath);sourceFence();checkTime(until);receipt.ok=true;return result;
    }catch(error){receipt.errorCode=error instanceof CasRefused?error.code:"sdk_raw_read_refused";throw new CasRefused(receipt.errorCode);}
    finally{try{finish(connection,receipt);}finally{
      active=false;receipt.allReturnedConnectionsClosedOnce=receipt.openedConnections===receipt.closeAttempts&&receipt.closeAttempts===receipt.knownClosedConnections;
      if(!receipt.allReturnedConnectionsClosedOnce)receipt.ok=false;
    }}
  }
  function apply({before,targetProfileId,newCredential,authorizedProfileIds,responseWitness,until},receipt={}){
    initialize(receipt);need(!active,"single_adapter_operation");active=true;let connection,readback;
    try{
      checkTime(until);sourceFence();
      need(plain(before)&&plain(before.store)&&plain(before.store.profiles)&&plain(before.storeRow)&&
        (before.state===null||plain(before.state))&&(before.stateRow===null||plain(before.stateRow)),"private_complete_owner_before_image");
      jsonValue(before);
      need(Array.isArray(authorizedProfileIds)&&authorizedProfileIds.length===3&&new Set(authorizedProfileIds).size===3&&
        authorizedProfileIds.every(x=>typeof x==="string"&&x.length>0&&x.length<=256)&&authorizedProfileIds.includes(targetProfileId),"exact_three_selected_owner_scope");
      const old=before.store.profiles[targetProfileId];
      need(plain(old)&&plain(newCredential)&&old.provider==="openai"&&old.type==="oauth"&&
        newCredential.provider==="openai"&&newCredential.type==="oauth"&&
        ["access","refresh"].every(k=>typeof newCredential[k]==="string"&&newCredential[k].length>0&&newCredential[k].length<=131072)&&
        typeof newCredential.expires==="number"&&Number.isFinite(newCredential.expires)&&newCredential.expires>Date.now(),"compatible_refreshed_oauth_shape");
      for(const key of ["accountId","email","clientId","tenantId","projectId","enterpriseUrl"])
        need(isDeepStrictEqual(old[key],newCredential[key]),"same_selected_owner_identity");
      const retained=value=>Object.fromEntries(Object.entries(value).filter(([key])=>!["access","refresh","expires","idToken"].includes(key)));
      need(isDeepStrictEqual(retained(old),retained(newCredential)),"target_nonrotation_fields_preserved");
      for(const key of ["keyRef","tokenRef","accessRef","refreshRef","oauthRef"])
        need(!(key in old)&&!(key in newCredential),"no_external_credential_reference");
      const expectedStore=structuredClone(before.store);expectedStore.profiles[targetProfileId]=structuredClone(newCredential);jsonValue(expectedStore);
      assertResponse(responseWitness,newCredential);checkTime(until);admit("before-write-open",databasePath);
      connection=manage(until,receipt,{readOnly:false});schema(connection);admit("before-begin",databasePath);sourceFence();checkTime(until);
      sdk.transaction(connection.db,()=>{
        need(isDeepStrictEqual(snapshot(connection),before),"complete_owner_compare_and_swap_before");
        assertResponse(responseWitness,newCredential);checkTime(until);
        receipt.writeDispatches++;need(receipt.writeDispatches===1,"single_raw_writer_dispatch");
        connection.writing=true;
        try{sdk.writeStore(expectedStore,ownerDir,{db:connection.db});}finally{connection.writing=false;}
        const after=snapshot(connection);
        need(isDeepStrictEqual(after.store,expectedStore)&&isDeepStrictEqual(after.state,before.state)&&
          isDeepStrictEqual(after.stateRow,before.stateRow)&&after.storeRow.store_key===before.storeRow.store_key&&
          after.storeRow.store_json===JSON.stringify(expectedStore)&&Number.isSafeInteger(after.storeRow.updated_at),"complete_owner_in_transaction_readback");
        receipt.inTransactionFullReadback=true;checkTime(until);
      });
      need(receipt.commitKnown&&!connection.activeTransaction,"original_commit_completed");
      finish(connection,receipt);connection=null;
      sdk.clearSnapshots();receipt.snapshotClears++;
      admit("after-commit",databasePath);checkTime(until);
      readback=manage(until,receipt,{readOnly:true});schema(readback);
      readback.db.exec("BEGIN");
      const actual=snapshot(readback);
      need(isDeepStrictEqual(actual.store,expectedStore)&&isDeepStrictEqual(actual.state,before.state)&&
        isDeepStrictEqual(actual.stateRow,before.stateRow)&&actual.storeRow.store_json===JSON.stringify(expectedStore),"independent_complete_commit_readback");
      finish(readback,receipt);readback=null;
      admit("after-readback",databasePath);sourceFence();checkTime(until);
      receipt.independentPostCommitReadback=true;receipt.ownerStateRowUnchanged=true;
      receipt.otherProfilesAndOrderUnchanged=true;receipt.ok=true;
      return actual;
    }catch(error){
      if(receipt.commitDispatches>0&&!receipt.commitKnown&&!receipt.rollbackKnown)receipt.outcomeUnknown=true;
      receipt.errorCode=error instanceof CasRefused?error.code:"sdk_raw_cas_refused";
      throw new CasRefused(receipt.errorCode);
    }finally{
      try{try{finish(readback,receipt);}finally{finish(connection,receipt);}}
      finally{try{sdk.clearSnapshots();receipt.snapshotClears++;}finally{active=false;}}
      receipt.allReturnedConnectionsClosedOnce=receipt.openedConnections===receipt.closeAttempts&&receipt.closeAttempts===receipt.knownClosedConnections;
      if(!receipt.allReturnedConnectionsClosedOnce)receipt.ok=false;
    }
  }
  return Object.freeze({readBefore,apply});
}
