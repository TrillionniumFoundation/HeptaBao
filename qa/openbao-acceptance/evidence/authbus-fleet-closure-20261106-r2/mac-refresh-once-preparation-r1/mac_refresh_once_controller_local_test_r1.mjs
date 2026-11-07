/** Synthetic controller faults using real local fsync/O_EXCL/retained files.
 * Actual Mac SDK mutex/raw-CAS qualifications are separate evidence. This
 * harness substitutes provider, source, writer and mutex capabilities; it does
 * not perform OAuth, open production SQLite, or claim runtime writer admission.
 */
import fs from "node:fs";
import path from "node:path";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import {fileURLToPath} from "node:url";
import {openPrivateOnceLedger,bindMain3RefreshOnce,RefreshOnceRefused} from "./mac_refresh_once_controller_r1.mjs";
process.umask(0o077);
const started=process.hrtime.bigint(),ROOT=fs.mkdtempSync("/home/agent/heptabao-refresh-once-local-"),results=[];
const fail=code=>{throw new RefreshOnceRefused(code);};
const ownerPath=root=>path.join(root,"state/agents/main/agent");
const resultToken={access:"synthetic-new-access",refresh:"synthetic-new-refresh",expires:Date.now()+3600000,accountId:"synthetic-owner"};
function fixture({ioFault,sourceFault,writerFault,heldFault,providerOverride,rawFault,releaseFault}={}){
  const root=fs.mkdtempSync(path.join(ROOT,"case-")),ledgerRoot=path.join(root,"ledger");fs.mkdirSync(ledgerRoot,{mode:0o700});
  const scope={schema:"heptabao.main3-once-private-scope.r1",provider:"openai",stateRoot:path.join(root,"state"),
    ownerDir:ownerPath(root),profileIds:["synthetic-owner-a","synthetic-owner-b","synthetic-owner-c"]};
  const old={type:"oauth",provider:"openai",access:"synthetic-old-access",refresh:"synthetic-old-refresh",expires:1,accountId:"synthetic-owner",email:"synthetic@example.invalid",metadata:{keep:true}};
  const before={store:{version:1,profiles:Object.fromEntries(scope.profileIds.map(x=>[x,structuredClone(old)])),unknown:"preserved"},
    state:{order:{openai:[...scope.profileIds]},usageStats:{"synthetic-owner-b":{lastUsed:77}}},
    storeRow:{store_key:"primary",store_json:"synthetic-original-raw-json",updated_at:77},
    stateRow:{state_key:"primary",state_json:"synthetic-original-state",updated_at:88}};
  const fdNames=new Map(),events=[],counts={send:0,raw:0,close:0};
  const io=new Proxy(fs,{get(target,key){
    if(key==="openSync")return (...args)=>{const fd=fs.openSync(...args);fdNames.set(fd,args[0]);events.push(["open",path.basename(args[0])]);return fd;};
    if(key==="fsyncSync")return fd=>{events.push(["fsync",path.basename(fdNames.get(fd))]);ioFault?.({op:"fsync",filename:fdNames.get(fd),fd,root,ledgerRoot});return fs.fsyncSync(fd);};
    if(key==="closeSync")return fd=>{const filename=fdNames.get(fd);counts.close++;events.push(["close",path.basename(filename)]);const value=fs.closeSync(fd);fdNames.delete(fd);ioFault?.({op:"close",filename,fd,root,ledgerRoot});return value;};
    return Reflect.get(target,key);
  }});
  const ledgerReceipt={};const ledger=openPrivateOnceLedger({root:ledgerRoot,scope,uid:process.getuid(),io,allowSyntheticRoot:true},ledgerReceipt);
  const source={observe:async()=>({credential:structuredClone(old),configuredLeader:false}),verify(observed,stage){sourceFault?.({observed,stage,root,ledgerRoot,scope,counts,events});}};
  const writer={verify(observed,stage){return writerFault?.({observed,stage,root,counts});}};
  const mutex={async withLock(options,callback,receipt){
    assert.equal(options.profileId,scope.profileIds[0]);
    Object.assign(receipt,{released:false,originalHandleClosed:false,parentDescriptorsClosed:false,guardianClosed:false});
    let primary;
    try{await callback({verifyHeld(){heldFault?.({counts,events,ledgerRoot});}});}catch(e){primary=e;}
    if(releaseFault)releaseFault({counts,receipt});
    Object.assign(receipt,{released:true,originalHandleClosed:true,parentDescriptorsClosed:true,guardianClosed:true});
    if(primary)throw primary;
  }};
  const rawFactory=({assertResponse})=>({
    readBefore(until,receipt){Object.assign(receipt,{ok:true,allReturnedConnectionsClosedOnce:true});return structuredClone(before);},
    apply(params,receipt){
      counts.raw++;events.push(["raw-cas"]);
      rawFault?.({params,receipt,ledgerRoot,scope,before,assertResponse,counts});
      assertResponse(params.responseWitness,params.newCredential);
      assert.deepEqual(params.before,before);assert.deepEqual(params.authorizedProfileIds,scope.profileIds);
      assert.deepEqual(params.newCredential.metadata,old.metadata);assert.equal(params.newCredential.email,old.email);
      Object.assign(receipt,{ok:true,commitKnown:true,independentPostCommitReadback:true,allReturnedConnectionsClosedOnce:true});
    }
  });
  async function standardProvider(p){
    p.assertLive();await p.finalDispatch(()=>{counts.send++;events.push(["provider-send"]);return Promise.resolve();});
    p.responseCapture({status:200,headers:[["content-type","application/json"]],bytes:Buffer.from(JSON.stringify({access_token:resultToken.access,refresh_token:resultToken.refresh,expires_in:3600}))});
    events.push(["sdk-parser"]);return {...resultToken};
  }
  const provider={refresh:p=>providerOverride?providerOverride(p,{counts,events,root,ledgerRoot,standardProvider,old,scope}):standardProvider(p)};
  const controller=bindMain3RefreshOnce({scope,ledger,mutex,source,writer,rawFactory,provider});
  const receipt={};
  return {root,ledgerRoot,scope,before,old,ledger,ledgerReceipt,source,writer,mutex,rawFactory,provider,controller,receipt,counts,events,
    run(until=process.hrtime.bigint()+5000000000n){return controller.runOne({ordinal:0,until},receipt);},
    close(){ledger.close();assert.equal(ledgerReceipt.allOwnedDescriptorsClosedOnce,true);assert.equal(fdNames.size,0);}};
}
async function refused(f,code){let e;try{await f.run();}catch(x){e=x;}assert(e instanceof RefreshOnceRefused);if(code)assert.equal(e.code,code);assert.equal(f.receipt.contextClosed,true);return e;}
async function test(id,fn){try{await fn();results.push({id,passed:true});}catch(e){results.push({id,passed:false,errorType:e?.name??"Error",code:/^refresh_once_/.test(e?.code??"")?e.code:null});}}

await test("R01_complete_durable_order",async()=>{
  const f=fixture();await f.run();assert.equal(f.receipt.ok,true);assert.equal(f.counts.send,1);assert.equal(f.counts.raw,1);
  const at=(op,n)=>f.events.findIndex(x=>x[0]===op&&(n===undefined||x[1]===n));
  assert(at("fsync","intent.private.json")<at("provider-send"));assert(at("fsync","dispatch-unknown.private.json")<at("provider-send"));
  assert(at("fsync","provider-response.private.bin")<at("sdk-parser"));assert(at("fsync","provider-response.private.json")<at("sdk-parser"));
  assert(at("fsync","normalized-credential.private.json")<at("raw-cas"));assert.deepEqual(f.before.state.order.openai,f.scope.profileIds);f.close();
});
await test("R02_new_controller_cannot_replay_same_slot",async()=>{
  const f=fixture();await f.run();f.close();const lr={};const ledger=openPrivateOnceLedger({root:f.ledgerRoot,scope:f.scope,uid:process.getuid(),allowSyntheticRoot:true},lr);
  const c=bindMain3RefreshOnce({...f,ledger});const r={};await assert.rejects(c.runOne({ordinal:0,until:process.hrtime.bigint()+5000000000n},r),e=>e.code==="refresh_once_existing_slot_never_replayed");
  assert.equal(r.providerDispatches,0);assert.equal(f.counts.send,1);ledger.close();assert.equal(lr.allOwnedDescriptorsClosedOnce,true);
});
await test("R03_existing_scope_cannot_rebind",async()=>{
  const f=fixture();f.close();const scope=structuredClone(f.scope);scope.profileIds[0]="synthetic-other";
  assert.throws(()=>openPrivateOnceLedger({root:f.ledgerRoot,scope,uid:process.getuid(),allowSyntheticRoot:true}),e=>e.code==="refresh_once_scope_cannot_rebind_existing_ledger");
});
await test("R04_unknown_send_consumed_no_cas",async()=>{
  const f=fixture({providerOverride:async(p,{counts})=>p.finalDispatch(()=>{counts.send++;throw Error("synthetic transport lost ack");})});await refused(f);
  assert.equal(f.counts.send,1);assert.equal(f.counts.raw,0);assert.equal(f.receipt.outcomeUnknown,true);
  assert(fs.existsSync(path.join(f.ledgerRoot,"owner-01/dispatch-unknown.private.json")));f.close();
});
await test("R05_complete_body_saved_before_parse_failure",async()=>{
  const f=fixture({providerOverride:async(p,{standardProvider})=>{await standardProvider(p);throw Error("synthetic parser failure");}});await refused(f);
  assert.equal(f.receipt.completeResponsesCaptured,1);assert.equal(f.counts.raw,0);assert(fs.existsSync(path.join(f.ledgerRoot,"owner-01/provider-response.private.bin")));f.close();
});
await test("R06_response_before_send_refused",async()=>{
  const f=fixture({providerOverride:async p=>p.responseCapture({status:200,headers:[],bytes:Buffer.from("{}")})});await refused(f,"refresh_once_response_after_one_dispatch");assert.equal(f.counts.send,0);f.close();
});
await test("R07_second_native_send_refused",async()=>{
  const f=fixture({providerOverride:async(p,{counts})=>{await p.finalDispatch(()=>{counts.send++;});p.finalDispatch(()=>{counts.send++;});}});await refused(f,"refresh_once_no_second_provider_dispatch");assert.equal(f.counts.send,1);f.close();
});
await test("R08_second_response_capture_refused",async()=>{
  const f=fixture({providerOverride:async(p,{standardProvider})=>{await standardProvider(p);p.responseCapture({status:200,headers:[],bytes:Buffer.from("{}")} );}});await refused(f,"refresh_once_response_after_one_dispatch");assert.equal(f.counts.raw,0);f.close();
});
await test("R09_response_fsync_failure_no_parse_or_cas",async()=>{
  const f=fixture({ioFault:({op,filename})=>{if(op==="fsync"&&filename.endsWith("provider-response.private.bin"))throw Error("synthetic fsync");}});await refused(f);assert.equal(f.counts.send,1);assert.equal(f.counts.raw,0);assert.equal(f.events.some(x=>x[0]==="sdk-parser"),false);f.close();
});
await test("R10_intent_fsync_failure_no_provider",async()=>{
  const f=fixture({ioFault:({op,filename})=>{if(op==="fsync"&&filename.endsWith("intent.private.json"))throw Error("synthetic fsync");}});await refused(f);assert.equal(f.counts.send,0);f.close();
});
await test("R11_normalized_fsync_failure_no_cas",async()=>{
  const f=fixture({ioFault:({op,filename})=>{if(op==="fsync"&&filename.endsWith("normalized-credential.private.json"))throw Error("synthetic fsync");}});await refused(f);assert.equal(f.counts.send,1);assert.equal(f.counts.raw,0);f.close();
});
await test("R12_full_owner_stale_after_provider_no_resend",async()=>{
  const f=fixture({rawFault:()=>fail("refresh_once_synthetic_owner_changed")});await refused(f,"refresh_once_synthetic_owner_changed");assert.equal(f.counts.send,1);assert.equal(f.counts.raw,1);assert.equal(f.receipt.outcomeUnknown,true);f.close();
});
await test("R13_commit_ack_lost_not_retried",async()=>{
  const f=fixture({rawFault:({receipt})=>{receipt.outcomeUnknown=true;receipt.commitDispatches=1;throw Error("synthetic commit ack lost");}});await refused(f);assert.equal(f.counts.raw,1);assert.equal(f.receipt.outcomeUnknown,true);f.close();
});
await test("R14_release_failure_after_known_commit_unfinished",async()=>{
  const f=fixture({releaseFault:()=>fail("refresh_once_synthetic_mutex_release_unknown")});await refused(f);assert.equal(f.receipt.localOwnerCommitKnown,true);assert.equal(f.receipt.ok,false);
  const value=JSON.parse(fs.readFileSync(path.join(f.ledgerRoot,"owner-01/outcome.private.json")));assert.equal(value.state,"COMMITTED_CLOSURE_UNFINISHED");f.close();
});
await test("R15_last_source_fence_before_native_send",async()=>{
  const f=fixture({sourceFault:({stage})=>{if(stage==="final-native-send")fail("refresh_once_synthetic_source_changed");}});await refused(f,"refresh_once_synthetic_source_changed");assert.equal(f.counts.send,0);assert.equal(f.receipt.providerDispatches,0);
  assert(fs.existsSync(path.join(f.ledgerRoot,"owner-01/dispatch-unknown.private.json")));f.close();
});
await test("R16_false_writer_admission_refused",async()=>{
  const f=fixture({writerFault:()=>false});await refused(f,"refresh_once_sync_running_writer_fence_required");assert.equal(f.counts.send,0);f.close();
});
await test("R17_async_final_source_fence_refused",async()=>{
  const f=fixture();f.source.verify=()=>Promise.resolve();await refused(f,"refresh_once_sync_source_fence_required");assert.equal(f.counts.send,0);f.close();
});
await test("R18_original_mutex_changed_no_send",async()=>{
  const f=fixture({heldFault:()=>fail("refresh_once_synthetic_lock_changed")});await refused(f,"refresh_once_synthetic_lock_changed");assert.equal(f.counts.send,0);f.close();
});
await test("R19_deadline_closes_late_callback",async()=>{
  let held;const f=fixture({providerOverride:p=>{held=p;return new Promise(()=>{});}});
  const keep=setTimeout(()=>{},100);let e;try{await f.run(process.hrtime.bigint()+20000000n);}catch(x){e=x;}clearTimeout(keep);
  assert.equal(e?.code,"refresh_once_original_absolute_deadline");assert.throws(()=>held.finalDispatch(()=>{f.counts.send++;}),x=>x.code==="refresh_once_original_absolute_deadline");
  assert.equal(f.counts.send,0);assert.equal(f.counts.raw,0);f.close();
});
await test("R20_response_cap_enforced_before_durable_copy",async()=>{
  const f=fixture({providerOverride:async(p,{counts})=>{p.finalDispatch(()=>{counts.send++;});p.responseCapture({status:200,headers:[],bytes:Buffer.alloc(1048577)});}});await refused(f,"refresh_once_bounded_response_shape");assert.equal(f.counts.raw,0);f.close();
});
await test("R21_provider_identity_change_no_cas",async()=>{
  const f=fixture({providerOverride:async(p,{standardProvider})=>({...await standardProvider(p),accountId:"synthetic-different-owner"})});await refused(f,"refresh_once_provider_identity_unchanged");assert.equal(f.counts.raw,0);f.close();
});
await test("R22_forged_normalized_witness_refused",async()=>{
  const f=fixture({rawFault:({params,assertResponse})=>assertResponse({...params.responseWitness},params.newCredential)});await refused(f,"refresh_once_original_normalized_witness");f.close();
});
await test("R23_response_private_inode_replacement_refused",async()=>{
  const f=fixture({rawFault:({ledgerRoot})=>{const p=path.join(ledgerRoot,"owner-01/provider-response.private.bin");fs.renameSync(p,p+".old");fs.writeFileSync(p,"{}",{mode:0o600});}});await refused(f,"refresh_once_private_file_changed");f.close();
});
await test("R24_scope_symlink_refused",async()=>{
  const f=fixture();f.close();const p=path.join(f.ledgerRoot,"scope.private.json");fs.renameSync(p,p+".old");fs.symlinkSync(p+".old",p);
  assert.throws(()=>openPrivateOnceLedger({root:f.ledgerRoot,scope:f.scope,uid:process.getuid(),allowSyntheticRoot:true}),e=>e.code==="ELOOP");
});
await test("R25_preexisting_slot_symlink_consumed",async()=>{
  const f=fixture();fs.symlinkSync(f.root,path.join(f.ledgerRoot,"owner-01"));await refused(f,"refresh_once_existing_slot_never_replayed");assert.equal(f.counts.send,0);f.close();
});
await test("R26_ledger_directory_replaced_refused",async()=>{
  let done=false;const f=fixture({sourceFault:({stage,ledgerRoot})=>{if(stage==="final-native-send"&&!done){done=true;fs.renameSync(ledgerRoot,ledgerRoot+".old");fs.mkdirSync(ledgerRoot,{mode:0o700});}}});
  await refused(f,"refresh_once_directory_replaced");assert.equal(f.counts.send,0);f.close();
});
await test("R27_original_close_failure_never_replayed",async()=>{
  let attempts=0;const f=fixture({ioFault:({op,filename})=>{if(op==="close"&&filename.endsWith("intent.private.json")){attempts++;throw Error("synthetic lost close ack");}}});
  await refused(f,"refresh_once_descriptor_close_unknown");assert.equal(f.counts.send,0);f.ledger.close();assert.equal(attempts,1);assert.equal(f.ledgerReceipt.allOwnedDescriptorsClosedOnce,false);
});
await test("R28_configured_leader_false_not_running_authority",async()=>{
  const f=fixture({writerFault:({observed})=>{assert.equal(observed.configuredLeader,false);fail("refresh_once_synthetic_running_writer_unbound");}});await refused(f,"refresh_once_synthetic_running_writer_unbound");assert.equal(f.counts.send,0);f.close();
});
await test("R29_provider_return_without_actual_send_refused",async()=>{
  const f=fixture({providerOverride:async()=>({...resultToken})});await refused(f,"refresh_once_complete_success_response_required");assert.equal(f.counts.send,0);assert.equal(f.counts.raw,0);f.close();
});
await test("R30_preexpired_original_deadline",async()=>{
  const f=fixture();let e;try{await f.run(process.hrtime.bigint()-1n);}catch(x){e=x;}assert.equal(e?.code,"refresh_once_original_absolute_deadline");assert.equal(f.counts.send,0);assert.equal(fs.existsSync(path.join(f.ledgerRoot,"owner-01")),false);f.close();
});
await test("R31_failed_terminal_write_not_retried",async()=>{
  let attempts=0;const f=fixture({ioFault:({op,filename})=>{if(op==="fsync"&&filename.endsWith("outcome.private.json")){attempts++;throw Error("synthetic outcome fsync");}}});
  await refused(f);assert.equal(attempts,1);assert.equal(f.receipt.localOwnerCommitKnown,true);assert.equal(f.receipt.ok,false);f.close();
});
const out={schema:"heptabao.main3-refresh-once-local-qualification.r1",ok:results.every(x=>x.passed),
  executed:results.length,passed:results.filter(x=>x.passed).length,cases:results,
  actualMacSdkExecuted:false,actualProviderCalls:0,productionWrites:0,productionLedgerCreated:false,
  realLocalFilesystemAndFsyncUsed:true,syntheticDependencies:["provider","source authority","running writer authority","SDK mutex","SDK raw CAS"],
  controllerSourceSha256:crypto.createHash("sha256").update(fs.readFileSync(fileURLToPath(new URL("./mac_refresh_once_controller_r1.mjs",import.meta.url)))).digest("hex"),
  elapsedSeconds:Number(process.hrtime.bigint()-started)/1e9};
process.stdout.write(JSON.stringify(out)+"\n");if(!out.ok)process.exitCode=1;
