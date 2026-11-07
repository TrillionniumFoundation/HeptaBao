/* Root-GO-gated pure Git closure of one already completed Native operation.
 * No operation_start/status/result/process tool is available in this code.
 * The real original paused slot stays unchanged until the separate apply call.
 */
const MC_SLOT="successor4a_mac_canonical_bundle_info_gitfirst_r1";
const MC_RECOVERY="successor4a_mac_bundle_original_payload_closure_r1";
const MC_OP="1f9f5693f0f51caf6516ffb07e5fea9973bd1c58bbecb8bece998293da6b1a9f";
const MC_STATE={"blob":"20e0200a0b0ae7d2fe75bce2a890004912ab5869","bytes":35435,"sha256":"66631828cf47fdb31f5da3b29dc8b7f9dfa2bdabd5f730c7bc3f3ccb6ec01b1d"};
const MC_PAYLOAD={"blob":"1d552dc540cd50d9142693e25ab7e57472fc8d30","bytes":2096,"sha256":"6a746ee482b96d481d2e76856e101d3e43c9beb3652cd5906376e6e725fe21d8"};
const MC_PAYLOAD_TREE="1d5ddf9d4b62cb26fa62837dacaf8312ca08bf02";
const MC_JOURNAL={"blob":"45b18f060093f8dc06f2e2ab7ef7fc8f871469a1","bytes":28437,"sha256":"251fe8bf5a476d87b50ddef2a488c1c46c1cca48a42ceef0814ae1e90b570685"};
const MC_PURE={"blob":"b6890e8b7217c546bec073dcb04988fc37652721","bytes":6685,"sha256":"44becefac5fb2ee5018a9044c4b32cf0f44f9ed4b59f9d4c0fb2d62ca5c93432"};
const MC_NEW_KEYS=["successor4a-mac-canonical-bundle-chunk-0-r1","successor4a-mac-canonical-source-bundle-whole-r1"];
const MC_PROOF_KEY="successor4a-mac-bundle-closure-proof-r1";
function mcNeed(v,c){if(!v)throw Error(c);}
function mcRaw(x){return JSON.stringify(x,null,2)+"\n";}
function mcSame(raw,pin){return JSON.stringify(gitBlobMeta(raw))===JSON.stringify(pin);}
function mcStateUnchanged(before){return mcRaw(load(MC_SLOT))===before;}
function mcGO(raw,pin,whole){
 mcNeed(whole===true&&mcSame(raw,pin),"whole exact closure GO");
 const g=JSON.parse(raw);
 mcNeed(g.authorization==="GO"&&g.scope==="successor4a_mac_bundle_pure_git_closure_only"
  &&g.original_operation===MC_OP&&g.paused_state?.blob===MC_STATE.blob
  &&g.original_payload?.blob===MC_PAYLOAD.blob&&g.corrected_mac_journal?.blob===MC_JOURNAL.blob
  &&g.maximum_native_calls===0&&g.maximum_new_git_archives===3
  &&JSON.stringify(g.new_output_archive_keys)===JSON.stringify(MC_NEW_KEYS)
  &&g.proof_archive_key===MC_PROOF_KEY&&g.apply_only_after_whole_proof===true,"closed original-payload-only GO");
 return g;
}
async function prepareMac4aOriginalPayloadClosure({goRaw,goPin,goWholeReadback,pureRaw,journalRaw,payloadRaw,payloadArchive}){
 let before;
 try{
  mcGO(goRaw,goPin,goWholeReadback);
  mcNeed(load(MC_RECOVERY)===undefined,"recovery already started; no retry");
  before=mcRaw(load(MC_SLOT));
  mcNeed(mcSame(before,MC_STATE)&&mcSame(pureRaw,MC_PURE)&&mcSame(journalRaw,MC_JOURNAL)
   &&mcSame(payloadRaw,MC_PAYLOAD),"all exact original inputs");
  mcNeed(payloadArchive?.whole===true&&payloadArchive.tree===MC_PAYLOAD_TREE
   &&payloadArchive.entries?.length===1&&payloadArchive.entries[0].path==="payload.original.json"
   &&payloadArchive.entries[0].whole===true&&payloadArchive.entries[0].blob===MC_PAYLOAD.blob
   &&payloadArchive.entries[0].bytes===MC_PAYLOAD.bytes&&payloadArchive.entries[0].sha256===MC_PAYLOAD.sha256,
   "previous original payload already external whole");
  const original=JSON.parse(before),history=mcRaw(load(MC_SLOT+":outer_failures"));
  mcNeed(original.paused===true&&original.pending===null&&!original.nativeCallInFlight
   &&original.activeObserver?.id===MC_OP&&original.activeObserver.futureClosed===true
   &&original.activeObserver.eof===true&&original.activeObserver.total===2096
   &&original.bundleBodyStarted===1&&original.bundleBodyRanges.length===0
   &&original.completedObservers.length===1&&Object.keys(original.calls).length===6
   &&original.outerFailure?.message==="archive_already_admitted_no_mutation_retry","fixed failed closure boundary");
  for(const key of MC_NEW_KEYS.concat(MC_PROOF_KEY))mcNeed(load("pure_git_once:"+key)===undefined,"new recovery archive key absent");
  const recovery={phase:"admitted_once",goRaw,goPin,before,originalErrorHistory:history,payloadArchive,
    originalPayload:MC_PAYLOAD,correctedJournal:MC_JOURNAL,NativeCalls:0,newArchives:[]};
  store(MC_RECOVERY,recovery);
  const privateState=JSON.parse(before);privateState.paused=false;
  const privateMap=new Map([[MC_SLOT,privateState]]);let step=0;
  const archived=[];
  const limitedArchive=async request=>{
   mcNeed(mcStateUnchanged(before)&&mcRaw(load(MC_SLOT+":outer_failures"))===history,"original paused slot and history unchanged");
   mcNeed(request.repository==="TrillionniumFoundation/HeptaBao","one public repository");
   if(step++===0){
    mcNeed(request.key==="gfc-"+MC_OP&&Object.keys(request.texts).join(",")==="payload.original.json"
      &&request.texts["payload.original.json"]===payloadRaw,"reuse only exact already whole payload; no create");
    return payloadArchive;
   }
   const n=step-2;mcNeed(n<2&&request.key===MC_NEW_KEYS[n],"only two distinct new output archives");
   const expectedPaths=n===0?["chunk.original.base64.txt"]:["BINARY-TRANSPORT.public.json","canonical.bundle.base64.txt"];
   mcNeed(JSON.stringify(Object.keys(request.texts).sort())===JSON.stringify(expectedPaths),"fixed output leaves");
   const result=await archiveFlatPublicTextsOnce(request);
   mcNeed(result.whole===true,"output must be external whole");
   archived.push(result);recovery.newArchives=archived;store(MC_RECOVERY,recovery);return result;
  };
  const noTools=new Proxy({}, {get(){throw Error("Native and direct tools unavailable in pure closure");}});
  const api=new Function("store","load","tools","archiveFlatPublicTextsOnce",pureRaw+"\n"+journalRaw+"\nreturn {gfRun};")
   ((k,v)=>privateMap.set(k,v),k=>privateMap.get(k),noTools,limitedArchive);
  const closed=await api.gfRun("close_observer",{});
  recovery.privateClosure=closed;
  mcNeed(closed.ok===true&&step===3&&archived.length===2,"original journal closure succeeded without Native");
  const after=privateMap.get(MC_SLOT),afterRaw=mcRaw(after);
  mcNeed(!after.paused&&after.activeObserver===null&&after.pending===null&&!after.nativeCallInFlight
   &&after.completedObservers.length===2&&after.bundleBodyStarted===1&&after.bundleBodyRanges.length===1,
   "one original observer closed without budget reset");
  const preserve=x=>{const y=JSON.parse(mcRaw(x));for(const k of ["paused","activeObserver","completedObservers","bundleBodyRanges","bundleBody"])delete y[k];return mcRaw(y);};
  mcNeed(preserve(after)===preserve(original)&&mcRaw(after.calls)===mcRaw(original.calls)
   &&mcRaw(after.completedObservers.slice(0,1))===mcRaw(original.completedObservers)
   &&mcRaw(after.outerFailure)===mcRaw(original.outerFailure),"only five permitted state fields changed; original error and all six calls unchanged");
  mcNeed(mcStateUnchanged(before)&&mcRaw(load(MC_SLOT+":outer_failures"))===history,"real state unchanged before proof");
  const base64=privateMap.get(MC_SLOT+":canonical_bundle_base64_original"),native=privateMap.get(MC_SLOT+":closed_native:"+MC_OP);
  mcNeed(typeof base64==="string"&&typeof native==="string"&&gitBlobMeta(base64).bytes===1673,"exact body closure products");
  const proof={schema:"heptabao.successor4a.mac-bundle-closure-proof.v1",rootGO:goPin,
   beforeState:MC_STATE,afterState:gitBlobMeta(afterRaw),originalOperation:MC_OP,
   originalPayload:MC_PAYLOAD,originalPayloadTree:MC_PAYLOAD_TREE,correctedJournal:MC_JOURNAL,
   newArchives:archived,originalErrorHistorySHA:gitBlobMeta(history),originalCallsUnchanged:true,
   allowedChangedStateFields:["paused","activeObserver","completedObservers","bundleBodyRanges","bundleBody"],
   originalFailureRetained:true,NativeCalls:0,applied:false};
  const proofArchive=await archiveFlatPublicTextsOnce({key:MC_PROOF_KEY,repository:"TrillionniumFoundation/HeptaBao",
   texts:{"before-state.original.json":before,"after-state.proposed.json":afterRaw,"PROOF.public.json":mcRaw(proof)}});
  mcNeed(proofArchive.whole===true&&mcStateUnchanged(before),"proof whole before real state publication");
  Object.assign(recovery,{phase:"prepared_external_whole",afterRaw,proof,proofArchive,canonicalBase64:base64,closedNative:native});
  store(MC_RECOVERY,recovery);
  return {ok:true,phase:recovery.phase,proofArchive,beforeState:MC_STATE,afterState:proof.afterState,NativeCalls:0,realStateChanged:false};
 }catch(error){
  const failure={message:String(error?.message??error),NativeCalls:0,automaticRetry:false,originalStateUnchanged:before===undefined?null:mcStateUnchanged(before)};
  const recovery=load(MC_RECOVERY);if(recovery){recovery.failure=failure;store(MC_RECOVERY,recovery);}
  store(MC_RECOVERY+":failure",failure);return {ok:false,failure};
 }
}
function applyMac4aOriginalPayloadClosure({goRaw,goPin,goWholeReadback}){
 try{
  mcGO(goRaw,goPin,goWholeReadback);
  const r=load(MC_RECOVERY);
  mcNeed(r?.phase==="prepared_external_whole"&&!r.failure&&r.proofArchive?.whole===true
   &&r.goRaw===goRaw&&JSON.stringify(r.goPin)===JSON.stringify(goPin),"one prepared whole recovery");
  mcNeed(mcStateUnchanged(r.before)&&mcRaw(load(MC_SLOT+":outer_failures"))===r.originalErrorHistory
   &&mcSame(r.afterRaw,r.proof.afterState),"exact original state and history before apply");
  mcNeed(load(MC_SLOT+":canonical_bundle_base64_original")===undefined
   &&load(MC_SLOT+":closed_native:"+MC_OP)===undefined,"no overwritten existing closure output");
  store(MC_SLOT+":canonical_bundle_base64_original",r.canonicalBase64);
  store(MC_SLOT+":closed_native:"+MC_OP,r.closedNative);
  store(MC_SLOT,JSON.parse(r.afterRaw));
  r.phase="applied_once";r.applied=true;store(MC_RECOVERY,r);
  return {ok:true,NativeCalls:0,GitCalls:0,afterState:r.proof.afterState,proofArchive:r.proofArchive,originalErrorRetained:true};
 }catch(error){const failure={message:String(error?.message??error),automaticRetry:false,NativeCalls:0,GitCalls:0};store(MC_RECOVERY+":apply_failure",failure);return {ok:false,failure};}
}
