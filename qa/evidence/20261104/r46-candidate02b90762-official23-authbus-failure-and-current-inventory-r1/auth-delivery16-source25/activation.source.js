/* Pure Git activation only. No Native calls and no mutation of the original runtime context. */
async function activateFutureRuntimeDelivery({goRaw,goPin,goWholeReadback}) {
 const slot="owner_authbus_current_home_runtime_gitfirst_r3",once=slot+":delivery16-activation";
 const prior={"blob":"f3ee8a7deed5183685c0b2c5701b242b5c795bce","bytes":68853,"sha256":"ce4b7bf7b8b2f271e51680405643c2ff5562bb9f246b0b473928c6504bb426bf"},after={"blob":"c2274b5979ecc8d73f95c27fdfb004339ca133db","bytes":19244,"sha256":"1988c68e38d215bb938337238b35425049c06b786630be783053b9a57c2b3418"};
 try {
  if(load(once)!==undefined)throw Error("activation_once_no_retry");
  if(goWholeReadback!==true||JSON.stringify(gitBlobMeta(goRaw))!==JSON.stringify(goPin))throw Error("whole_exact_root_amendment");
  const state=load(slot),raw=JSON.stringify(state,null,2)+"\n";
  if(JSON.stringify(gitBlobMeta(raw))!==JSON.stringify(prior))throw Error("exact_prior_closed_state");
  if(state.job!=="1a1b1d28dc2-fc05-7afe"||state.paused||state.pending!==null||state.activeObserver!==null||state.nativeCallInFlight!==false||state.completedObservers.length!==3||state.nextStdout!==32768||state.nextStderr!==0)throw Error("closed_original_boundary");
  const journal=load("authbus_home_r3_runtime_delivery_journal");
  if(typeof journal!=="string"||JSON.stringify(gitBlobMeta(journal))!==JSON.stringify(after))throw Error("exact_reviewed_delivery_source");
  const record={schema:"heptabao.original-runtime-future-delivery-activation.v1",originalRootGo:state.goPin,deliveryRootGo:goPin,priorClosedState:prior,afterJournal:after,slot,oldObserversUnchanged:true,oldCallsUnchanged:true,originalContextUnchanged:true,nextStdout:32768,futureProcessReadPageLimit:16384,otherNewObserverPageLimit:8192,newStarts:0,NativeCalls:0};
  store(once,{phase:"external_archive_entered_once",record});
  const archived=await archiveFlatPublicTextsOnce({key:"authbus-home-r3-delivery16-activation-r1",repository:"TrillionniumFoundation/HeptaBao",texts:{"prior-closed-state.original.json":raw,"delivery-root-GO.original.json":goRaw,"activation.public.json":JSON.stringify(record,null,2)+"\n"}});
  if(JSON.stringify(load(slot),null,2)+"\n"!==raw)throw Error("original_state_changed_during_pure_archive");
  const complete={...record,phase:"whole_before_future_observer",archive:archived.tree,whole:archived.whole};
  store(once,complete);
  store("authbus_home_r3_runtime_active_delivery_journal",journal);
  return {ok:true,...complete};
 } catch(error) {
  const failure={schema:"heptabao.delivery-activation-failure.v1",name:error.name,message:String(error.message),NativeCalls:0,newAdmissionAllowed:false,noMutationRetry:true};
  store(once+":failure",failure);
  return {ok:false,failure};
 }
}
