async function checkActualPreparedRootGo(input) {
 const checks=[];function c(k,v){checks.push({check:k,pass:!!v});if(!v)throw Error(k);}
 const source=input.after,original=JSON.parse(input.stateRaw);
 const go={authorization:"GO",scope:"build_failed_test2_logs_binary_read_only",original_job:"1a1b10cad9b-fc05-7560",maximum_binary_read_starts:2,maximum_file_info_starts:0,maximum_process_start_calls:0,immutable_body_page_bytes:16384,exact_requests:input.requestPins,info_operations:input.expected.map(x=>x.infoOperation)};
 const goRaw=JSON.stringify(go,null,2)+"\n",bodyPin=gitBlobMeta(goRaw);
 function fixture(){
  const map=new Map([[input.slot,JSON.parse(input.stateRaw)],[input.priorSlot,JSON.parse(input.priorStateRaw)]]);
  input.expected.forEach((x,i)=>map.set(input.slot+":closed_native:"+x.infoOperation,input.nativeRaws[i]));
  const archives=[];
  const archive=async({key,repository,texts})=>{
   archives.push({key,repository,texts:JSON.parse(JSON.stringify(texts))});
   return {tree:"a".repeat(40),whole:true,count:Object.keys(texts).length,entries:Object.entries(texts).map(([path,raw])=>({path,...gitBlobMeta(raw),whole:true})),pureMock:true};
  };
  const f=new Function("tools","store","load","archiveFlatPublicTextsOnce",input.pure+"\n"+source+"\nreturn {authorize:gfAuthorizeFailedTestLogBodiesOnly,prepare:gfPrepareOne};")({},(k,v)=>map.set(k,v),k=>map.get(k),archive);
  return {map,archives,f};
 }
 const f0=fixture(),i0=f0.map.get(input.slot);
 i0.calls={};i0.completedObservers=[];i0.logInfos=[];i0.logInfoStarted=[false,false];
 const infoRequest=JSON.parse(input.stateRaw).calls["jwt-pki-025b-test2-stderr-info-admit"].requestRaw;
 await f0.f.prepare({callKey:"fake-original-info",kind:"operation_start",requestRaw:infoRequest});
 for(const part of ["intent.json","armed.json"]){
  c("INFO-"+part+"-old-rootGo",JSON.parse(f0.archives[0].texts[part]).rootGo.blob===original.goPin.blob);
 }
 const f=fixture(),st=f.map.get(input.slot),oldCalls=JSON.stringify(st.calls),oldObservers=JSON.stringify(st.completedObservers);
 f.f.authorize({goRaw,goPin:bodyPin,goWholeReadback:true});
 c("authorize-preserves-old-calls",JSON.stringify(st.calls)===oldCalls);
 c("authorize-preserves-old-observers",JSON.stringify(st.completedObservers)===oldObservers);
 const id="b".repeat(64);
 const calls=[
  {callKey:"fake-body-admit",kind:"operation_start",requestRaw:input.requestRaws[0]},
  {callKey:"fake-body-status",kind:"operation_status",requestRaw:JSON.stringify({operation_id:id})+"\n"},
  {callKey:"fake-body-result",kind:"operation_result",requestRaw:JSON.stringify({operation_id:id,offset:0,limit:16384})+"\n"}
 ];
 for(let i=0;i<calls.length;i++){
  if(i===1){st.pending=null;st.activeObserver={id,tool:"binary_read",futureClosed:false,nextPageOffset:0,eof:false};}
  if(i===2){st.pending=null;st.activeObserver.futureClosed=true;}
  await f.f.prepare(calls[i]);
  const capture=f.archives[i];
  c(calls[i].kind+"-one-captured-archive",capture.key==="gfa-"+calls[i].callKey&&capture.repository==="TrillionniumFoundation/HeptaBao");
  for(const name of ["intent.json","armed.json"]){
   const v=JSON.parse(capture.texts[name]);
   c(calls[i].kind+"-"+name+"-BODY-rootGo",JSON.stringify(v.rootGo)===JSON.stringify(bodyPin));
   c(calls[i].kind+"-"+name+"-one-call",v.maximumNativeCalls===1&&v.kind===calls[i].kind);
  }
  c(calls[i].kind+"-request-exact",capture.texts["request.json"]===calls[i].requestRaw);
 }
 c("old-six-calls-still-byte-values",Object.entries(original.calls).every(([k,v])=>JSON.stringify(st.calls[k])===JSON.stringify(v)));
 c("original-info-arms-still-old-rootGo",Object.entries(original.calls).every(([k,v])=>JSON.parse(input.originalArmed[k]).rootGo.blob===original.goPin.blob&&gitBlobMeta(input.originalArmed[k]).blob===v.armed.entries.find(x=>x.path==="armed.json").blob&&JSON.stringify(st.calls[k].armed)===JSON.stringify(v.armed)));
 c("prior-build-context-exact",JSON.stringify(f.map.get(input.priorSlot),null,2)+"\n"===input.priorStateRaw);
 c("new-source-selects-validated-body",source.includes("rootGo:s.failedTestLogBodiesGO?.pin??s.goPin"));
 return {schema:"heptabao.two-log-bodies-rootgo-actual-prepare-fake.r2",pass:true,check_count:checks.length,checks,actualCapturedArchiveCalls:f.archives.length+f0.archives.length,Native_calls:0,Git_calls:0,product_cases:0};
}
