
function verifyOriginalJournal({label,calls,observers,blob,goPins,pageLimit,ck}){
 const eq=(s,p)=>{const m=gitBlobMeta(s);return m.blob===p.blob&&m.bytes===p.bytes&&m.sha256===p.sha256};
 ck(label+"_unique_calls",new Set(calls.map(c=>c.key)).size===calls.length);
 const cs=calls.map(c=>{
  const qr=c.requestText,sr=c.sdkText,nr=c.nativeText,a=JSON.parse(c.armedText),it=JSON.parse(c.intentText),sdk=JSON.parse(sr);
  const go=goPins.find(p=>p.blob===a.rootGo.blob);
  ck(label+"_call_"+c.key,eq(qr,c.requestPin)&&eq(sr,c.sdkPin)&&eq(nr,c.nativePin)&&c.phase==="accepted"&&sdk.isError===false&&sdk.content.length===1&&sdk.content[0].type==="text"&&sdk.content[0].text===nr&&a.callKey===c.key&&it.callKey===c.key&&a.kind===c.kind&&it.kind===c.kind&&eq(qr,a.request)&&eq(qr,it.request)&&!!go&&JSON.stringify(a.rootGo)===JSON.stringify(it.rootGo)&&a.rootGo.bytes===go.bytes&&a.rootGo.sha256===go.sha256&&a.maximumNativeCalls===1&&it.maximumNativeCalls===1&&it.nativeNotYetCalled===true&&a.nativeNotYetCalled===true&&a.mayHaveDispatchedAfterThisCheckpoint===true&&a.lossOfAcknowledgmentNeverGrantsReplay===true);
  if(c.armedTree)ck(label+"_armed_tree_"+c.key,immediateTreeSha([{path:"armed.json",mode:"100644",type:"blob",sha:gitBlobMeta(c.armedText).blob},{path:"intent.json",mode:"100644",type:"blob",sha:gitBlobMeta(c.intentText).blob},{path:"request.json",mode:"100644",type:"blob",sha:gitBlobMeta(qr).blob}])===c.armedTree);
  return {c,q:JSON.parse(qr),n:parseLosslessIntegers(nr),a,it};
 });
 ck(label+"_observer_unique",new Set(observers.map(o=>o.id)).size===observers.length);
 for(const o of observers){
  const starts=cs.filter(x=>x.c.kind==="operation_start"&&x.n.operation_id===o.id),sts=cs.filter(x=>x.c.kind==="operation_status"&&x.q.operation_id===o.id),pages=cs.filter(x=>x.c.kind==="operation_result"&&x.q.operation_id===o.id).sort((a,b)=>a.q.offset-b.q.offset);
  ck(label+"_observer_"+o.id,starts.length===1&&sts.length===1&&starts[0].n.reused===true&&starts[0].q.operation.tool===o.tool&&starts[0].n.tool_name===o.tool&&sts[0].n.operation_id===o.id&&sts[0].n.async_state==="completed"&&sts[0].n.result_state==="stored_observed"&&sts[0].n.owned_future_active===false&&sts[0].n.payload_available===true&&o.completedInactive===true&&pages.length===o.pages);
  let bytes=[],offset=0;
  for(const x of pages){const b=unb64(x.n.data_base64);ck(label+"_page_"+o.id+"_"+offset,x.n.operation_id===o.id&&x.q.offset===offset&&x.n.offset===offset&&x.q.limit===pageLimit(o)&&b.length>0&&b.length<=x.q.limit&&x.n.next_offset===offset+b.length&&x.n.immutable_snapshot===true&&x.n.payload_kind==="native_result"&&x.n.result_sha256===o.payload.sha256&&x.n.total_bytes===o.payload.bytes&&x.n.eof===(offset+b.length===o.payload.bytes));for(const z of b)bytes.push(z);offset+=b.length;}
  const raw=utf8Text(bytes),payload=JSON.parse(raw);
  ck(label+"_payload_"+o.id,offset===o.payload.bytes&&eq(raw,o.payload)&&raw===blob(o.payload.blob)&&payload.resultType==="complete"&&payload.isError===false&&payload.content.length===1&&payload.content[0].type==="text"&&eq(payload.content[0].text,o.nativeText)&&payload.content[0].text===blob(o.nativeText.blob));
 }
 ck(label+"_all_observer_calls_accounted",cs.filter(x=>x.c.kind!=="process_start").length===observers.reduce((n,o)=>n+o.pages+2,0)&&cs.filter(x=>x.c.kind==="operation_start").every(x=>observers.some(o=>o.id===x.n.operation_id)));
 return cs;
}
