function verifyThreePublicBodyChains(data,H){
const {lossless,u,bs,s256,s1,unb64}=H,r=data.raw,checks=[],ops=[];
function ok(n,v){if(!v)throw Error(n);checks.push(n);}
function eq(a,b){return JSON.stringify(a)===JSON.stringify(b);}
function hash(t){return s256(bs(u(t)));}
function nat(t,n){const x=lossless(t);ok(n+":SDK-not-error",x.isError!==true);const a=x.content?.filter(x=>x.type==="text");ok(n+":one-native-text",a?.length===1);return{text:a[0].text,v:lossless(a[0].text)};}
const closure=lossless(r["actual/CLOSURE.public.json"]);
ok("same-root-exact-GO",eq(lossless(r["authorization/root-exact-go.public.json"]),data.go)&&closure.rootExactGo===data.goBlob);
ok("three-whole-original-bodies",closure.bodies.length===3&&data.expected.length===3);
for(let i=0;i<3;i++){
 const e=data.expected[i],n="body-"+String(i+1).padStart(2,"0")+"-"+e.id,p="observations/"+n,requestText=r[p+"/request.original.json"],req=lossless(requestText),intent=lossless(r[p+"/intent.original.json"]);
 ok(n+":exact-frozen-request",requestText===data.requests[i]&&u(requestText).length===e.request_bytes&&hash(requestText)===e.request_sha256&&eq(req,e.request));
 ok(n+":exact-prior-intent",intent.submitted===false&&intent.singleOperation===true&&intent.previousAllOriginalsClosed===true&&intent.errorStopsFurtherAdmissions===true&&intent.rootExactGo===data.goBlob&&intent.request.blob===e.request_blob&&intent.request.sha256===e.request_sha256&&eq(intent.request.value,req));
 ok(n+":prior-actual-input-full9",intent.expectedWhole.path===e.path&&intent.expectedWhole.version===e.version&&intent.expectedWhole.bytes===e.bytes&&intent.expectedWhole.sha256===e.sha256&&eq(intent.expectedWhole.identity,e.full9_decimal));
 const ack=nat(r[p+"/ack.sdk.original.json"],n+":ACK"),st=nat(r[p+"/status-01.sdk.original.json"],n+":status"),sq=lossless(r[p+"/status-01.request.json"]),id=ack.v.operation_id;
 ok(n+":original-admission",ack.text===r[p+"/ack.native.original.txt"]&&ack.v.reused===false&&ack.v.tool_name==="binary_read"&&ack.v.idempotency_binding_retained===true&&typeof id==="string");
 ok(n+":original-status-closed",st.text===r[p+"/status-01.native.original.txt"]&&sq.operation_id===id&&st.v.operation_id===id&&st.v.async_state==="completed"&&st.v.result_state==="stored_observed"&&st.v.owned_future_active===false&&st.v.payload_available===true);
 const payload=r[p+"/payload.sdk.original.txt"],payloadBytes=u(payload),pq=lossless(r[p+"/page-00000000.request.json"]),pg=nat(r[p+"/page-00000000.sdk.original.json"],n+":page"),b=unb64(pg.v.data_base64);
 ok(n+":one-original-page-request",pq.operation_id===id&&pq.offset===0&&pq.limit===16384&&pg.v.operation_id===id&&pg.text===r[p+"/page-00000000.native.original.txt"]);
 ok(n+":immutable-full-payload",pg.v.immutable_snapshot===true&&pg.v.payload_kind==="native_result"&&pg.v.offset===0&&pg.v.total_bytes===payloadBytes.length&&pg.v.next_offset===payloadBytes.length&&pg.v.eof===true&&payloadBytes.length<=16384&&pg.v.result_sha256===hash(payload)&&bs(b)===bs(payloadBytes));
 const actual=nat(payload,n+":payload"),a=actual.v,body=r["sources/"+e.id+".original.js"],bodyBytes=u(body),decoded=unb64(a.data_base64),binding=lossless(r[p+"/actual-binding.public.json"]);
 ok(n+":exact-original-native",actual.text===r[p+"/payload.native.original.txt"]);
 ok(n+":actual-input-version-bound",a.path===e.path&&a.version===e.version&&a.size===e.bytes&&a.offset===0&&a.next_offset===e.bytes&&a.eof===true&&a.chunk_sha256===e.sha256);
 ok(n+":whole-source-hash-and-length",decoded.length===e.bytes&&bodyBytes.length===e.bytes&&bs(decoded)===bs(bodyBytes)&&hash(body)===e.sha256);
 const blob=s1(u("blob "+bodyBytes.length+"\0").concat(bodyBytes));
 ok(n+":closure-bound-to-actual",binding.operationId===id&&binding.blob===blob&&binding.sha256===e.sha256&&binding.bytes===e.bytes&&binding.originalClosedFull===true&&binding.sdkExecuted===false&&eq(binding.operationId,closure.bodies[i].operationId)&&closure.bodies[i].blob===blob);
 ops.push({name:n,operation_id:id,path:e.path,body_bytes:e.bytes,body_sha256:e.sha256,body_blob:blob,version:e.version,payload_bytes:payloadBytes.length,payload_sha256:hash(payload),completed:true,owned_future_active:false,immutable_pages:1});
}
ok("distinct-three-original-IDs",new Set(ops.map(x=>x.operation_id)).size===3);
ok("13569-total-within-admitted-readset",ops.reduce((n,x)=>n+x.body_bytes,0)===13569&&closure.totalAcceptedBodyBytes===13569);
ok("claimed-closure-has-no-inflight-or-errors",closure.runtimeCallsInFlight===0&&closure.nativeFuturesActive===0&&closure.allOriginalOperationsCompletedStoredInactive===true&&closure.errors.length===0&&closure.lineBReleasedToRoot===true&&closure.sdkImportOrExecution===false&&closure.actualSelectedOwnerProven===false);
return{schema:"heptabao.root-three-public-body-actual-chain-review.r30.v1",status:"PASS_ORIGINAL_READS_AND_WHOLE_SOURCES_ONLY",checks_passed:checks.length,checks,packet:data.packet,closed_original_operations:ops,total_body_bytes:13569,immutable_pages:3,line_B_prior_owner_released:true,active_known_Runtime_calls:0,active_known_native_futures:0,SDK_execution_qualified:false,selected_owner_proven:false,credential_qualification:false,full_replacement_qualified:false,root_Runtime_calls:0};
}