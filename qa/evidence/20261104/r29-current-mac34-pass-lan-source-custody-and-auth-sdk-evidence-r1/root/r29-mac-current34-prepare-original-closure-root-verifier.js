function verifyPrepareChains(data,H){
const {lossless,unb64,u,bs,s256}=H,r=data.raw,c=[],closed=[];
function ok(n,v){if(!v)throw Error(n);c.push(n);}
function canon(v){return JSON.stringify((function f(x){if(Array.isArray(x))return x.map(f);if(x&&typeof x==="object")return Object.fromEntries(Object.keys(x).sort().map(k=>[k,f(x[k])]));return x;})(v));}
function nat(t,n){const x=lossless(t);ok(n+":not-error",x.isError!==true);const a=x.content?.filter(v=>v.type==="text");ok(n+":one-text",a?.length===1);return{text:a[0].text,v:lossless(a[0].text)};}
const rows=lossless(r["operations/index.public.json"]);
ok("two-unique-original-reads",rows.length===2&&rows[0].name==="authority"&&rows[1].name==="streams"&&new Set(rows.map(x=>x.operation_id)).size===2);
for(const x of rows){
 const n=x.name,d="reads/"+n,req=x.request,ack=nat(r[d+"/admission.original.sdk.json"],n+":ack"),st=nat(r[d+"/status.original.sdk.json"],n+":status"),intent=lossless(r[d+"/intent.public.json"]),tool=n==="authority"?"process_status":"process_read";
 ok(n+":fixed-job-intent",canon(intent.request)===canon(req)&&req.operation.tool===tool&&req.operation.arguments.host==="mac"&&req.operation.arguments.job_id==="1a1ac939a61-fc05-5570");
 if(n==="streams")ok("streams:original0-offset16KiB",req.operation.arguments.stdout_offset===0&&req.operation.arguments.stderr_offset===0&&req.operation.arguments.limit===16384);
 ok(n+":ACK-native-identity",ack.text===r[d+"/admission.original.native.json"]&&ack.v.operation_id===x.operation_id&&ack.v.tool_name===tool&&ack.v.reused===false&&ack.v.idempotency_binding_retained===true);
 ok(n+":status-native-closure",st.text===r[d+"/status.original.native.json"]&&st.v.operation_id===x.operation_id&&st.v.tool_name===tool&&st.v.async_state==="completed"&&st.v.result_state==="stored_observed"&&st.v.owned_future_active===false&&st.v.payload_available===true);
 const raw=r[d+"/immutable-payload.original.json"],bytes=u(raw),hash=s256(bs(bytes));let cursor=0,parts=[];
 for(const page of x.pages){
  const pg=nat(r[page.sdk.path],n+":page"),v=pg.v,b=unb64(v.data_base64);
  ok(n+":page-native-exact",pg.text===r[page.native.path]);
  ok(n+":page-bound-to-original",v.operation_id===x.operation_id&&v.offset===cursor&&v.offset===page.offset&&v.next_offset===cursor+b.length&&b.length===page.bytes&&b.length<=16384);
  ok(n+":page-immutable-hash-eof",v.immutable_snapshot===true&&v.payload_kind==="native_result"&&v.total_bytes===bytes.length&&v.result_sha256===hash&&v.eof===(v.next_offset===bytes.length));
  cursor=v.next_offset;parts.push(...b);
 }
 ok(n+":original-whole-SDK",x.pages.length===1&&cursor===bytes.length&&cursor===x.total_bytes&&hash===x.result_sha256&&bs(parts)===bs(bytes));
 const out=nat(raw,n+":payload");ok(n+":native-exact",out.text===r["actual/"+n+".original.json"]);
 closed.push({name:n,operation_id:x.operation_id,tool,original_sdk_bytes:cursor,original_sdk_sha256:hash,immutable_pages:x.pages.length,completed:true,owned_future_active:false});
}
ok("stdout-root37-input-exact",r["actual/stdout.original.log"]===data.stdout);
ok("authority-root37-input-exact",r["actual/authority.original.json"]===data.authority);
ok("streams-root37-input-exact",r["actual/streams.original.json"]===data.streams);
ok("ACK-root37-input-exact",r["actual/prepare-start.original.native.json"]===data.ack);
ok("canonical-prepared-root37-exact",r["derived/prepared.actual.canonical.json"]===data.preparedCanonical);
ok("canonical-request-root37-exact",r["review/prepare-requestbinding.canonical.json"]===data.requestCanonical);
return{schema:"heptabao.root-mac34-prepare-original-chain-addendum.r29.v1",status:"PASS_PREPARE_ORIGINAL_CLOSURE_AND_WHOLE_INPUTS",packet:"e97e8aa0aabc61c6ab33d74a532b5db0fd73a019",files:39,bytes:347298,merkle_trees:10,checks_passed:c.length,checks:c,closed_observers:closed,lossless_actual_binding_root37:"c5f108be1fea634bbe89a46ac722a2c63d0364b4",prepared_sha256:"ff9ccbc62be817c507ad47e1f2aea7463a2e7b5e636e7ac1c292f4b88e504da3",conditional_live_GO:"a18dd24a7f863fc93a9d4e71a3cea123c3d262d1",prepare_conditions_satisfied:true,root_Runtime_calls:0,full34_runtime_pass_claimed:false,full_replacement_qualified:false};
}
