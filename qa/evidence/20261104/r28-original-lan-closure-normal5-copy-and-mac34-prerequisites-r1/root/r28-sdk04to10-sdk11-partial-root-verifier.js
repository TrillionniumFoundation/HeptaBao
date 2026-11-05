function verifySdk04to10And11(r, oldRaw, thirdNativeText, originalReqRaw, originalReqAudit, h) {
 const {utf8,bs,sha,unb64}=h,checks=[],hash=t=>sha(bs(utf8(t)));function ck(n,v){if(!v)throw Error(n);checks.push(n);}
 function sdk(t){const s=JSON.parse(t);ck("sdk_success_"+checks.length,s.isError===false);const x=s.content.filter(z=>z.type==="text");ck("sdk_one_native_"+checks.length,x.length===1);return{text:x[0].text,v:JSON.parse(x[0].text)};}
 let prefix=bs(unb64(JSON.parse(oldRaw["actual/02-selector_000000/original-binary-result.json"]).data_base64))+bs(unb64(JSON.parse(thirdNativeText).data_base64));
 const observations=[];
 for(let seq=4;seq<=10;seq++){
  const offset=(seq-2)*65536,base="operations/"+String(seq).padStart(2,"0")+"-selector_"+offset,obs=JSON.parse(r[base+"/observation.public.json"]),req=JSON.parse(r[base+"/request.original.json"]),rq=originalReqAudit.records.find(x=>x.blob===obs.request_blob);
  ck(base+"_frozen_request_bytes",!!rq&&r[base+"/request.original.json"]===originalReqRaw[rq.path]);
  const ack=sdk(r[base+"/start.sdk.original.json"]).v,statusPath=seq===10?"status/reconcile-01":"status/00",st=sdk(r[base+"/"+statusPath+"/sdk.original.json"]).v;
  ck(base+"_same_closed_operation",st.operation_id===ack.operation_id&&st.operation_id===obs.operation_id&&st.async_state==="completed"&&st.owned_future_active===false&&st.payload_available===true);
  let payload="",cursor=0,total=null,digest=null;
  for(let k=0;k<6;k++){const pbase=base+"/pages/"+String(k).padStart(2,"0"),q=JSON.parse(r[pbase+"/request.public.json"]),p=sdk(r[pbase+"/sdk.original.json"]).v,b=unb64(p.data_base64);if(total===null){total=p.total_bytes;digest=p.result_sha256;}
   ck(pbase+"_identity",q.operation_id===ack.operation_id&&p.operation_id===ack.operation_id&&q.offset===cursor&&p.offset===cursor);ck(pbase+"_whole_payload_binding",p.total_bytes===total&&p.result_sha256===digest&&p.immutable_snapshot===true);ck(pbase+"_bounds",p.next_offset===cursor+b.length&&b.length<=q.limit);payload+=bs(b);cursor+=b.length;ck(pbase+"_eof",p.eof===(cursor===total));}
  ck(base+"_payload_exact",payload===r[base+"/original.sdk.payload.json"]&&utf8(payload).length===total&&hash(payload)===digest);
  const n=sdk(payload);ck(base+"_native_exact",n.text===r[base+"/original.native.payload.json"]);const b=unb64(n.v.data_base64),args=req.operation.arguments;
  ck(base+"_original_binary_read",req.operation.tool==="binary_read"&&args.host==="mac"&&args.path==="/opt/homebrew/lib/node_modules/openclaw/dist/selection-JInn13lc.js");
  ck(base+"_version_size",n.v.path===args.path&&n.v.version===args.expected_version&&n.v.version==="16777233:405239260:673468:1784843463381890779:1784843463381890779"&&n.v.size===673468);
  ck(base+"_chunk_bounds",args.offset===offset&&args.limit===65536&&n.v.offset===offset&&n.v.next_offset===offset+65536&&n.v.eof===false&&b.length===65536);
  ck(base+"_chunk_hash",sha(bs(b))===n.v.chunk_sha256&&sha(bs(b))===obs.actual_chunk_sha256);prefix+=bs(b);observations.push({seq,operation_id:ack.operation_id,offset,next_offset:n.v.next_offset,bytes:b.length,chunk_sha256:n.v.chunk_sha256,payload_bytes:total,pages:6});
 }
 ck("selector_exact_contiguous_prefix",prefix.length===589824&&sha(prefix)==="fd3b2b87350c228e8a8d74e7ffb4e4a8e739304555dce3c6e9bde09cfda0b52b");
 ck("seq10_original_timeout_preserved",JSON.parse(r["operations/10-selector_524288/status/00/sdk.original.json"]).isError===true);
 const base="operations/11-selector_589824",ack=sdk(r[base+"/start.sdk.original.json"]).v,st=sdk(r[base+"/status/00/sdk.original.json"]).v,p=sdk(r[base+"/pages/00/sdk.original.json"]).v,b=unb64(p.data_base64);
 ck("seq11_original_closed_inactive",ack.operation_id==="0a76e36c0f77a78517a742fbcae67a51ea7e7e109c056c2348750086441f0d05"&&st.operation_id===ack.operation_id&&st.async_state==="completed"&&st.owned_future_active===false);
 ck("seq11_original_first_payload_page_only",p.operation_id===ack.operation_id&&p.offset===0&&p.next_offset===16384&&b.length===16384&&p.total_bytes===87804&&p.eof===false&&p.immutable_snapshot===true);
 for(const [k,off]of [["01",16384],["02",32768]]){const q=JSON.parse(r[base+"/pages/"+k+"/request.public.json"]),er=JSON.parse(r[base+"/pages/"+k+"/sdk.original.json"]);ck("seq11_error_"+k,er.isError===true&&q.operation_id===ack.operation_id&&q.offset===off&&q.limit===16384);}
 ck("seq11_no_fabricated_native_payload",!Object.hasOwn(r,base+"/original.native.payload.json")&&!Object.hasOwn(r,base+"/original.sdk.payload.json"));
 return{schema:"heptabao.sdk04to10-and-sdk11-partial-root-review.r1",status:"SEVEN_NEW_READS_COMPLETE_ORIGINAL11_CLOSED_BUT_PAYLOAD_PARTIAL",checks_passed:checks.length,checks,packet:"6fc7c9b76208bfdba84106373644eef97fb7cb3f",new_complete_sequences:[4,5,6,7,8,9,10],complete_observations_total:10,observations,selector_prefix_bytes:prefix.length,selector_prefix_sha256:sha(prefix),selector_full_expected_bytes:673468,selector_full_expected_sha256:"ccff13111aa60369ac9d88b526a58a7df1f733f1d99d205c01c6186036957e66",full_selector_qualified:false,read11:{operation_id:ack.operation_id,native_closed_inactive:true,original_payload_total:87804,payload_bytes_obtained:16384,failed_offsets:[16384,32768],unsubmitted_offsets:[49152,65536,81920],source_chunk_materialized:false},reads12_13_submitted:false,SDK_executed:false,selected_owner_conclusion:false,original_read_replayed:false};
}
