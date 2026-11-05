function verifyLanSources(data,H){
 const {u,bs,s256,unb64,lossless}=H,raw=data.raw,checks=[],operations=[],sources=[];
 function ok(n,v){if(!v)throw Error(n);checks.push(n);}
 function hash(t){return s256(bs(u(t)));}
 function canon(v){return JSON.stringify((function sort(x){if(Array.isArray(x))return x.map(sort);if(x&&typeof x==="object")return Object.fromEntries(Object.keys(x).sort().map(k=>[k,sort(x[k])]));return x;})(v));}
 function dec(v){return v&&typeof v==="object"&&"$exactInteger" in v?v.$exactInteger:String(v);}
 function native(t,n){const x=lossless(t);ok(n+":sdk-not-error",x.isError!==true);const a=x.content?.filter(i=>i.type==="text");ok(n+":one-native-text",a?.length===1);return {text:a[0].text,value:lossless(a[0].text)};}
 const plan=lossless(raw["references/original-frozen-plan.public.json"]).stages.source_readback_after_receipt,receipt=lossless(raw["references/original-receipt.public.json"]),state=lossless(raw["state.public.json"]);
 ok("nine-exact-planned-files",plan.length===9&&receipt.files.length===9&&state.total_sources===9);
 ok("packet-complete-nine",state.whole_sources_completed===9&&state.native_read_calls_inflight===0);
 function observe(i,label,request){
  const pref="source-"+i+"/observations/"+label,actualReq=lossless(raw[pref+"_start/request.json"]);ok(label+":exact-typed-request",canon(actualReq)===canon(request));
  let startSDK=raw[pref+"_start/original-sdk.json"];
  if(i===3&&label==="source3_body0"){
   const old=lossless(startSDK),rec=pref+"-reconciliation";
   ok(label+":original-lost-ack-preserved",old.isError===true&&old.content[0].text.includes("MCP request timed out"));
   ok(label+":same-original-request-reconciliation",raw[rec+"/ack/request.json"]===raw[pref+"_start/request.json"]&&raw[rec+"/intent/exact-original-request.json"]===raw[pref+"_start/request.json"]&&raw[rec+"/intent/original-error-sdk.json"]===startSDK);
   startSDK=raw[rec+"/ack/original-sdk.json"];
  }
  const ack=native(startSDK,label+":ack").value,id=ack.operation_id;
  ok(label+":retained-id-binding",typeof id==="string"&&id.length===64&&ack.idempotency_binding_retained===true&&ack.tool_name===request.operation.tool&&ack.reused===false);
  const statPaths=Object.keys(raw).filter(p=>p.startsWith(pref+"_status")&&p.endsWith("/original-sdk.json")).sort();ok(label+":status-evidence",statPaths.length>0);
  let last;
  for(const sp of statPaths){const r=lossless(raw[sp.replace("/original-sdk.json","/request.json")]),n=native(raw[sp],label+":status");ok(sp+":original-id",r.operation_id===id&&n.value.operation_id===id&&n.value.tool_name===request.operation.tool);last=n.value;}
  ok(label+":original-returned-future-closed",last.async_state==="completed"&&last.result_state==="stored_observed"&&last.owned_future_active===false&&last.payload_available===true);
  const serialized=raw[pref+".payload.json"],expectedBytes=u(serialized),expectedHash=hash(serialized),pages=Object.keys(raw).filter(p=>p.startsWith(pref+"_result")&&p.endsWith("/original-sdk.json")).sort((a,b)=>Number(a.slice((pref+"_result").length).split("/")[0])-Number(b.slice((pref+"_result").length).split("/")[0]));
  let cursor=0,assembled=[];
  ok(label+":pages-present",pages.length>0);
  for(const pp of pages){const r=lossless(raw[pp.replace("/original-sdk.json","/request.json")]),v=native(raw[pp],label+":page").value,b=unb64(v.data_base64);
   ok(pp+":original-id-fixed-page",r.operation_id===id&&v.operation_id===id&&r.offset===cursor&&v.offset===cursor&&r.limit===8192);
   ok(pp+":immutable-whole-binding",v.immutable_snapshot===true&&v.payload_kind==="native_result"&&v.total_bytes===expectedBytes.length&&v.result_sha256===expectedHash&&v.format==="serialized_original_native_sdk_payload_before_operation_metadata_and_transport_normalization");
   ok(pp+":range-eof",b.length<=8192&&v.next_offset===cursor+b.length&&v.eof===(v.next_offset===expectedBytes.length));
   cursor=v.next_offset;assembled.push(...b);
  }
  ok(label+":serialized-original-whole",cursor===expectedBytes.length&&bs(assembled)===bs(expectedBytes)&&s256(bs(assembled))===expectedHash);
  const v=native(serialized,label+":payload");ok(label+":native-original-exact",v.text===raw[pref+".native.json"]);
  operations.push({label,operation_id:id,tool:request.operation.tool,original_sdk_bytes:cursor,original_sdk_sha256:expectedHash,pages:pages.length,completed:true,owned_future_active:false});return v.value;
 }
 for(let i=0;i<9;i++){
  const p=plan[i],rr=receipt.files.find(x=>x.path===p.path);ok("source"+i+":frozen-publication-pin",!!rr&&rr.bytes===p.expected_bytes&&rr.sha256===p.expected_sha256&&rr.publication==="created"&&rr.mode==="0600");
  const info=observe(i,"source"+i+"_info",p.info_request),v=info.version.split(":");
  ok("source"+i+":independent-info",info.path===p.path&&info.size===p.expected_bytes&&info.sha256===p.expected_sha256&&v.length===5);
  const full9=[v[0],v[1],dec(info.metadata.uid),dec(info.metadata.gid),String(32768+info.mode),dec(info.metadata.link_count),dec(info.size),v[3],v[4]];
  ok("source"+i+":independent-full9",JSON.stringify(full9)===JSON.stringify(rr.identity.map(dec))&&info.mode===384&&info.metadata.mode===384&&info.metadata.uid===1000&&info.metadata.gid===1000&&info.metadata.link_count===1&&v[2]===String(info.size));
  let assembled=[],cursor=0;
  for(const c of p.body_chunks){const q=JSON.parse(JSON.stringify(c.request_template));q.operation.arguments.expected_version=info.version;
   const x=observe(i,"source"+i+"_body"+c.offset,q),b=unb64(x.data_base64);
   ok("source"+i+":chunk"+c.offset+"-identity",x.path===info.path&&x.version===info.version&&x.size===info.size&&x.offset===cursor&&x.offset===c.offset);
   ok("source"+i+":chunk"+c.offset+"-bytes",b.length===c.expected_decoded_bytes&&b.length===q.operation.arguments.limit&&x.next_offset===cursor+b.length&&x.chunk_sha256===s256(bs(b))&&x.eof===(x.next_offset===info.size));
   assembled.push(...b);cursor=x.next_offset;
  }
  const whole=raw["source-"+i+"/whole-source.py"];
  ok("source"+i+":entire-original-file",cursor===p.expected_bytes&&s256(bs(assembled))===p.expected_sha256&&bs(assembled)===bs(u(whole)));
  sources.push({index:i,path:p.path,bytes:p.expected_bytes,sha256:p.expected_sha256,version:info.version,full9_decimal:full9,chunks:p.body_chunks.length});
 }
 ok("34-unique-closed-returned-operations",operations.length===34&&new Set(operations.map(x=>x.operation_id)).size===34);
 const old=state.unacknowledged_initial_read_admissions;
 ok("historical-lost-ack-UNKNOWN-not-erased",old.length===1&&old[0].observation==="source3_body0"&&old[0].initial_native_future_state==="unknown"&&old[0].reconciliation_reused===false&&old[0].initial_future_not_inferred_closed_or_unstarted===true);
 return {schema:"heptabao.root-lan-nine-source-readback-review.r29.v1",status:"PASS_EXACT_SOURCE_PUBLICATION_READBACK_ONLY",packet_tree:data.tree,check_count:checks.length,checks,sources,operations,original_job:"desktop/1a1ac1641eb-fc05-521f",source_bytes:sources.reduce((n,x)=>n+x.bytes,0),historical_unacknowledged_initial_read:old,root_runtime_calls:0,source_executed:false,prepare_or_live_authorized:false,HA_qualified:false,full_replacement_qualified:false};
}
