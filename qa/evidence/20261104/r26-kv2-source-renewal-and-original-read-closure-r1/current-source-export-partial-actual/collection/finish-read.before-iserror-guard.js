async function finishSource4e8ExportRead(label){
const persist=eval("("+load("recover_r3_persist_js")+")"),dec=eval("("+load("source_decode_base64_js")+")"),utf=eval("("+load("source_decode_utf8_js")+")"),h=eval("("+load("source_hash_sha256_js")+")");
const prefix="source4e808_export_read_"+label+"_";
const admission=load(prefix+"admission");if(!admission?.operation_id)throw Error("no admission "+label);
let status=load(prefix+"status");
if(!status){
 const sdk=await tools.mcp__codex_apps__heptaruntime_mac_controller_operation_status({operation_id:admission.operation_id});
 const sr=JSON.stringify(sdk,null,2)+"\n",sm=await persist(sr,"reads/"+label+"/status.original.sdk.json");
 store(prefix+"status_sdk",sdk);store(prefix+"status_sdk_meta",sm);
 const raw=sdk.content.filter(x=>x.type==="text").map(x=>x.text).join("\n"),m=await persist(raw,"reads/"+label+"/status.original.json");
 store(prefix+"status_raw",raw);store(prefix+"status_meta",m);status=JSON.parse(raw);store(prefix+"status",status);
}
if(status.operation_id!==admission.operation_id||status.async_state!=="completed"||status.result_state!=="stored_observed"||status.owned_future_active!==false||status.payload_available!==true)return {label,closed:false,status};
let offset=0,parts=[],pages=[],snapshot=null;
for(let index=0;index<16;index++){
 const request={operation_id:admission.operation_id,offset,limit:16384};
 const sdk=await tools.mcp__codex_apps__heptaruntime_mac_controller_operation_result(request);
 const sr=JSON.stringify(sdk,null,2)+"\n",name=String(offset).padStart(6,"0");
 const sm=await persist(sr,"reads/"+label+"/page-"+name+".original.sdk.json");
 const raw=sdk.content.filter(x=>x.type==="text").map(x=>x.text).join("\n"),m=await persist(raw,"reads/"+label+"/page-"+name+".original.json");
 const page=JSON.parse(raw),bytes=dec(page.data_base64);
 pages.push({request,sdk_meta:sm,raw,meta:m});store(prefix+"pages",pages);
 if(snapshot===null)snapshot={bytes:page.total_bytes,sha256:page.result_sha256};
 if(page.operation_id!==admission.operation_id||page.immutable_snapshot!==true||page.offset!==offset||page.next_offset!==offset+bytes.length||page.total_bytes!==snapshot.bytes||page.result_sha256!==snapshot.sha256||page.total_bytes>131072||page.payload_kind!=="native_result")throw Error("page binding "+label);
 parts.push(...bytes);offset=page.next_offset;
 if(page.eof){
  if(offset!==snapshot.bytes||parts.length!==snapshot.bytes||h(parts)!==snapshot.sha256)throw Error("payload whole "+label);
  break;
 }
 if(index===15)throw Error("original payload cap");
}
const sdkRaw=utf(parts),sdkMeta=await persist(sdkRaw,"reads/"+label+"/payload.original.sdk.json");
store(prefix+"payload_raw",sdkRaw);store(prefix+"payload_meta",sdkMeta);
const payload=JSON.parse(sdkRaw);
if(payload.resultType!=="complete"||payload.isError){store(prefix+"original_error",payload);return{label,closed:true,original_error:true,payload_meta:sdkMeta};}
const texts=payload.content.filter(x=>x.type==="text");if(texts.length!==1)throw Error("native text "+label);
const nativeRaw=texts[0].text,nativeMeta=await persist(nativeRaw,"actual/"+label+".original.json");
store(prefix+"native_raw",nativeRaw);store(prefix+"native_meta",nativeMeta);
const native=JSON.parse(nativeRaw);store(prefix+"native",native);
return {label,closed:true,original_error:false,status_meta:load(prefix+"status_meta"),payload_meta:sdkMeta,native_meta:nativeMeta,native:{...native,data_base64:native.data_base64?"<saved>":undefined}};
}