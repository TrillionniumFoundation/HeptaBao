async function pageOnce(){
 const key="source4e808_export_body_recovery01";
 if(!load(key+"_closed")||load(key+"_page_error")||load(key+"_eof"))throw Error("page scope closed/error/EOF");
 const pages=load(key+"_pages")||[]; const offset=pages.length?pages[pages.length-1].value.next_offset:0;
 const req={operation_id:load(key+"_status_request").operation_id,offset,limit:16384};
 const label=String(pages.length).padStart(2,"0");
 const persist=eval("("+load("recover_r3_persist_js")+")");
 const requestRaw=JSON.stringify(req,null,2)+"\n";const requestMeta=await persist(requestRaw,"recovery01/pages/"+label+".request.json");
 store(key+"_page_inflight",{index:pages.length,request:req,requestMeta});
 const sdk=await tools.mcp__codex_apps__heptaruntime_mac_controller_operation_result(req);
 const sdkRaw=JSON.stringify(sdk,null,2)+"\n";const sdkMeta=await persist(sdkRaw,"recovery01/pages/"+label+".original.sdk.json");
 const record={request:req,requestMeta,sdkRaw,sdkMeta};store(key+"_last_page_saved",record);
 if(sdk.isError){store(key+"_page_error",record);store(key+"_page_inflight",null);return{error:true,sdk:sdkMeta};}
 const ts=sdk.content.filter(x=>x.type==="text").map(x=>x.text);
 if(ts.length!==1){store(key+"_page_error",record);throw Error("page native text count");}
 const raw=ts[0];const meta=await persist(raw,"recovery01/pages/"+label+".original.json");
 const v=JSON.parse(raw);record.raw=raw;record.meta=meta;record.value=v;
 const dec=eval("("+load("source_decode_base64_js")+")");const bytes=dec(v.data_base64);
 if(v.operation_id!==req.operation_id||v.offset!==offset||v.next_offset!==offset+bytes.length||v.total_bytes>1048576||v.next_offset>v.total_bytes||v.immutable_snapshot!==true||v.eof!==(v.next_offset===v.total_bytes)||!bytes.length)throw Error("page exact range/immutability");
 if(pages.length&&(v.result_sha256!==pages[0].value.result_sha256||v.total_bytes!==pages[0].value.total_bytes))throw Error("page snapshot mismatch");
 record.bytes=bytes;pages.push(record);store(key+"_pages",pages);store(key+"_page_inflight",null);store(key+"_eof",v.eof);
 return{error:false,index:pages.length-1,offset:v.offset,next_offset:v.next_offset,total_bytes:v.total_bytes,result_sha256:v.result_sha256,eof:v.eof,sdk:sdkMeta,native:meta};
}