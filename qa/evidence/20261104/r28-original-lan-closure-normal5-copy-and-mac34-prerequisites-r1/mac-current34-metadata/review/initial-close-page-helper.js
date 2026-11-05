async function closePage(role){
 const sdk=JSON.parse(load("mac34_metadata_"+role+"_page_sdk_raw"));if(sdk.isError||sdk.local_caught_error)throw Error("result transport error");
 const pageRaw=sdk.content[0].text,page=JSON.parse(pageRaw),id=load("mac34_metadata_"+role+"_operation_id");
 if(page.operation_id!==id||page.offset!==0||page.eof!==true||page.immutable_snapshot!==true||page.payload_kind!=="native_result"||page.next_offset!==page.total_bytes||page.total_bytes>16384)throw Error("unexpected page");
 const bytes=eval("("+load("mac34_metadata_decode64_js")+")")(page.data_base64),h=eval("("+load("source_hash_sha256_js")+")"),u=eval("("+load("source_hash_utf8_js")+")");
 if(bytes.length!==page.total_bytes||h(bytes)!==page.result_sha256)throw Error("payload whole hash");
 const payloadRaw=decodeURIComponent(bytes.map(b=>"%"+b.toString(16).padStart(2,"0")).join(""));if(u(payloadRaw).length!==bytes.length)throw Error("utf8");
 const persist=eval("("+load("recover_r3_persist_js")+")"),files=load("mac34_metadata_files");
 files.push(await persist(pageRaw,"reads/"+role+"/page-00000.original.json"));files.push(await persist(payloadRaw,"reads/"+role+"/payload.original.sdk.json"));store("mac34_metadata_"+role+"_payload_raw",payloadRaw);
 const payload=JSON.parse(payloadRaw);if(payload.resultType!=="complete"||payload.isError!==false||payload.content?.length!==1||payload.content[0].type!=="text")throw Error("native tool failed");
 const infoRaw=payload.content[0].text,nativeMeta=await persist(infoRaw,"reads/"+role+"/file-info.original.json");files.push(nativeMeta);store("mac34_metadata_"+role+"_fileinfo_raw",infoRaw);
 const info=JSON.parse(infoRaw),approval=JSON.parse(load("mac34_metadata_root_approval_raw")).requests.find(x=>x.name===role);
 if(info.path!==approval.path||!Number.isSafeInteger(info.size)||info.size<=0||!/^[0-9a-f]{64}$/.test(info.sha256)||(approval.expected_sha256!==null&&info.sha256!==approval.expected_sha256)||(approval.expected_bytes!==null&&info.size!==approval.expected_bytes)||info.metadata?.metadata_platform!=="darwin"||info.metadata?.link_count!==1||info.mode!==info.metadata.mode||!/^\\d+:\\d+:\\d+:\\d+:\\d+$/.test(info.version)||info.version.split(":")[2]!==String(info.size))throw Error("file info binding");
 const closure={schema:"heptabao.current-mac-full34-fixed-file-info-closure.v1",role,request_blob:approval.blob,operation_id:id,completed:true,result_state:"stored_observed",owned_future_active:false,immutable_payload_bytes:bytes.length,immutable_payload_sha256:page.result_sha256,payload_eof:true,file_info_blob:nativeMeta.blob,path:info.path,bytes:info.size,sha256:info.sha256,version:info.version,mode_permissions:info.mode,link_count:info.metadata.link_count,full9_projection_pending_python_lossless:true,new_process_started:false};
 files.push(await persist(JSON.stringify(closure,null,2)+"\n","reads/"+role+"/closure.public.json"));store("mac34_metadata_files",files);
 store("mac34_metadata_state",{...load("mac34_metadata_state"),current:null,native_inflight:false,completed:[...load("mac34_metadata_state").completed,role]});
 return closure;
}