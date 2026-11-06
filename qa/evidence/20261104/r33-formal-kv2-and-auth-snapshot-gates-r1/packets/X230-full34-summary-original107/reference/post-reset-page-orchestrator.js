async function readPreparedPageAndFreezeNext(){
 const H=eval(load("r32_root_helpers_source")+";({save:saveVerifiedPublicBlobJournaled,persist:persistRecoveryText,unb64})");
 const s=load("x230_full34_recovered_read_state"),c=load("x230_full34_recovered_pending_page");
 if(!s||s.halted||s.call_inflight||s.complete||!c||c.submitted||c.request.operation_id!==s.active_operation_id||c.request.offset!==s.next_offset||c.request.limit!==8192)throw Error("original immutable page state");
 const label=s.label+"-page-"+String(c.request.offset).padStart(6,"0");
 c.submitted=true;s.call_inflight=true;store("x230_full34_recovered_pending_page",c);store("x230_full34_recovered_read_state",s);
 await H.persist("x230-full34-"+label+"-submitted",JSON.stringify({request:c.request,requestPin:c.requestPin,intentPin:c.intentPin,submission_started:true},null,2)+"\n");
 let sdk;
 try {sdk=await tools.mcp__codex_apps__heptaruntime_mac_controller_operation_result(c.request);}
 catch(e){s.halted=true;s.call_inflight=false;store("x230_full34_recovered_read_state",s);const pin=await H.save("x230-full34-"+label+"-rpc-error",JSON.stringify({error:String(e),original_request:c.request,may_not_have_observed_output:true},null,2)+"\n");return{ok:false,errorPin:pin};}
 const sdkPin=await H.save("x230-full34-"+label+"-sdk",JSON.stringify(sdk,null,2)+"\n");
 if(sdk.isError||sdk.content?.length!==1||sdk.content[0].type!=="text"){s.halted=true;s.call_inflight=false;store("x230_full34_recovered_read_state",s);await H.persist("x230-full34-"+label+"-halted",JSON.stringify({state:s,sdkPin},null,2)+"\n");return{ok:false,sdkPin};}
 const raw=sdk.content[0].text,nativePin=await H.save("x230-full34-"+label+"-native",raw),p=JSON.parse(raw),bytes=H.unb64(p.data_base64);
 const want=Math.min(8192,s.total_bytes-c.request.offset);
 if(p.operation_id!==s.active_operation_id||p.offset!==c.request.offset||p.next_offset!==c.request.offset+want||bytes.length!==want||p.total_bytes!==s.total_bytes||p.result_sha256!==s.result_sha256||p.immutable_snapshot!==true||p.eof!==(p.next_offset===s.total_bytes)){s.halted=true;s.call_inflight=false;store("x230_full34_recovered_read_state",s);await H.persist("x230-full34-"+label+"-geometry-failure",JSON.stringify({state:s,sdkPin,nativePin},null,2)+"\n");throw Error("original page geometry");}
 s.pages.push({offset:p.offset,bytes:bytes.length,request_blob:c.requestPin.blob,intent_blob:c.intentPin.blob,sdk:sdkPin,native:nativePin});
 s.next_offset=p.next_offset;s.complete=p.eof;s.call_inflight=false;
 store("x230_full34_recovered_read_state",s);store("x230_full34_page_native_"+s.label+"_"+p.offset,{raw,parsed:p});
 await H.persist("x230-full34-"+s.label+"-state-after-"+String(p.offset).padStart(6,"0"),JSON.stringify(s,null,2)+"\n");
 let next=null;
 if(!p.eof){
 const request={operation_id:s.active_operation_id,offset:s.next_offset,limit:8192},nl=s.label+"-page-"+String(s.next_offset).padStart(6,"0");
 const requestPin=await H.save("x230-full34-"+nl+"-request",JSON.stringify(request,null,2)+"\n");
 const intent={schema:"heptabao.x230-full34-original-observation-intent.v1",GO:s.GO,lane:"B",label:nl,method:"operation_result",request_blob:requestPin.blob,request_bytes:requestPin.bytes,request_sha256:requestPin.sha256,request,only_original_job_and_fixed_public_observation:true,process_start_authorized:false,prior_active_operation_id:s.active_operation_id,original_call_only:true};
 const intentPin=await H.save("x230-full34-"+nl+"-intent",JSON.stringify(intent,null,2)+"\n");
 next={request,requestPin,intentPin,submitted:false};store("x230_full34_recovered_pending_page",next);await H.persist("x230-full34-"+nl+"-pending",JSON.stringify(next,null,2)+"\n");
 }else store("x230_full34_recovered_pending_page",null);
 return{ok:true,label,offset:p.offset,next_offset:p.next_offset,total_bytes:p.total_bytes,eof:p.eof,sdkPin,nativePin,nextIntent:next?.intentPin};
}
