function verifyCurrentNULInfos(data,H){
 const {lossless,u,bs,s256,unb64}=H,r=data.raw,c=[],rows=[],state=lossless(r["STATE.public.json"]),eq=(a,b)=>JSON.stringify(a)===JSON.stringify(b),hash=t=>s256(bs(u(t)));
 function ok(n,v){if(!v)throw Error(n);c.push(n);}
 function nat(t,n){const v=lossless(t);ok(n+":SDK-not-error",v.isError!==true);const a=v.content?.filter(x=>x.type==="text");ok(n+":single-native-text",a?.length===1);return{text:a[0].text,v:lossless(a[0].text)};}
 ok("original-job-and-two-only-infos",state.job_id==="1a1acd0d62d-fc05-571a"&&state.files.length===2&&state.original_observers.length===2&&state.original_plan_tree==="bc3ac1786389aa597cdd980d2fd5bff5b7ef66e8");
 for(let i=0;i<2;i++){
 const name="inventory"+i+"_info",p="observers/"+name,e=data.expected[i],fixed=data.plan.large_files[i],req=lossless(r[p+"/start/request.json"]),intent=lossless(r[p+"/intent/read-intent.public.json"]);
 ok(name+":exact-original-fixed-intent",eq(req,intent.request)&&r[p+"/start/request.json"]===r[p+"/intent/exact-operation-start-request.public.json"]&&intent.root_GO.blob==="f1fcb91c33a38ba8074281c300f8f3c7b8f1534e"&&intent.one_native_future===true&&intent.product_replay===false);
 ok(name+":only-original-file-info",req.operation.tool==="file_info"&&req.operation.arguments.host==="desktop"&&req.operation.arguments.path===fixed.path&&fixed.label===e.label);
 const ack=nat(r[p+"/start/original-sdk.json"],name+":ACK"),status=nat(r[p+"/status-0/original-sdk.json"],name+":status"),sq=lossless(r[p+"/status-0/request.json"]),id=ack.v.operation_id;
 ok(name+":one-original-ID",id===state.original_observers[i].operation_id&&ack.v.reused===false&&ack.v.tool_name==="file_info"&&ack.v.idempotency_binding_retained===true);
 ok(name+":same-ID-closed-status",sq.operation_id===id&&status.v.operation_id===id&&status.v.async_state==="completed"&&status.v.result_state==="stored_observed"&&status.v.owned_future_active===false&&status.v.payload_available===true);
 const page=nat(r[p+"/page-0/original-sdk.json"],name+":page"),pq=lossless(r[p+"/page-0/request.json"]),payload=r[p+"/original-payload.json"],pb=u(payload);
 ok(name+":exact-single-immutable-page",pq.operation_id===id&&pq.offset===0&&pq.limit===8192&&page.v.operation_id===id&&page.v.offset===0&&page.v.next_offset===pb.length&&page.v.total_bytes===pb.length&&page.v.eof===true&&page.v.immutable_snapshot===true&&page.v.payload_kind==="native_result"&&page.v.result_sha256===hash(payload)&&bs(unb64(page.v.data_base64))===bs(pb));
 const actual=nat(payload,name+":payload"),info=actual.v;
 ok(name+":whole-original-native-info",actual.text===r["actual/"+name+".public.json"]);
 ok(name+":measured-whole-hash-size-path-match",info.path===fixed.path&&info.size===e.bytes&&info.size===fixed.bytes&&info.sha256===e.sha256&&info.sha256===fixed.sha256&&info.mode===384&&info.metadata.mode===384&&info.metadata.uid===1000&&info.metadata.gid===1000&&info.metadata.link_count===1);
 const v=info.version.split(":");
 ok(name+":exact-version-and-full9",v.length===5&&v.every(x=>/^[0-9]+$/.test(x))&&v[2]===String(e.bytes)&&info.version===data.versions[i]&&eq([v[0],v[1],"1000","1000","33152","1",v[2],v[3],v[4]],state.files[i].full9_decimal));
 rows.push({label:e.label,path:info.path,bytes:info.size,sha256:info.sha256,version:info.version,full9_decimal:state.files[i].full9_decimal,current_info_operation:id,current_info_blob:data.actualMeta[i].blob,reconstructed_content_blob:e.blob,content_bytes_from:"canonical Git tree reconstruction; current native file_info independently measured the same whole SHA256",current_host_body_RPC_count:0});
 }
 ok("no-large-native-body-submissions-and-old-unknown-preserved",state.current_host_body_RPC_count===0&&state.original_planned_14_body_RPCs_submitted===0&&state.original_first_tail_lost_ACK_future_unknown===true&&state.root_reuse_GO===false&&state.new_product_or_LAN===false);
 return{schema:"heptabao.root-current-two-NUL-independent-info-and-content-identity.r31.v1",status:"PASS_CURRENT_WHOLE_HASH_AND_RECONSTRUCTED_CONTENT_IDENTITY",checks_passed:c.length,checks:c,metadata_packet:"415f01281d989ab35c1108c888b15afcff70db29",canonical_reconstruction_packet:"30707c64ebc10009785c51283bbf91d65463c846",canonical_tree:"eba5e650bd080b8ad41ea52a2bc68867f541d255",root_reconstruction_review:data.reconstructionReview,files:rows,original_info_operations_closed:2,original_immutable_pages:2,total_content_bytes:889176,original_native_large_body_requests_submitted:0,full_source_import_qualified:false,remaining63_original_files_requirement_unchanged:true,root_Runtime_calls:0};
}