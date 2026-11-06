function verifyFreshBuildLogBodiesSource(I) {
 const checks=[];function need(ok,name){checks.push({name,ok:!!ok});if(!ok)throw Error(name);}
 function exact(a,b){return JSON.stringify(a)===JSON.stringify(b);}
 need(exact(gitBlobMeta(I.before),I.beforePin),"current_info_journal_exact");
 need(exact(gitBlobMeta(I.after),I.afterPin),"body_ranges_journal_exact");
 need(snapshotApply(I.before,I.forward)===I.after,"strict_eight_hunk_forward");
 need(snapshotApply(I.after,I.reverse)===I.before,"strict_eight_hunk_reverse");
 need((I.forward.match(/^@@/gm)||[]).length===8&&I.edits.length===8,"eight_bounded_edits");
 let rebuilt=I.before;for(const e of I.edits){need(rebuilt.split(e.old).length-1===1,"unique_edit_"+checks.length);rebuilt=rebuilt.replace(e.old,e.next);}
 need(rebuilt===I.after,"whole_reconstruction");
 need(I.ranges.length===7&&I.ranges.reduce((n,x)=>n+x.limit,0)===404821,"seven_ranges_total404821");
 for(const f of I.infos){
  const native=parseLosslessIntegers(I.infoNativeRaws[f.stream]);
  need(exact(gitBlobMeta(I.infoNativeRaws[f.stream]),f.nativeText),"actual_info_native_"+f.stream);
  need(native.path===f.path&&native.size===f.size&&native.sha256===f.sha256&&native.version===f.version,"actual_file_identity_"+f.stream);
  const chunks=I.ranges.filter(x=>x.stream===f.stream);let offset=0;
  for(const n of chunks){
   const q=JSON.parse(n.requestRaw),a=q.operation.arguments;
   need(exact(gitBlobMeta(n.requestRaw),n.request)&&q.idempotency_key===n.idempotencyKey,"exact_request_"+n.index);
   need(q.operation.tool==="binary_read"&&a.host==="rog"&&a.path===f.path&&a.expected_version===f.version,"same_file_version_"+n.index);
   need(a.offset===offset&&a.limit===n.limit&&n.limit===Math.min(65536,f.size-offset)&&n.eof===(offset+n.limit===f.size),"exact_range_"+n.index);
   offset+=n.limit;
  }
  need(offset===f.size,"complete_file_geometry_"+f.stream);
 }
 need(I.infos[0].size===20639&&I.infos[1].size===384182,"actual_2_sizes");
 need(I.state.buildLogInfoNext===2&&I.state.buildLogInfoCalled===2&&!I.state.pending&&!I.state.activeObserver&&!I.state.nativeCallInFlight&&!I.state.paused,"closed_original_two_infos");
 need(Object.keys(I.state.calls).length===37&&I.state.completedObservers.length===10,"old37calls10observers_preserved");
 need(I.state.outerFailure?.message==="same_closed_original_operation_next_page","original_pure_prepare_failure_preserved");
 need(I.toolContract.includes("at most 16384 bytes")&&I.toolContract.includes("at most 1 MiB"),"current_original_tool_page_and_payload_contract");
 need(I.after.includes('v.total_bytes<=1048576')&&I.after.includes('<=128')&&I.after.includes('<=8'),"original_payload_status_page_count_caps_unchanged");
 need(I.after.includes('if(s.buildLogsBodyGO?.whole===true)s.buildLogBodyCalled++;'),"new_once_marker_before_dispatch");
 need(I.after.includes('sha256Latin1(byteString(joined))===n.sha256')&&I.after.indexOf('sha256Latin1(byteString(joined))===n.sha256')<I.after.indexOf('const bodyRaw=utf8Text(joined)'),"whole_byte_SHA_before_UTF8");
 need(I.after.includes('bodyArchive=await archiveFlatPublicTextsOnce')&&I.after.indexOf('bodyArchive=await archiveFlatPublicTextsOnce')<I.after.indexOf('s.buildLogBodyNext++'),"whole_file_archive_before_next_range_advance");
 const zeroTools=new Proxy({}, {get(){throw Error("no tools in pure verifier");}});
 function ctx(change){
  const s=JSON.parse(JSON.stringify(I.state));if(change)change(s);
  const map=new Map([[I.slot,s]]);for(const f of I.infos)map.set(I.slot+":closed_native:"+f.originalOperation,I.infoNativeRaws[f.stream]);
  const api=new Function("load","store","tools",I.pure+"\n"+I.archive+"\n"+I.after+";return {auth:gfAuthorizeBuildLogBodiesOnly,valid:gfValidateRequest,width:gfBuildLogPageBytes};")(k=>map.get(k),(k,v)=>map.set(k,v),zeroTools);
  return{s,api};
 }
 const g={authorization:"GO",scope:"build_logs_binary_read_ranges_only",original_job:I.state.job,maximum_binary_read_starts:7,new_body_page_bytes:16384,maximum_body_bytes:404821,exact_requests:I.ranges.map(x=>x.request)};
 function auth(c,obj=g){const raw=JSON.stringify(obj,null,2)+"\n";c.api.auth({goRaw:raw,goPin:gitBlobMeta(raw),goWholeReadback:true});}
 function valid(c,index){const n=I.ranges[index];c.api.valid(c.s,"operation_start",JSON.parse(n.requestRaw),n.requestRaw);}
 function reject(name,work){let denied=false;try{work();}catch(e){denied=true;}need(denied,name);}
 const c=ctx();auth(c);
 for(let i=0;i<7;i++){c.s.buildLogBodyNext=i;c.s.buildLogBodyCalled=i;valid(c,i);need(c.s.buildLogBodyCalled===i,"private_range_"+i+"_accepted_without_dispatch");}
 c.s.buildLogBodyNext=7;c.s.buildLogBodyCalled=7;reject("reject_eighth_range",()=>valid(c,6));
 const once=ctx();auth(once);once.s.buildLogBodyCalled=1;reject("reject_same_range_after_called",()=>valid(once,0));
 reject("reject_duplicate_authorization",()=>auth(c));
 for(const [name,change]of [["paused",s=>s.paused=true],["pending",s=>s.pending="x"],["active",s=>s.activeObserver={}],["inflight",s=>s.nativeCallInFlight=true],["wrongJob",s=>s.job="other"],["incompleteInfos",s=>s.buildLogInfoNext=1],["versionDrift",s=>s.buildLogInfos[1].version+="0"]])
  reject("reject_"+name,()=>auth(ctx(change)));
 reject("reject_wrong_scope",()=>auth(ctx(),{...g,scope:"build_logs_file_info_only"}));
 reject("reject_page_cap_change",()=>auth(ctx(),{...g,new_body_page_bytes:32768}));
 reject("reject_total_change",()=>auth(ctx(),{...g,maximum_body_bytes:404822}));
 const page=ctx();auth(page);const n=I.ranges[0];
 page.s.activeObserver={id:"1".repeat(64),request:JSON.parse(n.requestRaw),tool:"binary_read",futureClosed:true,nextPageOffset:0,eof:false};
 need(page.api.width(page.s)===16384,"new_log_body_16K_only");
 const q={operation_id:"1".repeat(64),offset:0,limit:16384};page.api.valid(page.s,"operation_result",q,JSON.stringify(q,null,2)+"\n");
 reject("reject_new_page_32K",()=>page.api.valid(page.s,"operation_result",{...q,limit:32768},"{}"));
 page.s.activeObserver.tool="file_info";need(page.api.width(page.s)===8192,"old_info_pages_8K_unchanged");
 reject("reject_metadata_page_widening",()=>page.api.valid(page.s,"operation_result",q,"{}"));
 page.s.activeObserver.tool="binary_read";page.s.activeObserver.request.operation.arguments.path="old";need(page.api.width(page.s)===8192,"unmatched_old_binary_page_8K");
 for(const [name,change]of [["path",q=>q.operation.arguments.path+="x"],["version",q=>q.operation.arguments.expected_version+="0"],["offset",q=>q.operation.arguments.offset++],["limit",q=>q.operation.arguments.limit++],["key",q=>q.idempotency_key+="x"]]){
  const d=ctx();auth(d);const wrong=JSON.parse(n.requestRaw);change(wrong);reject("reject_mutated_"+name,()=>d.api.valid(d.s,"operation_start",wrong,JSON.stringify(wrong,null,2)+"\n"));
 }
 // Exercise the actual source join/hash/decode block with a multibyte boundary.
 const begin=I.after.indexOf("    let joined=[];"),end=I.after.indexOf("    store(GF_SLOT+\":build_log_body_original:",begin);
 const block=I.after.slice(begin,end);
 const raw="x".repeat(65535)+"€"+"end",bytes=utf8Bytes(raw),parts=[{base64:encodeBase64Bytes(bytes.slice(0,65536))},{base64:encodeBase64Bytes(bytes.slice(65536))}],expected={bytes:bytes.length,sha256:gitBlobMeta(raw).sha256};
 const joined=new Function("parts","n",I.pure+"\nfunction gfNeed(x,n){if(!x)throw Error(n);}\n"+block+"\nreturn bodyRaw;")(parts,expected);
 need(joined===raw,"actual_join_block_preserves_split_multibyte_UTF8");
 reject("reject_whole_join_SHA_mismatch",()=>new Function("parts","n",I.pure+"\nfunction gfNeed(x,n){if(!x)throw Error(n);}\n"+block)(parts,{...expected,sha256:"0".repeat(64)}));
 return {schema:"heptabao.fresh-build-log-body-seven-range-source-checks.r1",status:"passed",checkCount:checks.length,checks,runtimeCalls:0,sourceOnly:true,privateClonedStoreOnly:true};
}