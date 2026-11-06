function verifyInfoActual(files){
 const checks=[];function ck(ok,code){checks.push({code,pass:!!ok});if(!ok)throw Error(code);}
 const eq=(a,b)=>JSON.stringify(a)===JSON.stringify(b),rows=JSON.parse(files["CALL-INDEX.public.json"]),s=JSON.parse(files["STATE.public.json"]),info=JSON.parse(files["ACTUAL-INFO.public.json"]),o=s.infoObserver;
 ck(rows.length===3&&rows.map(x=>x.kind).join(",")==="operation_start,operation_status,operation_result","three_original_INFO_calls");
 const v=[];
 for(const row of rows){const prefix=row.key+"--",sdkRaw=files[prefix+"sdk.original.json"],sdk=JSON.parse(sdkRaw);
 ck(eq(gitBlobMeta(files[prefix+"request.json"]),row.request),row.key+":request_pin");
 ck(eq(gitBlobMeta(sdkRaw),row.sdk)&&row.sdkWhole===true,row.key+":sdk_whole_before_parse");
 ck(sdk.isError!==true&&sdk.content.length===1&&sdk.content[0].type==="text",row.key+":original_sdk_success");
 ck(sdk.content[0].text===files[prefix+"native.original.json"]&&eq(gitBlobMeta(sdk.content[0].text),row.native),row.key+":native_byteexact");
 ck(row.phase==="accepted"&&row.called===true,row.key+":accepted_once");
 const intent=JSON.parse(files[prefix+"intent.json"]),armed=JSON.parse(files[prefix+"armed.json"]);
 ck(intent.maximumNativeCalls===1&&intent.nativeNotYetCalled===true&&eq(intent.request,row.request)&&armed.mayHaveDispatchedAfterThisCheckpoint===true,row.key+":pre_dispatch_records");
 v.push({q:JSON.parse(files[prefix+"request.json"]),n:parseLosslessIntegers(sdk.content[0].text)});
 }
 ck(v[0].q.operation.tool==="file_info"&&v[0].q.operation.arguments.path===info.path&&v[0].q.operation.arguments.host==="rog"&&v[0].n.operation_id===o.id&&v[0].n.reused===false,"one_exact_fixed_INFO");
 ck(v[1].q.operation_id===o.id&&v[1].n.operation_id===o.id&&v[1].n.async_state==="completed"&&!v[1].n.owned_future_active&&v[1].n.result_state==="stored_observed"&&v[1].n.payload_available,"same_original_closed_future");
 const pg=v[2];ck(pg.q.operation_id===o.id&&pg.q.offset===0&&pg.q.limit===8192&&pg.n.operation_id===o.id&&pg.n.offset===0&&pg.n.eof&&pg.n.immutable_snapshot,"one_original_immutable_page");
 const raw=utf8Text(unb64(pg.n.data_base64));ck(raw===files["observer.payload.original.json"]&&eq(gitBlobMeta(raw),o.payload)&&pg.n.total_bytes===o.payload.bytes&&pg.n.next_offset===o.payload.bytes&&pg.n.result_sha256===o.payload.sha256,"whole_payload_exact");
 const payload=parseLosslessIntegers(raw);ck(payload.resultType==="complete"&&payload.isError===false&&payload.content.length===1&&payload.content[0].text===files["observer.native.original.json"],"original_native_payload_success");
 ck(eq(gitBlobMeta(payload.content[0].text),o.nativeText)&&eq(o.nativeText,info.nativeText),"actual_native_info_pin");
 const n=parseLosslessIntegers(payload.content[0].text),parts=n.version.split(":");
 ck(n.path===info.path&&n.size===28125&&n.sha256===info.sha256&&n.version===info.version,"actual_content_identity");
 ck(n.mode===384&&n.metadata.mode===384&&n.metadata.uid===1000&&n.metadata.gid===1000&&n.metadata.link_count===1&&n.metadata.metadata_platform==="linux","actual_permission_owner_links_platform");
 const full9=[parts[0],parts[1],"1000","1000","33152","1",String(n.size),parts[3],parts[4]];
 ck(eq(full9,info.full9Strings)&&parts[2]===String(n.size)&&parts.every(x=>/^[0-9]+$/.test(x)),"lossless_full9_version");
 ck(o.completedInactive===true&&o.pages===1&&s.totalCalls===10&&s.originalStageCalls===7,"closure_original_chain_counts");
 ck(s.pending===null&&s.activeObserver===null&&!s.nativeCallInFlight&&!s.paused&&!s.bodyReadSubmitted&&!s.buildSubmitted,"closed_NO_BODY_NO_CARGO");
 return {schema:"heptabao.025b-stage-INFO-actual-verification.r1",status:"PASS",checks:checks.length,results:checks,Runtime_calls:0,product_tests:0,scope:"original3calls/1page and actual fixed metadata only"};
}
