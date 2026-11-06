function verify576CanonicalInfoActual(files){
 const checks=[];function check(name,v){checks.push({name,pass:v===true});if(v!==true)throw Error(name);}
 const pinEq=(raw,p)=>{const a=gitBlobMeta(raw);return a.blob===p.blob&&a.bytes===p.bytes&&a.sha256===p.sha256;};
 const calls=JSON.parse(files["CALL-INDEX.public.json"]),state=JSON.parse(files["STATE.closed.original.json"]),actual=JSON.parse(files["ACTUAL.public.json"]),go=JSON.parse(files["GO.original.json"]),release=JSON.parse(files["RELEASE.public.json"]);
 check("exact_GO",pinEq(files["GO.original.json"],actual.GO)&&actual.GO.blob==="1899d302ebd3e63f20a9e496bd6b9518d2bb6a07");
 check("three_original_calls",calls.length===3&&calls.map(x=>x.kind).join(",")==="operation_start,operation_status,operation_result");
 const native=[];
 for(const c of calls){
  check("call_"+c.index+"_whole_request",pinEq(files[c.files.request],c.request));
  check("call_"+c.index+"_whole_SDK",pinEq(files[c.files.sdk],c.sdk));
  const sdk=JSON.parse(files[c.files.sdk]);
  check("call_"+c.index+"_native_text",sdk.isError!==true&&sdk.content.length===1&&sdk.content[0].type==="text"&&sdk.content[0].text===files[c.files.native]&&pinEq(files[c.files.native],c.native));
  const intent=JSON.parse(files[c.files.intent]),armed=JSON.parse(files[c.files.armed]);
  check("call_"+c.index+"_same_GO_single_arm",JSON.stringify(intent.rootGo)===JSON.stringify(actual.GO)&&intent.maximumNativeCalls===1&&armed.maximumNativeCalls===1&&c.called===true&&c.phase==="accepted"&&c.armed.whole===true);
  for(const key of ["request","intent","armed"]){const raw=files[c.files[key]],entry=c.armed.entries.find(x=>x.path===key+".json");check("call_"+c.index+"_"+key+"_arm_leaf",entry!==undefined&&pinEq(raw,entry));}
  native.push(parseLosslessIntegers(files[c.files.native]));
 }
 const q=JSON.parse(files[calls[0].files.request]),id=actual.original_operation;
 check("exact_original_admission_request",JSON.stringify(q)===JSON.stringify(go.exact_operation)&&pinEq(files[calls[0].files.request],go.exact_request));
 check("original_admission_ID",native[0].operation_id===id&&native[0].tool_name==="file_info"&&native[0].reused===false&&native[0].automatic_retry===false);
 check("original_status_completed_inactive",native[1].operation_id===id&&native[1].async_state==="completed"&&native[1].result_state==="stored_observed"&&native[1].owned_future_active===false&&native[1].payload_available===true);
 const page=native[2],body=utf8Text(unb64(page.data_base64));
 check("one_original_page_whole_EOF",page.operation_id===id&&page.offset===0&&page.next_offset===589&&page.total_bytes===589&&page.eof===true&&page.immutable_snapshot===true&&body===files["payload.original.json"]&&gitBlobMeta(body).sha256===page.result_sha256&&pinEq(body,actual.payload));
 const envelope=parseLosslessIntegers(body),m=parseLosslessIntegers(files["metadata.native.original.json"]);
 check("original_payload_native_complete",envelope.resultType==="complete"&&envelope.isError===false&&envelope.content[0].text===files["metadata.native.original.json"]&&pinEq(files["metadata.native.original.json"],actual.native));
 check("actual_metadata_identity",m.path===go.expected.path&&m.size===5766&&m.sha256===go.expected.sha256&&m.mode===384&&m.metadata.mode===384&&m.metadata.metadata_platform==="linux"&&m.metadata.uid===1000&&m.metadata.gid===1000&&m.metadata.link_count===1);
 const v=m.version.split(":"),f=[v[0],v[1],"1000","1000",String(32768|m.mode),"1",String(m.size),v[3],v[4]];
 check("lossless_full9_exact_stage",JSON.stringify(f)===JSON.stringify(go.expected.full9)&&JSON.stringify(f)===JSON.stringify(actual.info.derivedFull9)&&actual.info.version===m.version);
 check("closed_original_context",state.pending===null&&state.activeObserver===null&&state.nativeCallInFlight===false&&state.paused===false&&state.completedObservers.length===1&&state.completedObservers[0].id===id&&state.completedObservers[0].completedInactive===true&&pinEq(files["STATE.closed.original.json"],actual.state));
 check("metadata_only_lane_released",release.Native_calls_inflight===0&&release.owned_futures_active===0&&release.pending===null&&release.activeObserver===null&&release.only_metadata_observed===true&&release.BODY_GO===null&&actual.body_observed===false);
 return{schema:"heptabao.canonical576-info-original-chain-verification.v1",pass:true,check_count:checks.length,checks,source_executed:false,new_Native_calls:0};
}
