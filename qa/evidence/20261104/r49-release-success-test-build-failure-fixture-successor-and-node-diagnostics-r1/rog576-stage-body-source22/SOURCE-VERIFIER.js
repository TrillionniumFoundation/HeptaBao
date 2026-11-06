function verifyCombinedStageBodySource(t){
 const checks=[];function ck(name,pass){checks.push({name,pass:pass===true});if(pass!==true)throw Error(name);}
 const p=JSON.parse(t["PLAN.public.json"]),r=JSON.parse(t["REFERENCES.public.json"]),q=JSON.parse(t["request.exact.json"]),b=t["journal.before.js"],a=t["journal.after.js"],d=t["donor.body-journal.js"],e=p.expected_report;
 const eq=(raw,pin)=>{const m=gitBlobMeta(raw);return m.blob===pin.blob&&m.bytes===pin.bytes&&m.sha256===pin.sha256;};
 for(const[key,pin]of [["journal.before.js",r.before],["journal.after.js",p.journal],["donor.body-journal.js",r.donor],["donor.body-GO.public.json",r.donorGO],["request.exact.json",p.exact_request],["actual.info.native.original.json",e.infoNative]])ck("exact_pin_"+key,eq(t[key],pin));
 ck("strict_forward",snapshotApply(b,t["journal.forward.diff"])===a&&snapshotApply(a,t["journal.forward.diff"],true)===b);
 ck("strict_reverse",snapshotApply(a,t["journal.reverse.diff"])===b&&snapshotApply(b,t["journal.reverse.diff"],true)===a);
 ck("strict_donor",snapshotApply(d,t["donor.literal-only.diff"])===a&&snapshotApply(a,t["donor.literal-only.diff"],true)===d);
 ck("six_current_three_donor_hunks",(t["journal.forward.diff"].match(/^@@ /gm)||[]).length===6&&(t["donor.literal-only.diff"].match(/^@@ /gm)||[]).length===3);
 let rebuilt=d;const swaps=JSON.parse(t["LITERAL-BINDINGS.public.json"]);ck("ten_groups_eleven_literals",swaps.length===10&&swaps.reduce((n,x)=>n+x.count,0)===11);
 for(const x of swaps){ck("exact_literal_count_"+x.name,rebuilt.split(x.before).length-1===x.count);rebuilt=rebuilt.split(x.before).join(x.after);}
 ck("donor_logic_unchanged",rebuilt===a);
 const functions=src=>[...src.matchAll(/^(?:async )?function ([A-Za-z0-9_]+)/gm)],fn=(src,n)=>{const row=functions(src).find(x=>x[1]===n);if(!row)throw Error("function_absent");const end=src.indexOf("\n}\n",row.index);if(end<0)throw Error("function_end_absent");return src.slice(row.index,end+3);};
 ck("one_new_body_authorizer",functions(a).length===functions(b).length+1&&functions(a).some(x=>x[1]==="gfAuthorizeStageResultBodyOnly"));
 for(const n of ["gfAuthorizeStageResultInfoOnly","gfNeed","gfMetaEquals","gfState","gfSave","gfIntegerText","gfInitializeOnlyAfterRootGO","gfAcceptArchivedSDK","gfReconcileSameGitArchiveReadOnly"])ck("unchanged_function_"+n,fn(b,n)===fn(a,n));
 const s=JSON.parse(t["actual.boundary.projection.public.json"]),info=parseLosslessIntegers(t["actual.info.native.original.json"]),sdk=JSON.parse(t["actual.info.status.sdk.json"]),status=parseLosslessIntegers(sdk.content[0].text);
 ck("closed_existing_context",s.projectionOnly===true&&s.job===p.original_job&&s.pending===null&&s.activeObserver===null&&!s.paused&&!s.nativeCallInFlight&&s.startCalled===true&&s.stageResultInfoStarted===true&&s.stageResultBodyStarted===null&&s.stageResultBodyGO===null&&p.initialize_allowed===false);
 ck("closed_original_metadata",sdk.isError!==true&&status.operation_id===e.infoOperation&&status.tool_name==="file_info"&&status.async_state==="completed"&&status.result_state==="stored_observed"&&status.owned_future_active===false&&status.payload_available===true&&s.completedObservers.some(o=>o.id===e.infoOperation&&o.completedInactive===true&&o.nativeText.blob===e.infoNative.blob));
 ck("actual_metadata_identity",info.path===e.path&&info.size===e.bytes&&info.sha256===e.sha256&&info.version===e.version&&s.stageResultInfo.originalOperation===e.infoOperation);
 ck("lossless_metadata_version",e.version==="66306:31358204:29748:1794000540708114035:1794000540708114035"&&JSON.stringify(s.stageResultInfo.full9Strings)===JSON.stringify(["66306","31358204","1000","1000","33152","1","29748","1794000540708114035","1794000540708114035"]));
 ck("request_closed_shape",Object.keys(q).sort().join(",")==="idempotency_key,operation"&&q.operation.tool==="binary_read"&&Object.keys(q.operation.arguments).sort().join(",")==="expected_version,host,limit,offset,path");
 ck("fixed_request",q.operation.arguments.host==="rog"&&q.operation.arguments.path===e.path&&q.operation.arguments.offset===0&&q.operation.arguments.limit===29748&&q.operation.arguments.expected_version===e.version&&q.idempotency_key==="heptabao-combined-5767739c-rog-source-observe-r1-report-body");
 ck("original_caps",e.bytes===29748&&e.bytes<=65536&&p.maximum_binary_read_starts===1&&p.limits.immutable_page_bytes===8192&&p.limits.original_payload_bytes===1048576&&a.includes("b.length<=8192")&&a.includes("v.total_bytes<=1048576"));
 ck("separate_exact_body_GO",a.includes('g.scope==="stage_result_binary_read_only"')&&a.includes("g.info_operation===need.infoOperation")&&a.includes("g.maximum_binary_read_starts===1")&&a.includes("goPin.blob!==s.stageResultInfoGO.pin.blob"));
 ck("once_marker_before_native",a.includes('if(c.kind==="operation_start" && q.operation.tool==="binary_read")s.stageResultBodyStarted=true;')&&a.indexOf("s.stageResultBodyStarted=true;")<a.indexOf('sdk=await tools.mcp__codex_apps__heptaruntime_mac_controller_operation_start(q)'));
 ck("full_extent_SHA",a.includes("v.offset===0 && v.next_offset===need.bytes && v.eof===true")&&a.includes("v.chunk_sha256===need.sha256")&&a.includes("bodyBytes.length===need.bytes && bodyPin.bytes===need.bytes")&&a.includes("bodyPin.sha256===need.sha256"));
 ck("whole_decode_before_semantics",a.includes("bodyBytes=unb64(v.data_base64),bodyRaw=utf8Text(bodyBytes)")&&a.includes("originalPayload:pin,semanticQualification:false")&&!a.includes("JSON.parse(bodyRaw)"));
 ck("donor_checker_history_not_current_candidate",JSON.parse(t["checker.first-failure.public.json"]).originalFailureReproduced===true&&JSON.parse(t["checker.first-failure.public.json"]).originalCandidate.blob===r.donor.blob);
 ck("no_execution_or_body_claim",p.actual_body===null&&p.body_started===false&&p.semantic_report_qualification===false&&r.sourceTaskNativeCalls===0&&p.source_formatted===false);
 return {schema:"heptabao.combined5767739.stage-report-body-source-verification.r1",ok:true,checks:checks.length,results:checks,pureV8:true,candidateFunctionsInvoked:false,NativeCalls:0,RustOrPythonRun:false,semanticReportQualification:false};
}
