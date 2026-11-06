
function reviewCLIBody13(){
 const p=load("r34_packet_CLI-body13-source"),ip=load("r34_packet_CLI-fileinfo-actual"),r=p.raw,ir=ip.raw,plan=JSON.parse(r["PLAN.public.json"]),rel=JSON.parse(ir["OWNER-RELEASE.public.json"]),before=r["before.info-only.js"],after=r["candidate.body-ranges.js"],checks=[];
 const ck=(name,v)=>{checks.push({name,passed:!!v});if(!v)throw Error(name)};
 const eq=(text,pin)=>{const m=gitBlobMeta(text);return m.blob===pin.blob&&m.bytes===pin.bytes&&m.sha256===pin.sha256};
 ck("whole_source28_and_info20",p.audit.whole&&p.audit.files===28&&ip.audit.whole&&ip.audit.files===20);
 const forward=strictApply(before,r["candidate.diff"]),back=strictApply(after,r["candidate.diff"],true);
 ck("eight_exact_strict_hunks",forward.hunks===8&&back.hunks===8&&forward.text===after&&back.text===before&&eq(before,plan.before)&&eq(after,plan.after)&&eq(r["candidate.diff"],plan.diff));
 ck("original_reviewed_info_source",before===load("r34_packet_CLI-fileinfo-source").raw["native_gitfirst.info-only.js"]||gitBlobMeta(before).blob==="f0819073ffb9ee7e1a39135a3b6f41782e4aafdb");
 ck("unchanged_pure_archive",gitBlobMeta(r["archive.unchanged.js"]).blob==="b093fdbf655511f7db94be2d95555606141bbb42"&&gitBlobMeta(r["pure.unchanged.js"]).blob==="b6890e8b7217c546bec073dcb04988fc37652721");
 const infoOp=plan.metadataActual.infoOperation,ns=[];
 for(const [suffix,kind]of [["admit","operation_start"],["status0","operation_status"],["page0","operation_result"]]){
  const k="cli-phaseb-r4-result-info0-"+suffix,qraw=ir[k+".request.json"],q=JSON.parse(qraw),intent=JSON.parse(ir[k+".intent.json"]),arm=JSON.parse(ir[k+".armed.json"]),sdk=JSON.parse(ir[k+".original.sdk.json"]),nr=ir[k+".original.native.json"],n=JSON.parse(nr),row=rel.calls.find(x=>x.callKey===k);
  ck("actual_info_"+suffix+"_pins",row.phase==="accepted"&&eq(qraw,row.request)&&eq(ir[k+".original.sdk.json"],row.SDK)&&eq(nr,row.native)&&eq(qraw,intent.request)&&eq(qraw,arm.request));
  ck("actual_info_"+suffix+"_arm_and_original",intent.kind===kind&&intent.maximumNativeCalls===1&&arm.mayHaveDispatchedAfterThisCheckpoint===true&&intent.rootGo.blob===load("r34_CLI_fileinfo_GO").blob&&arm.rootGo.blob===intent.rootGo.blob&&sdk.isError===false&&sdk.content.length===1&&sdk.content[0].type==="text"&&sdk.content[0].text===nr&&n.operation_id===infoOp&&n.automatic_retry===false);ns.push({q,n});
 }
 ck("one_file_info_original_admission",ns[0].n.reused===false&&ns[0].n.tool_name==="file_info"&&eq(ir["cli-phaseb-r4-result-info0-admit.request.json"],load("r34_CLI_fileinfo_GO").value.exact_request));
 ck("info_completed_inactive",ns[1].n.async_state==="completed"&&ns[1].n.owned_future_active===false&&ns[1].n.result_state==="stored_observed"&&ns[1].n.payload_available===true&&rel.operation.completedInactive===true&&rel.currentNativeFuture===0&&rel.nativeCallInFlight===false&&rel.activeObserver===null&&rel.pendingCall===null);
 const pg=ns[2].n,bytes=unb64(pg.data_base64),payload=utf8Text(bytes),pl=JSON.parse(payload);
 ck("info_original610_page_SHA_EOF",ns[2].q.limit===8192&&ns[2].q.offset===0&&pg.offset===0&&pg.next_offset===610&&pg.total_bytes===610&&pg.eof&&pg.immutable_snapshot&&bytes.length===610&&gitBlobMeta(payload).sha256===pg.result_sha256&&eq(payload,rel.operation.payload)&&payload===ir["PAYLOAD.original.json"]);
 ck("original_metadata_payload_exact",pl.resultType==="complete"&&pl.isError===false&&pl.content.length===1&&pl.content[0].text===ir["FILE-INFO.original.json"]&&eq(pl.content[0].text,plan.metadataActual.infoNative)&&ir["FILE-INFO.original.json"]===r["actual-file-info.original.json"]);
 const md=JSON.parse(ir["FILE-INFO.original.json"]),need=plan.metadataActual;
 ck("fixed_actual_metadata_owner_and_version",md.path===need.path&&md.size===848065&&md.sha256===need.sha256&&md.version===need.version&&md.mode===384&&md.metadata.mode===384&&md.metadata.uid===1000&&md.metadata.gid===1000&&md.metadata.link_count===1&&md.metadata.metadata_platform==="linux"&&JSON.stringify(rel.metadata.full9Strings)===JSON.stringify(need.full9Strings));
 ck("failed_exit1_not_requalified",rel.originalKnownExit===1&&rel.knownCompatibilityFailureUnchanged&&rel.independentCaseQualification===false&&plan.originalExit===1&&plan.originalJob==="1a1aee01612-fc05-639b"&&rel.metadata.binaryReadAuthorized===false);
 let end=0;const unique=new Set();
 for(let j=0;j<13;j++){
  const raw=r["request-body"+String(j).padStart(2,"0")+".json"],q=JSON.parse(raw),a=q.operation.arguments,n=plan.exactRequests[j];
  ck("exact_bounded_range_"+j,eq(raw,n)&&q.idempotency_key===n.key&&q.operation.tool==="binary_read"&&a.host==="desktop"&&a.path===md.path&&a.offset===end&&a.offset===j*65536&&a.limit===(j===12?61633:65536)&&a.expected_version===md.version&&Object.keys(a).sort().join(",")==="expected_version,host,limit,offset,path");
  end+=a.limit;unique.add(q.idempotency_key);
 }
 ck("thirteen_ranges_whole_geometry",plan.exactRequests.length===13&&unique.size===13&&end===848065&&end===md.size&&md.size<=4194304);
 const def=(src,name)=>{const start=src.search(new RegExp("(?:async )?function "+name+"\\("));if(start<0)return null;const e=src.indexOf("\n}",start);return e<0?null:src.slice(start,e+2)};
 for(const name of ["gfAuthorizeCliResultInfoOnly","gfInitializeOnlyAfterRootGO","gfIntegerText","gfMetaEquals","gfNeed","gfReconcileSameGitArchiveReadOnly","gfSave","gfState"])ck("old_definition_unchanged_"+name,def(before,name)!==null&&def(before,name)===def(after,name));
 ck("separate_exact_GO_scope_and_closed_metadata",after.includes('g.scope==="cli_result_binary_read_ranges_only"')&&after.includes("g.maximum_binary_read_starts===13")&&after.includes("g.immutable_body_page_bytes===GF_CLI_BODY_PAGE_BYTES")&&after.includes("prior?.completedInactive===true")&&after.includes("g.exact_requests.length===GF_CLI_BODY_RANGES.length"));
 ck("single_next_range_no_replay",after.includes("s.cliResultBodyStarted===index && gfMetaEquals(raw,range.request)")&&after.includes("s.activeObserver===null")&&after.includes("s.cliResultBodyStarted++")&&after.indexOf("s.cliResultBodyStarted++")<after.indexOf('sdk=await tools.mcp__codex_apps__heptaruntime_mac_controller_process_start(q)'));
 ck("only_new_binary_pages_16384",after.includes('q.limit===(s.activeObserver.tool==="binary_read"?GF_CLI_BODY_PAGE_BYTES:8192)')&&after.includes('b.length<=(a.tool==="binary_read"?GF_CLI_BODY_PAGE_BYTES:8192)')&&after.includes("const GF_CLI_BODY_PAGE_BYTES = 16384;")&&after.includes("v.total_bytes<=1048576"));
 const contract=JSON.parse(r["exposed-tool-contract.public.json"]);
 ck("current_actual_tool_contract",contract.tools.every(x=>ALL_TOOLS.some(t=>t.name===x.name&&t.description===x.description))&&contract.tools.find(x=>x.name.endsWith("operation_result")).description.includes("at most 16384"));
 ck("each_chunk_SHA_before_join",after.includes("sha256Latin1(byteString(bodyBytes))===v.chunk_sha256")&&after.includes("bodyBytes.length===range.limit")&&after.includes("v.eof===(v.next_offset===need.bytes)")&&!after.includes("utf8Text(bodyBytes)"));
 ck("whole_final_SHA_UTF8_archive_before_semantics",after.includes("complete.length===need.bytes")&&after.includes("sha256Latin1(byteString(complete))===need.sha256")&&after.includes("wholePin.sha256===need.sha256")&&after.includes('key:"cli-phaseb-r4-public-report-whole"')&&after.includes("semanticQualification:false"));
 new Function(after);ck("JS_parse_only_no_Native",true);
 return{schema:"heptabao.root-CLI-actual-info-and-body13-source-review.v1",source_packet:p.audit,actual_info_packet:ip.audit,checks,passed:true,actual_report:need,original_exit_code:1,full_report_reviewed:false,case_qualifications_from_full_report:false,page_width_change:"Only these new binary_read original observers:16384; prior8192 routes unchanged; existing1MiB payload cap unchanged",root_Runtime_calls:0};
}