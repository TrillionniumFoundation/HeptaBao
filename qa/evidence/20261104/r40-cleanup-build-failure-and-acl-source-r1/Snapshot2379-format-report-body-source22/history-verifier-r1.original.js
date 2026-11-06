function verifyFormatterBodySource(f,meta,apply,lossless) {
 const checks=[];function ck(name,ok){checks.push({name,passed:!!ok});if(!ok)throw new Error(name);}
 const c=f.candidate,b=f.infoCandidate,a=f.actualInfo;
 ck("base_is_exact_actual_INFO_journal",c.before===b.after);
 ck("candidate_whole_pin",JSON.stringify(meta(c.after))===JSON.stringify(c.pin));
 ck("eight_declared_local_edits",c.edits.length===8);
 let next=c.before;
 for(let i=0;i<c.edits.length;i++){const e=c.edits[i];ck("edit_"+i+"_unique",next.split(e.before).length===2);next=next.replace(e.before,e.after);}
 ck("eight_edits_reconstruct_whole",next===c.after);
 for(let i=c.edits.length-1;i>=0;i--){const e=c.edits[i];ck("reverse_edit_"+i+"_unique",next.split(e.after).length===2);next=next.replace(e.after,e.before);}
 ck("reverse_edits_reconstruct_whole",next===c.before);
 ck("strict_forward_whole",apply(c.before,c.diff)===c.after);
 ck("strict_reverse_whole",apply(c.after,c.reverse)===c.before);
 ck("eight_hunks",(c.diff.match(/^@@ /gm)||[]).length===8);
 const names=["gfNeed","gfMetaEquals","gfState","gfSave","gfIntegerText","gfInitializeOnlyAfterRootGO","gfReconcileSameGitArchiveReadOnly"];
 function block(s,name){const start=s.indexOf("function "+name+"("),tail=s.slice(start);let m=/\n(?:async )?function \w+\(/.exec(tail);return m?tail.slice(0,m.index):tail;}
 for(const name of names)ck("old_helper_unchanged_"+name,block(c.before,name)===block(c.after,name));
 ck("same_info_authorization_prefix",c.before.slice(0,c.before.indexOf("function gfNeed("))===c.after.slice(0,c.after.indexOf("/* Two original version-bound")));
 ck("existing_slot_exact",c.after.includes('const GF_SLOT = "snapshot_2379_rog_formatter_gitfirst_r1";'));
 ck("original_formatter_request_pin_unchanged",c.after.includes('blob:"0fce0771c8a4e42b85abfc10ffbc14e59e588616"'));
 ck("original_file_cap_131072",c.after.includes("const GF_FORMAT_RESULT_MAX_BYTES = 131072;"));
 ck("old_payload_cap_oneMiB",c.after.includes("v.total_bytes<=1048576"));
 ck("separate_new_BODY_GO_scope",c.authorization.includes('g.scope==="format_result_binary_read_ranges_only"'));
 ck("separate_GO_whole_and_info_distinct",c.authorization.includes('goPin.blob!==s.goPin.blob && goPin.blob!==s.formatResultInfoGO.pin.blob'));
 ck("existing_closed_info_and_once_authorize",c.authorization.includes("s.activeObserver===null")&&c.authorization.includes("s.formatResultBodyGO===undefined"));
 ck("metadata_full_original_blob",c.expected.infoNative.blob===meta(a).blob);
 const info=lossless(a),need=c.expected;
 for(const [k,v] of [["path",info.path],["bytes",info.size],["sha256",info.sha256],["version",info.version]])ck("expected_actual_"+k,need[k]===v);
 ck("actual_regular_identity",info.metadata.mode===384&&info.metadata.uid===1000&&info.metadata.gid===1000&&info.metadata.nlink===1);
 ck("fixed_two_requests",c.requests.length===2);
 let offset=0;
 for(let i=0;i<c.requests.length;i++){
  const r=c.requests[i],q=JSON.parse(r.raw),arg=q.operation.arguments;
  ck("request_"+i+"_whole",JSON.stringify(meta(r.raw))===JSON.stringify(r.pin));
  ck("request_"+i+"_tool_host_path",q.operation.tool==="binary_read"&&arg.host==="rog"&&arg.path===need.path);
  ck("request_"+i+"_version_exact",arg.expected_version===need.version);
  ck("request_"+i+"_contiguous_bounded",arg.offset===offset&&arg.limit===r.limit&&arg.limit>0&&arg.limit<=65536);
  ck("request_"+i+"_fixed_key",q.idempotency_key==="heptabao-native-snapshot-2379d02b-formatter-observe-r1-result-body"+i);
  offset+=arg.limit;
 }
 ck("ranges_exact_whole_size",offset===118925&&offset===need.bytes);
 ck("two_only_started_equal_prior_completed",c.validation.includes("s.formatResultBodyStarted===index")&&c.validation.includes("gfMetaEquals(raw,range.request)"));
 ck("new_pages_branch_only_16384_old8192",c.after.includes('q.limit===(s.activeObserver.tool==="binary_read"?GF_FORMAT_BODY_PAGE_BYTES:8192)')&&c.after.includes('b.length<=(a.tool==="binary_read"?GF_FORMAT_BODY_PAGE_BYTES:8192)'));
 ck("capability_max16384",f.capability.description.includes("at most 16384 bytes"));
 ck("marker_before_only_dispatch",c.after.indexOf('s.formatResultBodyStarted++')<c.after.indexOf('sdk=await tools.')&&c.after.indexOf('s.formatResultBodyStarted++')>c.after.indexOf('c.called=true;'));
 ck("range_length_SHA_and_actual_EOF",c.closeBlock.includes("bodyBytes.length===range.limit")&&c.closeBlock.includes("v.eof===(v.next_offset===need.bytes)")&&c.closeBlock.includes("===v.chunk_sha256"));
 ck("individual_chunk_no_UTF8_decode",!c.closeBlock.slice(0,c.closeBlock.indexOf("if(index+1")).includes("utf8Text"));
 ck("whole_SHA_then_UTF8_roundtrip",c.closeBlock.indexOf('sha256Latin1(byteString(complete))===need.sha256')<c.closeBlock.indexOf('utf8Text(complete)'));
 ck("whole_archive_before_semantics",c.closeBlock.includes("semanticQualification:false")&&!c.closeBlock.includes("JSON.parse(wholeRaw)"));
 ck("no_new_Native_tool_dispatch_branch",c.after.match(/sdk=await tools\.[A-Za-z0-9_]+/g).join("\n")===c.before.match(/sdk=await tools\.[A-Za-z0-9_]+/g).join("\n"));
 ck("no_new_initializer_call",c.after.match(/gfInitializeOnlyAfterRootGO\(args\)/g).length===1);
 ck("outer_failure_stops_new_admission",c.after.includes("state.paused=true;state.outerFailure=record;")&&c.after.includes("newAdmissionAllowed:false"));
 return {schema:"heptabao.source-only.formatter49-two-range-checks.v1",status:"PASS",checks,count:checks.length,candidate:c.pin,requests:c.requests.map(x=>x.pin),nativeCalls:0,candidateFunctionsInvoked:0,sourceOnly:true};
}
