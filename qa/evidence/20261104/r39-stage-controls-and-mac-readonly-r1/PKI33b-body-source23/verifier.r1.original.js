function verifyFinalStageBodySource(f,h,d){
 const checks=[];function ck(n,v){checks.push({check:n,pass:!!v});if(!v)throw Error(n);}
 const c=JSON.parse(f["BINDINGS.public.json"]),a=f["journal.before.js"],b=f["journal.after.js"];
 ck("exact_original_successful_body_source",h.gitBlobMeta(a).blob==="703a403a43fbd8ce8db9d0e30c21b77d13982900");
 ck("candidate_pin",h.gitBlobMeta(b).blob===c.candidate.blob);
 ck("13_binding_entries_14_literal_occurrences",c.replacements.length===13&&c.replacements.reduce((s,x)=>s+x[2],0)===14);
 let x=a;for(const[p,q,n]of c.replacements){ck("exact_occurrences:"+p.slice(0,50),x.split(p).length===n+1);x=x.split(p).join(q);}ck("all_other_source_bytes_unchanged",x===b);
 for(const[p,q,n]of c.replacements.slice().reverse()){if(x.split(q).length!==n+1)throw Error("reverse_occurrence");x=x.split(q).join(p);}ck("inverse_whole_original",x===a);
 const fw=d.applyStrictUnified(a,f["journal.strict.diff"]),rv=d.applyStrictUnified(b,f["journal.strict.diff"],true);ck("strict_four_hunks_forward_reverse",fw.text===b&&rv.text===a&&fw.hunks===4&&rv.hunks===4);
 const def=s=>{const z=[...s.matchAll(/^(?:async )?function ([A-Za-z0-9_]+)\(/gm)];return z.map((q,i)=>({name:q[1],text:s.slice(q.index,z[i+1]?.index??s.length)}));};
 const aa=def(a),bb=def(b);ck("same_complete_function_order",aa.length===bb.length&&aa.every((q,i)=>q.name===bb[i].name));
 const changed=aa.filter((q,i)=>q.text!==bb[i].text).map(q=>q.name);ck("only_3_existing_binding_sections_changed",JSON.stringify(changed)===JSON.stringify(["gfAuthorizeStageResultInfoOnly","gfAuthorizeStageResultBodyOnly","gfValidateRequest"]));
 for(let i=0;i<aa.length;i++)if(!changed.includes(aa[i].name))ck("whole_function:"+aa[i].name,aa[i].text===bb[i].text);
 const v=h.parseLosslessIntegers(f["info.native.original.json"]),p=c.expected,s=JSON.parse(f["info.status.original.json"]);
 ck("metadata_source_pin",h.gitBlobMeta(f["info.native.original.json"]).blob===p.infoNative.blob&&h.gitBlobMeta(f["info.native.original.json"]).bytes===p.infoNative.bytes&&h.gitBlobMeta(f["info.native.original.json"]).sha256===p.infoNative.sha256);
 ck("original_info_closed",s.operation_id===p.infoOperation&&s.tool_name==="file_info"&&s.async_state==="completed"&&s.result_state==="stored_observed"&&s.owned_future_active===false&&s.payload_available===true);
 ck("whole_metadata_content_match",v.path===p.path&&v.size===p.bytes&&v.sha256===p.sha256&&v.version===p.version);
 ck("private_Linux_singlelink_unchanged",v.mode===384&&v.metadata.mode===384&&v.metadata.metadata_platform==="linux"&&v.metadata.uid===1000&&v.metadata.gid===1000&&v.metadata.link_count===1);
 const parts=v.version.split(":");ck("decimal_version_without_loss",parts.length===5&&parts.every(x=>/^[0-9]+$/.test(x))&&parts[2]===String(v.size));
 const q=JSON.parse(f["request.exact.json"]),old=JSON.parse(f["request.before.json"]),e=JSON.parse(JSON.stringify(old));e.idempotency_key=c.bodyKey;e.operation.arguments.path=p.path;e.operation.arguments.limit=p.bytes;e.operation.arguments.expected_version=p.version;
 ck("request_only_known_bindings",JSON.stringify(q)===JSON.stringify(e));
 ck("exact_frozen_request_pin",h.gitBlobMeta(f["request.exact.json"]).blob===c.exactRequest.blob&&h.gitBlobMeta(f["request.exact.json"]).bytes===c.exactRequest.bytes&&h.gitBlobMeta(f["request.exact.json"]).sha256===c.exactRequest.sha256);
 ck("one_fixed_binary_range_no_extra_args",q.operation.tool==="binary_read"&&q.operation.arguments.host==="rog"&&q.operation.arguments.offset===0&&q.operation.arguments.limit===27931&&Object.keys(q.operation.arguments).sort().join(",")==="expected_version,host,limit,offset,path");
 ck("single_chunk_and_original_caps",p.bytes>0&&p.bytes<=65536&&p.bytes<=150000&&b.includes("q.limit===8192")&&b.includes("a.total<=1048576"));
 ck("separate_body_GO_once_no_reset",b.includes('g.scope==="stage_result_binary_read_only"')&&b.includes('g.maximum_binary_read_starts===1')&&b.includes('goPin.blob!==s.goPin.blob && goPin.blob!==s.stageResultInfoGO.pin.blob')&&b.includes('s.stageResultBodyGO===undefined && s.stageResultBodyStarted!==true'));
 ck("actual_info_proof_not_summary_derived",b.includes('prior?.completedInactive===true && prior.tool==="file_info"')&&b.includes('info.version===need.version && info.originalOperation===need.infoOperation'));
 ck("original_stream_complete_bound",b.includes('s.nextStdout===374 && s.nextStderr===0')&&b.includes('s.job==="1a1afcbafab-fc05-6bb0"'));
 ck("SOURCE_not_body_observation",c.NativeCalls===0&&c.attachOnly===true&&c.newGORequired===true&&c.reportBodyObserved===false);
 return {schema:"heptabao.jwt-pki-finalstage-body-source-checks.v1",pass:true,checks:checks.length,rows:checks,functionCount:aa.length,wholeFunctions:aa.length-changed.length,changedSections:changed,strictHunks:4,bindingEntries:13,literalOccurrences:14,candidateExecuted:false,NativeCalls:0};
}
