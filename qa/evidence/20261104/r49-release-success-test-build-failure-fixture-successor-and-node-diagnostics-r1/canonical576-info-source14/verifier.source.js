function verify576CanonicalInfoSource(input){
 const {before,after,diff,requestRaw,reportRaw,plan}=input,checks=[];
 function check(name,value){checks.push({name,pass:value===true});if(value!==true)throw Error(name);}
 check("exact_predecessor_d86f",gitBlobMeta(before).blob==="d86f10d12cc1303c8d5bd66ffde8423a03a3f576");
 check("exact_successor_source_a0f4",gitBlobMeta(after).blob==="a0f43f0aa0789d7405f7ac1b00379a4b0ece8749");
 check("one_strict_hunk",(diff.match(/^@@ /gm)||[]).length===1);
 check("strict_forward",applyStrict(before,diff)===after);
 check("strict_reverse",applyStrict(after,diff,true)===before);
 const normalize=s=>s.replace(/^const GF_(SLOT|REQUEST|EXPECTED) = .*;$/gm,"const GF_$1 = BINDING;");
 check("only_three_constants_all_rest_equal",normalize(before)===normalize(after));
 check("all13_function_bodies_byte_exact",after.slice(after.indexOf("\nfunction gfNeed"))===before.slice(before.indexOf("\nfunction gfNeed"))&&Array.from(after.matchAll(/^(?:async )?function /gm)).length===13);
 check("exact_original_producer_whole",gitBlobMeta(reportRaw).blob==="f2b99e2c118f4066e99f6f926427ca67cd61d1b2");
 const r=parseLosslessIntegers(reportRaw),b=r.canonical_bundle;
 check("producer_actual576_and_parent02b",r.status==="prepared"&&r.source_commit==="5767739cd25e458ac052dc8d384019bab8688ae0"&&r.source_tree==="42477d622dcf96e1e2b0929fe9ecc6b7ba484740"&&r.sole_parent==="02b90762b3d6cc8699cc88bffb6f76cb1f07e270");
 const full9=b.identity.map(x=>typeof x==="object"?x.$exactInteger:String(x));
 check("lossless_exact_stage_full9",JSON.stringify(plan.expected.full9)===JSON.stringify(full9)&&full9[7]==="1794000539740776688"&&full9[8]===full9[7]);
 check("stage_bytes_sha_path_exact",plan.expected.path===b.path&&plan.expected.bytes===b.bytes&&plan.expected.sha256===b.sha256&&b.bytes===5766);
 check("v2_sole_prerequisite_head",b.header.version===2&&JSON.stringify(b.header.prerequisites)===JSON.stringify([r.sole_parent])&&JSON.stringify(b.header.heads)===JSON.stringify([[r.source_commit,"HEAD"]]));
 const q=JSON.parse(requestRaw);
 check("only_exact_fixed_INFO_request",JSON.stringify(q)===JSON.stringify(plan.exact_operation)&&q.operation.tool==="file_info"&&q.operation.arguments.host==="rog"&&q.operation.arguments.path===b.path&&Object.keys(q.operation.arguments).sort().join(",")==="host,path");
 check("exact_request_pin",JSON.stringify(gitBlobMeta(requestRaw))===JSON.stringify(plan.request)&&after.includes("const GF_REQUEST = "+JSON.stringify(plan.request)+";"));
 check("new_fresh_slot_exact",plan.protocol.fresh_slot==="successor576_canonical_bundle_info_gitfirst_r1"&&after.includes('const GF_SLOT = "successor576_canonical_bundle_info_gitfirst_r1";'));
 check("expected_constant_exact",after.includes("const GF_EXPECTED = "+JSON.stringify(plan.expected)+";"));
 check("unchanged_limits",plan.limits.operation_status_total===8&&plan.limits.operation_result_total===128&&plan.limits.immutable_page_bytes===8192&&plan.limits.payload_bytes===1048576&&plan.limits.max_native_calls===137&&plan.limits.simultaneous_call_or_future===1);
 check("no_BODY_or_process_scope",plan.scope.file_info_admissions===1&&plan.scope.process_start===0&&plan.scope.binary_read===0&&plan.scope.new_processes===0&&plan.scope.filesystem_writes===0&&plan.actual_version===null&&plan.actual_body===null&&plan.new_native_calls===0);
 return {schema:"heptabao.canonical576-info-source-verification.v1",pass:true,check_count:checks.length,checks,Native_calls:0,Git_calls:0,candidate_executed:false};
}
