function verify4aDualInfoSource(texts) {
 const checks=[];const need=(name,ok)=>{checks.push({name,pass:!!ok});if(!ok)throw Error(name);};
 const before=texts["journal.before.js"],bs=JSON.parse(texts["BINDINGS.public.json"]),plan=JSON.parse(texts["PLAN.public.json"]);
 const report=parseLosslessIntegers(texts["producer-report.original.json"]);
 need("donor_whole",gitBlobMeta(before).blob==="a0f43f0aa0789d7405f7ac1b00379a4b0ece8749");
 need("producer_report_whole",gitBlobMeta(texts["producer-report.original.json"]).blob==="1bc73accafe974e2ae7462c4e76b9093ad0edf12");
 need("producer_qualification_whole",gitBlobMeta(texts["producer-root-qualification.original.json"]).blob==="489681f4680763539866097e650073729c68dee7");
 need("two_fixed_ordered_contexts",bs.length===2&&bs.map(b=>b.tag).join(",")==="mac,x230"&&new Set(bs.map(b=>b.slot)).size===2);
 need("no_execution_or_body_authority",plan.state==="SOURCE_ONLY_UNEXECUTED"&&plan.authorization.GO===null&&!plan.authorization.binary_read&&!plan.authorization.process_start&&!plan.authorization.Mac_write&&!plan.authorization.Cargo&&!plan.authorization.B_store_access&&!plan.authorization.old_context_reset);
 need("serial_budget",plan.authorization.complete_first_original_operation_and_all_pages_before_second_initialize===true&&plan.authorization.C_lane_maximum===1&&JSON.stringify(plan.per_operation_limits)===JSON.stringify({status:8,pages:128,page_bytes:8192,payload_bytes:1048576,native_calls_maximum:137,one_call_or_future:true}));
 for(const b of bs){
  const tag=b.tag,after=texts[tag+".journal.source.js"],requestRaw=texts[tag+".request.exact.json"],q=JSON.parse(requestRaw),r=report[b.field];
  need(tag+"_strict_forward",applyStrict(before,texts[tag+".forward.diff"])===after);
  need(tag+"_strict_reverse",applyStrict(after,texts[tag+".reverse.diff"])===before);
  need(tag+"_one_hunk",(texts[tag+".forward.diff"].match(/^@@ /gm)||[]).length===1);
  let expected=before.replace(/^const GF_SLOT = .*;$/m,"const GF_SLOT = "+JSON.stringify(b.slot)+";").replace(/^const GF_REQUEST = .*;$/m,"const GF_REQUEST = "+JSON.stringify(b.exact_request)+";").replace(/^const GF_EXPECTED = .*;$/m,"const GF_EXPECTED = "+JSON.stringify(b.expected)+";");
  need(tag+"_only_three_constant_lines",after===expected);
  need(tag+"_all_thirteen_functions_unchanged",before.slice(before.indexOf("function gfNeed"))===after.slice(after.indexOf("function gfNeed"))&&(after.match(/^(?:async )?function [^(]+/gm)||[]).length===13);
  need(tag+"_source_and_request_pins",JSON.stringify(gitBlobMeta(after))===JSON.stringify(b.journal)&&JSON.stringify(gitBlobMeta(requestRaw))===JSON.stringify(b.exact_request));
  need(tag+"_closed_exact_request",Object.keys(q).sort().join(",")==="idempotency_key,operation"&&q.idempotency_key==="heptabao-4a49405b-"+tag+"-bundle-info-rog-20261106-r1"&&q.operation.tool==="file_info"&&Object.keys(q.operation.arguments).sort().join(",")==="host,path"&&q.operation.arguments.host==="rog"&&q.operation.arguments.path===b.expected.path);
  need(tag+"_actual_stage_identity_lossless",r.path===b.expected.path&&r.bytes===b.expected.bytes&&r.sha256===b.expected.sha256&&JSON.stringify(r.identity.map(v=>typeof v==="number"?String(v):v.$exactInteger))===JSON.stringify(b.expected.full9));
  need(tag+"_known_qual_reference",JSON.stringify(b.stage_witness.report)===JSON.stringify(gitBlobMeta(texts["producer-report.original.json"]))&&JSON.stringify(b.stage_witness.root_qualification)===JSON.stringify(gitBlobMeta(texts["producer-root-qualification.original.json"])));
  need(tag+"_header_exact_candidate",r.header.version===2&&JSON.stringify(r.header)===JSON.stringify(b.header)&&JSON.stringify(r.header.heads)==='[["4a49405b93c45ab1c25ecba11cde63a7ede20dce","HEAD"]]'&&JSON.stringify(r.header.prerequisites)===JSON.stringify([tag==="mac"?"5767739cd25e458ac052dc8d384019bab8688ae0":"02b90762b3d6cc8699cc88bffb6f76cb1f07e270"]));
  need(tag+"_actual_future_values_null",b.actual_info===null&&b.actual_body===null);
 }
 return {schema:"heptabao.C4a.dual-info-source-checks.r1",pass:true,check_count:checks.length,checks,Native_calls:0,contexts_initialized:0,Python_executed:false};
}
