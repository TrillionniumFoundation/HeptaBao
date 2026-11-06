function verifyStderrBodySource(files,h,d){
 const {gitBlobMeta}=h,checks=[];
 function ck(n,v){checks.push({name:n,pass:!!v});if(!v)throw Error(n);}
 function pin(n,raw,p){const a=gitBlobMeta(raw);ck(n,a.blob===p.blob&&a.bytes===p.bytes&&a.sha256===p.sha256);}
 const plan=JSON.parse(files["PLAN.public.json"]),before=files["journal.before.js"],after=files["journal.after.js"];
 pin("before_exact",before,plan.reference);pin("after_exact",after,plan.source);pin("diff_exact",files["journal.strict.diff"],plan.diff);pin("request_exact",files["request.original.json"],plan.exact_request);
 const fw=d.applyStrictUnified(before,files["journal.strict.diff"]),rv=d.applyStrictUnified(after,files["journal.strict.diff"],true);
 ck("eight_hunks_forward",fw.text===after&&fw.hunks===8);ck("eight_hunks_reverse",rv.text===before&&rv.hunks===8);
 const q=JSON.parse(files["request.original.json"]),e=plan.expected;
 ck("only_one_binary",q.operation.tool==="binary_read"&&q.operation.arguments.host==="rog"&&q.operation.arguments.path===e.path&&q.operation.arguments.offset===0&&q.operation.arguments.limit===14696&&q.operation.arguments.expected_version===e.version);
 ck("typed_exact_keys",Object.keys(q).sort().join(",")==="idempotency_key,operation"&&Object.keys(q.operation.arguments).sort().join(",")==="expected_version,host,limit,offset,path");
 const infos=JSON.parse(files["ACTUAL-INFOS.original.json"]),st=JSON.parse(files["metadata.STATE.original.json"]);
 pin("metadata_state_whole",files["metadata.STATE.original.json"],plan.metadata_state);
 ck("two_metadata_originals_closed",st.completedObservers.length===2&&st.completedObservers.every(o=>o.completedInactive===true)&&st.pending===null&&st.activeObserver===null&&st.nativeCallInFlight===false);
 for(let i=0;i<2;i++){
  const p=plan.original_info_prerequisites[i],raw=files[i===0?"stderr-info.native.original.json":"stdout-info.native.original.json"];
  pin("info_native_"+i,raw,p.nativeText);
  const v=JSON.parse(raw);
  ck("original_info_"+i,st.completedObservers[i].id===p.id&&infos[i].originalOperation===p.id&&infos[i].path===v.path&&infos[i].size===v.size&&infos[i].sha256===v.sha256&&infos[i].version===v.version);
 }
 ck("actual_stderr_whole_binding",infos[0].path===e.path&&infos[0].size===e.bytes&&infos[0].sha256===e.sha256&&infos[0].version===e.version&&JSON.stringify(infos[0].full9Strings)===JSON.stringify(e.full9Strings));
 const result=JSON.parse(files["original-failed-result.json"]);
 ck("report_log_SHA",result.normal_release_build.stderr_sha256===e.sha256&&result.normal_release_build.exit_code===101&&result.runtime_tests_started===false);
 ck("old_metadata8k_new_binary16k",after.includes('q.limit===(s.activeObserver.tool==="binary_read"?16384:8192)')&&after.includes('b.length<=(a.tool==="binary_read"?16384:8192)')&&after.includes('v.total_bytes<=1048576'));
 ck("once_marker_before_tool",after.indexOf('s.compilerStderrBodyStarted=true')<after.indexOf('sdk=await tools.'));
 ck("separate_GO_in_new_intent",after.includes('rootGo:s.compilerStderrBodyGO?.pin??s.goPin'));
 ck("whole_body_archive_before_store",after.indexOf('const bodyArchive=await archiveFlatPublicTextsOnce')<after.indexOf('store(GF_SLOT+":compiler_stderr_original"'));
 ck("no_stderr_semantics_parser",!after.includes('JSON.parse(bodyRaw)')&&!after.includes('parseLosslessIntegers(bodyRaw)'));
 function defs(t){const a=[...t.matchAll(/^(?:async )?function (\w+)\(/gm)];return Object.fromEntries(a.map((x,i)=>[x[1],t.slice(x.index,a[i+1]?.index??t.length)]));}
 const a=defs(before),b=defs(after);
 ck("one_new_authorizer_only",Object.keys(b).length===Object.keys(a).length+1&&b.gfAuthorizeCompilerStderrBodyOnly);
 for(const n of ["gfNeed","gfMetaEquals","gfState","gfSave","gfIntegerText","gfInitializeOnlyAfterRootGO","gfReconcileSameGitArchiveReadOnly"])ck("unchanged_"+n,a[n]===b[n]);
 new Function("tools","store","load",files["pure.original.js"]+"\n"+files["archive.original.js"]+"\n"+after+"\nreturn gfRun;");
 ck("construct_only",true);
 return {schema:"heptabao.compiler-stderr-body.source-checks.r1",status:"PASS",checks:checks.length,results:checks,Native:0,candidate_invoked:false};
}
