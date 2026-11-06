function verify576DefaultCompileLogsInfoSource(I) {
 const checks=[];function need(ok,name){checks.push({name,ok:!!ok});if(!ok)throw Error(name);}
 function exact(a,b){return JSON.stringify(a)===JSON.stringify(b);}
 need(exact(gitBlobMeta(I.before),I.beforePin),"exact_body_journal_before");
 need(exact(gitBlobMeta(I.after),I.afterPin),"exact_logs_info_journal_after");
 need(snapshotApply(I.before,I.forward)===I.after,"strict_forward_six_hunks");
 need(snapshotApply(I.after,I.reverse)===I.before,"strict_reverse_six_hunks");
 need((I.forward.match(/^@@/gm)||[]).length===6&&I.edits.length===6,"six_changes_only");
 let rebuilt=I.before;for(const e of I.edits){need(rebuilt.split(e.old).length-1===1,"unique_edit_"+checks.length);rebuilt=rebuilt.replace(e.old,e.next);}
 need(rebuilt===I.after,"whole_reconstruction");
 need(exact(gitBlobMeta(I.reportRaw),I.reportPin),"actual_report_whole_pin");
 const report=parseLosslessIntegers(I.reportRaw);
 const failed=report.compile_shared.commands[2];
 need(report.status==="failed"&&report.normal_release_build.exit_code===0
  &&report.compile_shared.commands.length===3&&failed.label==="default-libtest-build"
  &&failed.exit_code===101&&failed.timed_out===false
  &&report.runtime_tests_started===false&&report.group_results.length===0,"known_actual_default_profile_compile_failure_not_test_failure");
 need(report.compile_shared.commands[0].label==="ordinary-no-default-check"&&report.compile_shared.commands[0].exit_code===0
  &&report.compile_shared.commands[1].label==="file-libtest-build"&&report.compile_shared.commands[1].exit_code===0,"prior_two_compile_profiles_success");
 need(report.cleanup.length===4&&report.cleanup.every(x=>x.direct_child_reaped&&x.remaining.length===0),"four_original_direct_children_closed");
 need(I.runner.includes("with (output / (label + '.stdout')).open('xb') as out, (output / (label + '.stderr')).open('xb') as err:")
  &&I.launcher.includes("OUTPUT = ROOT / 'build-tests-r1'")&&I.launcher.includes("'--output', str(OUTPUT)"),"exact_runner_owned_log_path_construction");
 need(I.files.length===2&&I.files[0].stream==="stderr"&&I.files[1].stream==="stdout","two_fixed_ordered_logs");
 for(const file of I.files) {
  need(exact(gitBlobMeta(file.requestRaw),file.request),"exact_request_"+file.stream);
  const q=JSON.parse(file.requestRaw),a=q.operation.arguments;
  need(q.operation.tool==="file_info"&&a.host==="rog"&&Object.keys(a).sort().join(",")==="host,path","metadata_only_"+file.stream);
  need(a.path==="/home/qian-qi/hb-5767739c-controls-20261106-r1/build-tests-r1/default-libtest-build."+file.stream,"fixed_path_"+file.stream);
  need(file.sha256===failed[file.stream+"_sha256"]&&file.maximumBytes===4194304,"actual_report_SHA_and_finite_cap_"+file.stream);
 }
 need(I.state.job==="1a1b2d90976-fc05-7fff"&&!I.state.paused&&!I.state.pending&&!I.state.activeObserver&&!I.state.nativeCallInFlight,"closed_existing_original_context");
 need(Object.keys(I.state.calls).length===56&&Object.values(I.state.calls).every(c=>c.phase==="accepted"&&c.called),"retain56originalCalls");
 need(I.state.completedObservers.length===16&&I.state.completedObservers.every(o=>o.completedInactive),"retain16closedObservers");
 need(I.state.outerFailure?.message==="original_expected_tree_not_observed"
  &&I.state.exactOriginalStatusSDKArchiveRecovery?.oldUnknownRetained===true
  &&I.state.exactOriginalStatusSDKArchiveRecovery?.oldCreateExpectedTree==="5ecb3221ebad396fb9b7af067e7549d3294b2225"
  &&I.state.exactOriginalStatusSDKArchiveRecovery?.originalNativeCallNotRepeated===true,"retain_original_Git_UNKNOWN_and_exact_recovery");
 need(I.state.completedObservers.reduce((n,o)=>n+o.pages,0)===23,"retain23originalPayloadPages");
 function fn(s,name,next){const k=s.indexOf(name);return s.slice(k,s.indexOf(next,k));}
 need(fn(I.before,"function gfAcceptArchivedSDK","async function gfCloseOriginalObserver")===fn(I.after,"function gfAcceptArchivedSDK","async function gfCloseOriginalObserver"),"original_SDK_accept_status_pages_identical");
 need(I.after.includes("q.limit===8192")&&I.after.includes("v.total_bytes<=1048576")&&I.after.includes("b.length<=8192"),"original_8KiB_page_and_1MiB_payload_limits");
 need(I.after.includes("v.sha256===need.sha256 && v.mode===384")&&I.after.includes("md.uid===1000 && md.gid===1000 && md.link_count===1"),"metadata_whole_SHA_owner_mode_gate");
 need(I.after.includes('parts[2]===String(v.size)')&&I.after.includes('parts.every(x=>/^[0-9]+$/.test(x))'),"lossless_version_gate");
 const zeroTools=new Proxy({}, {get(){throw Error("no tools in source verifier");}});
 function ctx(change) {
  const s=JSON.parse(JSON.stringify(I.state));if(change)change(s);
  const map=new Map([[I.slot,s],[I.slot+":stage_result_body_original",I.reportRaw]]);
  const api=new Function("load","store","tools",I.pure+"\n"+I.archive+"\n"+I.after+";return {auth:gfAuthorizeBuildLogsInfoOnly,valid:gfValidateRequest};")(k=>map.get(k),(k,v)=>map.set(k,v),zeroTools);
  return {s,api};
 }
 const g={sourcePrivateFixtureOnly:true,authorization:"GO",scope:"build_logs_file_info_only",original_job:I.state.job,maximum_file_info_starts:2,binary_read_authorized:false,exact_requests:I.files.map(x=>x.request)};
 function auth(c,obj=g){const raw=JSON.stringify(obj,null,2)+"\n";return c.api.auth({goRaw:raw,goPin:gitBlobMeta(raw),goWholeReadback:true});}
 function valid(c,n){const raw=I.files[n].requestRaw;c.api.valid(c.s,"operation_start",JSON.parse(raw),raw);}
 const c=ctx();auth(c);valid(c,0);need(c.s.buildLogInfoCalled===0&&c.s.buildLogInfoNext===0,"private_first_info_allowed_no_native");
 function reject(name,action){let denied=false;try{action();}catch(e){denied=true;}need(denied,name);}
 reject("reject_second_before_first_closed",()=>valid(c,1));
 c.s.buildLogInfoCalled=1;reject("reject_first_replay_after_called",()=>valid(c,0));
 c.s.buildLogInfoNext=1;valid(c,1);need(c.s.buildLogInfoCalled===1,"private_second_only_after_first_closed");
 reject("reject_old_first_after_advance",()=>valid(c,0));
 c.s.buildLogInfoCalled=2;c.s.buildLogInfoNext=2;reject("reject_third_metadata",()=>valid(c,1));
 reject("reject_reauthorization",()=>auth(c));
 for(const [name,change]of [
  ["paused",s=>s.paused=true],["pending",s=>s.pending="x"],["activeObserver",s=>s.activeObserver={}],
  ["inflight",s=>s.nativeCallInFlight=true],["wrongJob",s=>s.job="other"],
  ["wrongBodyOperation",s=>s.stageResultBody.originalOperation="0".repeat(64)]
 ])reject("reject_"+name,()=>auth(ctx(change)));
 reject("reject_wrong_scope",()=>auth(ctx(),{...g,scope:"build_result_file_info_only"}));
 reject("reject_body_permission",()=>auth(ctx(),{...g,binary_read_authorized:true}));
 reject("reject_wrong_GO_requests",()=>auth(ctx(),{...g,exact_requests:[...g.exact_requests].reverse()}));
 const fresh=ctx();auth(fresh);
 const oldBody=I.bodyRequestRaw;reject("reject_body_replay",()=>fresh.api.valid(fresh.s,"operation_start",JSON.parse(oldBody),oldBody));
 const other=JSON.parse(I.files[0].requestRaw);other.operation.arguments.path+="/other";const otherRaw=JSON.stringify(other,null,2)+"\n";
 reject("reject_other_path",()=>fresh.api.valid(fresh.s,"operation_start",other,otherRaw));
 need(exact(I.state,JSON.parse(I.stateRaw)),"actual_state_input_not_mutated");
 return {schema:"heptabao.current576-default-compile-loginfo-source-checks.r1",status:"passed",checkCount:checks.length,checks,runtimeCalls:0,onlyPrivateClonedStateUsed:true,actualFailurePreserved:true,productQualified:false};
}