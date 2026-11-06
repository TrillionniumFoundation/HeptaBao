function verify025bInfoRoot(p,t,author){
 const checks=[];function ck(v,k){checks.push({code:k,pass:!!v});if(!v)throw Error(k);}
 const raw=p.raw,plan=JSON.parse(raw["PLAN.public.json"]),before=raw["journal.33b.info.before.js"],after=raw["journal.025b.info.after.js"],diff=raw["journal.strict.diff"],repl=JSON.parse(raw["literal-bindings.public.json"]);
 ck(p.pins.length===22 && p.pins.reduce((n,x)=>n+x.bytes,0)===106252,"whole22_source_packet");
 for(const x of p.pins)ck(gitBlobMeta(raw[x.path]).blob===x.blob && gitBlobMeta(raw[x.path]).sha256===x.sha256 && gitBlobMeta(raw[x.path]).bytes===x.bytes,"whole_pin:"+x.path);
 ck(t.passed && t.checkCount===35 && t.job==="1a1b07b7e0b-fc05-70ca" && t.knownExitCode===0 && t.fullDurable && t.actualCalls===7 && t.returnedObservers===2 && t.immutablePages===2 && t.currentLineCReleased,"original_stage_terminal_root_qualification");
 ck(author.status==="PASS"&&author.checks===32&&author.actual_Native_calls===0,"author32_root_reproduced_pure_only");
 ck(gitBlobMeta(before).blob==="696e07c763ccefaa375e947ed84b2433a1d0f089" && gitBlobMeta(after).blob==="69a754dee5fc0fa48d6f2bbf8e356914b0332551","exact_old_and_new_journal");
 ck(strictApply(before,diff).text===after && strictApply(after,diff,true).text===before && strictApply(before,diff).hunks===2,"bidirectional_strict_two_hunks");
 let x=before;ck(repl.length===7,"seven_literal_groups");for(const r of repl){ck(x.split(r.old).length===2,"one_binding:"+r.why);x=x.replace(r.old,r.next);}ck(x===after,"all_other_bytes_unchanged");
 const q=JSON.parse(raw["request.025b.exact.json"]),s=JSON.parse(raw["reference.current-stage-state.json"]),v=JSON.parse(raw["verifier.state-input.public.json"]);
 ck(q.operation.tool==="file_info"&&q.operation.arguments.host==="rog"&&q.operation.arguments.path===t.resultPath && Object.keys(q.operation.arguments).sort().join(",")==="host,path","single_fixed_public_report_path");
 ck(q.idempotency_key==="heptabao-native-jwt-pki-025b05a3-rog-source-observe-r1-stage-result-info0" && gitBlobMeta(raw["request.025b.exact.json"]).blob===plan.exact_request.blob,"exact_once_info_request");
 ck(s.job===t.job&&s.pending===null&&s.activeObserver===null&&s.nativeCallInFlight===false&&s.paused===false&&s.startCalled===true,"current_closed_stage_state");
 ck(JSON.stringify(s.completedObservers)===JSON.stringify(v.completedObservers)&&s.completedObservers.length===2,"actual_closed_observers_preserved");
 ck(plan.prerequisites.every((r,i)=>r.id===s.completedObservers[i].id&&r.tool===s.completedObservers[i].tool&&r.nativeText.blob===s.completedObservers[i].nativeText.blob),"two_actual_prerequisites_exact");
 ck(gitBlobMeta(raw["reference.authority.native.json"]).blob===t.authority.blob&&gitBlobMeta(raw["reference.streams.native.json"]).blob===t.streams.blob,"prior_native_full_bodies_match_terminal_qualification");
 ck(plan.slot==="jwt_pki_025b05a3_rog_source_gitfirst_r1"&&plan.no_reinitialize&&plan.no_process_start&&plan.binary_read_authorized===false,"attach_existing_slot_only");
 ck(plan.expected.mode===384&&plan.expected.full_mode===33152&&plan.expected.uid===1000&&plan.expected.gid===1000&&plan.expected.nlink===1&&plan.expected.maximum_size===150000,"fixed_metadata_guards_unchanged");
 ck(["actual_size","actual_sha256","actual_version","actual_full9"].every(k=>plan.expected[k]===null),"actual_metadata_not_manufactured");
 ck(plan.limits.maximum_file_info_starts===1&&plan.limits.immutable_page_bytes===8192&&plan.limits.original_payload_bytes===1048576,"bounded_original_observer_caps");
 return {schema:"heptabao.root.025b-stage-result-INFO-source-qualification.r1",passed:true,checkCount:checks.length,checks,sourceTree:"8f350d50067d528ff00529870c8ae82831f9aed6",sourceFiles:22,sourceBytes:106252,originalStagePacket:t.packet.tree,originalJob:t.job,exactRequest:plan.exact_request,journal:plan.after,slot:plan.slot,scope:"stage_result_file_info_only",actualMetadataObserved:false,binaryReadAuthorized:false,productionChanged:false,NativeCalls:0};
}