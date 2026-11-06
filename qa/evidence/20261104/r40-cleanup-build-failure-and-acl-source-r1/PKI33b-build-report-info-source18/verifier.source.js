function verifyBuildResultInfoSource(i,h,d) {
 const checks=[];
 function ok(name,value){checks.push({name,passed:!!value});if(!value)throw Error(name);}
 const f=d.applyStrictUnified(i.before,i.diff),r=d.applyStrictUnified(i.after,i.diff,true);
 ok("strict_forward_whole",f.text===i.after);ok("strict_reverse_whole",r.text===i.before);
 ok("five_diff_hunks",f.hunks===5&&r.hunks===5);
 let rebuilt=i.before;
 for(const x of i.replacements){ok("one_literal_or_fixed_block_"+x.reason,rebuilt.split(x.before).length===2);rebuilt=rebuilt.replace(x.before,x.after);}
 ok("complete_replacement_inventory",rebuilt===i.after);
 const exact=JSON.parse(i.requestRaw);
 ok("only_file_info",exact.operation.tool==="file_info");
 ok("exact_host_path_keys",Object.keys(exact.operation.arguments).sort().join(",")==="host,path"&&exact.operation.arguments.host==="rog"&&exact.operation.arguments.path===i.path);
 ok("exact_key",exact.idempotency_key==="heptabao-native-jwt-pki-33b814c7-build149-observe-r1-result-info");
 ok("exact_request_pin",JSON.stringify(h.gitBlobMeta(i.requestRaw))===JSON.stringify(i.requestPin));
 ok("original_build_slot",i.after.includes('const GF_SLOT = "jwt_pki_33b814c7_build149_gitfirst_r1";'));
 ok("actual_failed_authority",i.authority.exit_code===1&&i.authority.state==="failed"&&i.authority.output_complete&&i.authority.output_durable&&i.authority.terminal_publication_confirmed&&!i.authority.timed_out&&!i.authority.cancelled);
 const rows=i.streams.stdout.text.trimEnd().split("\n").map(JSON.parse);
 ok("two_actual_rows",rows.length===2&&rows[0].status==="preflight-admitted"&&rows[1].status==="failed");
 ok("actual_original_summary_binding",rows[1].result_path===i.path&&rows[1].result_sha256===i.expectedSha256&&rows[1].all_owned_stopped===true&&rows[1].publication_within_original_outer===true);
 ok("867_bytes_original_stdout",h.gitBlobMeta(i.streams.stdout.text).bytes===867&&i.streams.stdout.eof&&i.streams.stderr.eof&&i.streams.stderr.size===0);
 function funcs(s){const m=[...s.matchAll(/^(?:async )?function ([A-Za-z0-9_]+)\(/gm)];return Object.fromEntries(m.map((x,n)=>[x[1],s.slice(x.index,n+1<m.length?m[n+1].index:s.length)]));}
 const old=funcs(i.before),now=funcs(i.after),unchanged=[];
 for(const name of Object.keys(old))if(!["gfAuthorizeStageResultInfoOnly","gfValidateRequest","gfCloseOriginalObserver","gfRun"].includes(name)){ok("whole_function_"+name,old[name]===now[name]);unchanged.push(name);}
 ok("archive_sdk_before_interpretation_unchanged",old.gfInvokePreparedOnce===now.gfInvokePreparedOnce&&old.gfAcceptArchivedSDK===now.gfAcceptArchivedSDK);
 ok("8k_pages_and_1MiB_payload_unchanged",i.after.includes("q.limit===8192")&&i.after.includes("b.length<=8192")&&i.after.includes("v.total_bytes<=1048576"));
 ok("16k_stream_cap_unchanged",i.after.includes("a.limit===16384")&&i.after.includes("b.length<=16384"));
 ok("single_info_once_marker",i.after.includes("s.stageResultInfoStarted!==true")&&i.after.includes('q.operation.tool==="file_info")s.stageResultInfoStarted=true'));
 ok("stronger_exact_known_SHA_guard",i.after.includes("v.sha256===GF_STAGE_RESULT_EXPECTED_SHA256"));
 ok("new_size_limit_explicit_not_observed",i.maxBytes===1048576&&i.actualSize===null&&i.actualVersion===null);
 ok("full9_linux_mode_uid_gid_singlelink_guard_preserved",i.after.includes("md.uid===1000 && md.gid===1000 && md.link_count===1")&&i.after.includes("String(32768|v.mode)")&&i.after.includes('parts.every(x=>/^[0-9]+$/.test(x))'));
 ok("new_scope_explicit",i.after.includes('g.scope==="build_result_file_info_only"')&&i.after.includes('action==="authorize_build_result_info"'));
 ok("no_binary_read_admission",!i.after.includes('op.tool==="binary_read"')&&!i.after.includes('q.operation.tool==="binary_read"'));
 ok("original_build_not_reinitialized",i.currentState.startCalled===true&&i.currentState.job===i.job&&i.currentState.pending===null&&i.currentState.activeObserver===null&&!i.currentState.nativeCallInFlight&&!i.currentState.paused);
 ok("three_original_observers_closed",i.currentState.completedObservers.length===3&&i.currentState.completedObservers.every(x=>x.completedInactive===true));
 ok("original_report_permissions_source",i.runner.includes("os.umask(0o077)")&&i.runner.includes("with path.open('x') as f:"));
 return {schema:"heptabao.build149-failed-result-info.source-checks.r1",status:"PASS_SOURCE_ONLY",checks:checks.length,passed:checks.every(x=>x.passed),details:checks,unchangedFunctions:unchanged,Native:0,Cargo:0,originalResultSizeUnobserved:true,resultBodyAuthorized:false,metadataAuthorized:false};
}
