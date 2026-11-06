
function qualifyAuthStderrActual(r,audit){
 const checks=[];const ck=(name,v)=>checks.push({name,passed:v===true});
 const eq=(t,p)=>{const m=gitBlobMeta(t);return m.blob===p.blob&&m.bytes===p.bytes&&m.sha256===p.sha256};
 const idx=JSON.parse(r["OBSERVATION-INDEX.public.json"]),rel=JSON.parse(r["actual-RELEASE.public.json"]),out=JSON.parse(r["actual-stdout.original.txt"]),a=JSON.parse(r["actual-authority.original.json"]),streams=JSON.parse(r["actual-streams.original.json"]),ctx=JSON.parse(r["complete-context.public.json"]),go=load("r34_auth_stderr_GO"),recGo=load("r34_auth_stderr_adopt_GO"),job="1a1aed868b6-fc05-6321",calls=idx.originalCalls;
 ck("whole_original83",audit.whole&&audit.files===83&&audit.bytes===658848);
 ck("ten_original_calls",calls.length===10&&idx.callCount===10&&new Set(calls.map(c=>c.callKey)).size===10);
 const kinds={};
 for(let k=0;k<calls.length;k++){
  const c=calls[k];kinds[c.kind]=(kinds[c.kind]||0)+1;
  const q=r[c.request.path],s=r[c.sdk.path],n=r[c.native.path],intent=JSON.parse(r[c.intent.path]),armed=JSON.parse(r[c.armed.path]),sdk=JSON.parse(s),g=k<5?go:recGo;
  ck("pins_"+c.callKey,[["request",q],["sdk",s],["native",n],["intent",r[c.intent.path]],["armed",r[c.armed.path]]].every(([key,t])=>eq(t,c[key])));
  ck("one_armed_"+c.callKey,c.once===true&&c.phase==="accepted"&&intent.kind===c.kind&&intent.callKey===c.callKey&&intent.maximumNativeCalls===1&&armed.maximumNativeCalls===1&&intent.nativeNotYetCalled===true&&armed.mayHaveDispatchedAfterThisCheckpoint===true&&eq(q,intent.request)&&eq(q,armed.request)&&eq(g.text,intent.rootGo)&&eq(g.text,armed.rootGo));
  ck("SDK_native_"+c.callKey,sdk.isError===false&&sdk.content.length===1&&sdk.content[0].type==="text"&&sdk.content[0].text===n);
 }
 ck("one_start_two_observers_five_pages",kinds.process_start===1&&kinds.operation_start===2&&kinds.operation_status===2&&kinds.operation_result===5&&Object.keys(kinds).length===4);
 const q=JSON.parse(r[calls[0].request.path]),ack=parseLosslessIntegers(r[calls[0].native.path]);
 ck("original_exact_START",eq(r[calls[0].request.path],go.value.exact_request)&&eq(q.stdin,go.value.source)&&ack.audit_recorded===true&&ack.local_record_pending===false&&ack.reused===false&&ack.launch.ok===true&&ack.job.id===job&&ack.job.host==="mac"&&ack.job.execution_mode==="operator"&&ack.job.idempotency_key===q.idempotency_key&&ack.job.request_digest===go.value.native_binding.sha256&&ack.job.request_fingerprint.$exactInteger===go.value.native_binding.native_fingerprint);
 ck("terminal_exit0_full_durable",a.job_id===job&&a.state==="succeeded"&&a.exit_code===0&&a.audit_recorded&&a.output_complete&&a.output_durable&&a.terminal_publication_confirmed&&!a.automatic_retry&&!a.cancelled&&!a.timed_out);
 ck("two_closed_original_observers",rel.originalObserverCount===2&&rel.originalImmutablePageCount===5&&rel.originalObservers.length===2&&rel.activeRuntimeCalls===0&&rel.activeNativeFutures===0&&idx.activeRuntimeCalls===0&&idx.activeNativeFutures===0);
 for(const o of rel.originalObservers){
  const admission=calls.filter(c=>c.kind==="operation_start"&&JSON.parse(r[c.native.path]).operation_id===o.id);
  ck("one_original_admission_"+o.tool,admission.length===1&&JSON.parse(r[admission[0].request.path]).operation.arguments.job_id===job&&JSON.parse(r[admission[0].request.path]).operation.arguments.host==="mac"&&JSON.parse(r[admission[0].native.path]).reused===false);
  const pc=calls.filter(c=>c.kind==="operation_result"&&JSON.parse(r[c.request.path]).operation_id===o.id).sort((x,y)=>JSON.parse(r[x.request.path]).offset-JSON.parse(r[y.request.path]).offset);let bytes=[],off=0,valid=true;
  for(let j=0;j<pc.length;j++){const c=pc[j],req=JSON.parse(r[c.request.path]),v=JSON.parse(r[c.native.path]),b=unb64(v.data_base64);
   valid=valid&&req.limit===8192&&req.offset===off&&v.offset===off&&v.operation_id===o.id&&v.immutable_snapshot===true&&v.automatic_retry===false&&b.length<=8192&&v.next_offset===off+b.length&&v.total_bytes===o.payload.bytes&&v.result_sha256===o.payload.sha256&&v.eof===(j===pc.length-1);
   bytes.push(...b);off+=b.length;}
  const pr=utf8Text(bytes),payload=JSON.parse(pr),key=o.tool==="process_status"?"authority":"streams";
  ck("original_contiguous_pages_"+key,valid&&pc.length===o.pages&&off===o.payload.bytes&&eq(pr,o.payload)&&pr===r[key+"-payload.original.json"]);
  ck("whole_payload_native_"+key,payload.resultType==="complete"&&payload.isError===false&&payload.content.length===1&&payload.content[0].text===r["actual-"+key+".original.json"]&&eq(payload.content[0].text,o.nativeText));
  const sc=calls.filter(c=>c.kind==="operation_status"&&JSON.parse(r[c.request.path]).operation_id===o.id);
  ck("actual_inactive_"+key,sc.length===1&&sc.every(c=>{const v=JSON.parse(r[c.native.path]);return v.operation_id===o.id&&v.async_state==="completed"&&v.owned_future_active===false&&v.result_state==="stored_observed"&&v.payload_available===true&&!v.automatic_retry})&&o.completedInactive);
 }
 for(const name of ["stdout","stderr"]){const row=streams[name],raw=r["actual-"+name+".original.txt"],b=utf8Bytes(raw),hex=b.map(x=>x.toString(16).padStart(2,"0")).join("");
  ck("stream_text_hex_EOF_"+name,streams.job_id===job&&row.offset===0&&row.next_offset===b.length&&row.size===b.length&&row.eof===true&&row.text===raw&&row.bytes_hex===hex&&eq(raw,rel[name]));
  ck("authority_stream_"+name,a.log_bytes[name].seen===b.length&&a.log_bytes[name].stored===b.length&&a.log_synced[name]===true&&a.log_truncated[name]===false&&a.log_errors[name]===null);}
 ck("only_known_two_warnings",r["actual-stderr.original.txt"]==="<stdin>:607: SyntaxWarning: 'return' in a 'finally' block\n<stdin>:612: SyntaxWarning: 'return' in a 'finally' block\n");
 ck("actual_diagnostic_complete_deadline",out.ok===true&&!out.outcomeUnknown&&out.deadlineMetAfterClosure&&out.elapsedSeconds>0&&out.elapsedSeconds<45&&out.newDiagnosticSeconds===45&&out.outerSeconds===60&&out.pendingSignalAfterRestore===null&&out.signalRestoreErrors.length===0);
 ck("eleven_new_FDs_closed",out.newApplicationDescriptorLedger.length===11&&out.newApplicationDescriptorLedger.every(x=>x.closeAttempted&&x.closed)&&out.allNewOwnedApplicationDescriptorsClosed);
 ck("two_helpers_fully_reaped",out.newHelperCommands.commands.length===2&&out.newHelperCommands.unknownCommandCount===0&&out.newHelperCommands.commands.every(x=>x.exitCode===0&&!x.outcomeUnknown&&x.streamsClosed&&x.completeBeforeDeadline&&x.cleanup.directChildReaped&&x.cleanup.allGroupRowsEmptyAfterReap&&x.cleanup.remainingGroupRows.length===0&&!x.cleanup.postReapSignalSent)&&out.allNewOwnedHelperCommandsClosed);
 ck("exact_two_helper_argv",JSON.stringify(out.newHelperCommands.commands.map(x=>x.argv))===JSON.stringify(go.value.allowed_helpers.map(x=>x.argv)));
 ck("held_volume_guard_closed",out.volumeGuard.allDescriptorsClosed&&out.volumeGuard.volumeUUIDVerified&&out.volumeGuard.lastAnchorCheckPassed&&out.volumeGuard.closeErrors.length===0&&out.volumeGuard.expectedVolumeDevice==="16777244");
 ck("original_plist_exact",out.originalPlist.allKeysValuesAndOriginalArgumentsExact&&out.originalPlist.sha256===go.value.original_binding.plist_sha256&&out.originalPlist.originalPythonAliasUnchanged&&!out.originalPlist.keepAlive);
 const f=out.freshLaunchctl,n=f.numericFields["last exit code"],literal=gitBlobMeta("78: EX_CONFIG");
 ck("same_original_print",f.stdoutBytes===4198&&f.stdoutSha256==="588b9781cf64a432ab5ef8378de462bc7b3b4cce64f618257c89fa82e6018ae5"&&f.sameWholeShaAsOriginalTwoPrints&&f.argumentsCount===17&&f.registrationMatchesOriginalPlist&&f.structureAccepted&&f.exitCode===0);
 ck("actual_78_failure_literal",n.present&&n.bytes===13&&n.sha256===literal.sha256&&n.kind==="exact_observed_sysexits_pair"&&n.value===78&&n.symbol==="EX_CONFIG"&&!n.isExitCodeZero&&!f.originalManagerParserAccepted&&f.originalManagerParserError.code==="typed_launchctl_integer");
 ck("not_running_one_run_no_pid",f.state==="not running"&&f.numericFields.runs.value===1&&!f.numericFields.pid.present&&!f.serviceMissingAtThisQuery);
 ck("exact_two_allowed_read_paths",out.readObservations.length===2&&JSON.stringify(out.readObservations.map(x=>x.path))===JSON.stringify(go.value.allowed_readset.map(x=>x.path)));
 const pl=out.readObservations[0],log=out.readObservations[1],ident=x=>JSON.stringify(x.beforeIdentity)===JSON.stringify(x.afterIdentity)&&JSON.stringify(x.beforeIdentity)===JSON.stringify(x.namedAfterIdentity)&&x.beforeIdentity.length===9&&x.beforeIdentity.every(y=>typeof y==="string");
 ck("public_plist_stable_whole3984",pl.stable&&pl.present&&pl.bytes===3984&&pl.sha256===go.value.original_binding.plist_sha256&&ident(pl)&&pl.closed);
 ck("stderr_actual_stable_empty",log.present&&log.stable&&log.prefixBytes===0&&!log.firstLfPresent&&log.repeatedPrefixExact&&!log.trailingBytesRead&&!log.wholePrivateLogRead&&log.beforeIdentity[6]==="0"&&ident(log)&&log.closed&&!log.unknownPrefixHashPublished);
 ck("cause_not_invented",out.stderrStartupPrefix.classification==="absent_or_incomplete"&&!out.stderrStartupPrefix.startupCauseQualified&&!out.stderrStartupPrefix.knownPublicMessageMatched&&!out.stderrStartupPrefix.rawMessagePublished&&!out.stderrStartupPrefix.unknownMessageHashPublished);
 ck("unchanged_finite_budgets",out.budget.readSyscalls===3&&out.budget.returnedBytes===3984&&out.budget.readSyscalls<=go.value.budgets.read_syscalls&&out.budget.returnedBytes<=go.value.budgets.body_returned_bytes);
 ck("original_unknown_nonclosure_preserved",out.originalOutcomeUnknownPreserved&&!out.actualServerExitQualified&&!out.registrationClosureQualified&&!f.serviceClosureQualified);
 ck("no_old_service_mutation_or_private_export",["oldServerSignalAttempted","sameOriginalLabelMutationAttempted","newFixtureStarted","privatePlanOrCapsuleRead","wholePrivateLogRead","sdkOrProviderExecuted"].every(k=>out[k]===false));
 const old=JSON.parse(r["recovery-paused-state.original.json"]),ad=JSON.parse(r["actual-adoption.actual.public.json"]),recovery=JSON.parse(r["recovery-RECOVERY.public.json"]);
 ck("old_snapshot_unchanged_still_paused",eq(r["recovery-paused-state.original.json"],recGo.value.old_snapshot)&&old.paused&&old.pending==="launchd-stderr-streams-01-start"&&old.calls[old.pending].phase==="sdk_git_archive_unresolved"&&old.calls[old.pending].called);
 ck("returned_SDK_not_repeated",eq(r["recovery-native-ack.original.sdk.json"],recGo.value.original_SDK)&&r["recovery-native-ack.original.sdk.json"]===r[calls[4].sdk.path]&&eq(r[calls[4].request.path],recGo.value.original_request)&&ad.nativeCalled===false&&ad.oldGitCreateOutcome==="UNKNOWN"&&recovery.noNativeCallRepeated&&recovery.noOldCreateReplay);
 ck("exact_separate_recovery_adoption",eq(r["adoption-root-recovery-go.original.json"],recGo)&&eq(r["adoption-request.original.json"],recGo.value.exact_adopt_request)&&ad.ok&&ad.oldContextStillPaused&&ad.archive.whole&&ad.archive.tree==="f3017221df9f6f09e1a23427b85a8c298ec471a6"&&ad.archive.entries.every(x=>eq(r["adoption-"+x.path],x)));
 ck("final_new_context_closed_old_UNKNOWN_kept",ctx.job===job&&ctx.pending===null&&ctx.activeObserver===null&&!ctx.nativeCallInFlight&&!ctx.paused&&ctx.nextStdout===8094&&ctx.nextStderr===116&&rel.historical.oldGitCreateOutcome==="UNKNOWN"&&rel.historical.oldContextByteExactAndStillPaused&&rel.historical.originalProcessStartNotRepeated&&rel.historical.originalStreamsOperationStartNotRepeated);
 return{schema:"heptabao.root-authbus-second-readonly-diagnostic-actual-qualification.v1",packet:audit,actual_job:"mac/"+job,passed:checks.every(x=>x.passed),check_count:checks.length,checks,findings:{original_stderr_size:0,original_stderr_stable:true,first_LF_present:false,startup_cause_qualified:false,last_exit_code:78,last_exit_symbol:"EX_CONFIG",state:"not running",runs:1,pid_present:false,new_descriptors_closed:11,new_helpers_reaped:2,elapsed_seconds:out.elapsedSeconds,original_registration_closed:false,historical_lineage_unknown_preserved:true,original_Git_create_unknown_preserved:true,original_returned_ACK_adopted_without_Native_replay:true,AppRole_TLS_KV_Policy_renew_revoke_qualified:false},full_replacement:false,production_cutover:false,legacy_cleanup:false,root_Runtime_calls:0};
}