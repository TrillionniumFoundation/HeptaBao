function verifyIndependentPidObservationR3OriginalEvidence(input){
 const checks=[],ck=(name,ok)=>checks.push({name,pass:ok===true}),eq=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
 const meta=(raw,pin)=>{const m=gitBlobMeta(raw);return m.blob===pin.blob&&m.bytes===pin.bytes&&m.sha256===pin.sha256;};
 const tree=(texts)=>{const b=[];for(const p of Object.keys(texts).sort()){b.push(...utf8Bytes("100644 "+p+"\0"));const h=gitBlobMeta(texts[p]).blob;for(let i=0;i<40;i+=2)b.push(parseInt(h.slice(i,i+2),16));}return sha1Bytes(utf8Bytes("tree "+b.length+"\0").concat(b));};
 const s=input.state,terminal=parseLosslessIntegers(input.authorityRaw);
 ck("original_job",s.job==="1a1b17e6d6f-fc05-7924");ck("journal_closed",s.pending===null&&s.activeObserver===null&&!s.nativeCallInFlight&&!s.paused);
 ck("eleven_original_calls",Object.keys(s.calls).length===11);ck("two_original_observers",s.completedObservers.length===2);
 const counts={process_start:0,operation_start:0,operation_status:0,operation_result:0},admissions=new Map(),statusRows=new Map(),pageRows=new Map();
 for(const [key,c] of Object.entries(s.calls)){
  const x=input.calls[key],q=JSON.parse(x.requestRaw),sdk=JSON.parse(x.sdkRaw),v=parseLosslessIntegers(x.nativeRaw),intent=JSON.parse(x.intentRaw),armed=JSON.parse(x.armedRaw);
  counts[c.kind]++;
  ck(key+":called_once_accepted",c.called===true&&c.phase==="accepted");
  ck(key+":request_whole",meta(x.requestRaw,c.requestPin)&&x.requestRaw===c.requestRaw);
  ck(key+":SDK_whole",meta(x.sdkRaw,c.sdkPin));ck(key+":native_whole",meta(x.nativeRaw,c.nativePin));
  ck(key+":SDK_nonerror_exact_native",sdk.isError!==true&&sdk.content?.length===1&&sdk.content[0].type==="text"&&sdk.content[0].text===x.nativeRaw);
  ck(key+":intent",intent.callKey===key&&intent.kind===c.kind&&eq(intent.request,c.requestPin)&&intent.maximumNativeCalls===1&&intent.nativeNotYetCalled===true);
  ck(key+":armed",armed.callKey===key&&eq(armed.request,c.requestPin)&&armed.mayHaveDispatchedAfterThisCheckpoint===true);
  ck(key+":whole_armed_Merkle",c.armed.whole===true&&tree({"request.json":x.requestRaw,"intent.json":x.intentRaw,"armed.json":x.armedRaw})===c.armed.tree);
  ck(key+":whole_SDK_Merkle",c.sdkArchive.whole===true&&tree({"original.sdk.json":x.sdkRaw})===c.sdkArchive.tree);
  if(c.kind==="process_start"){
   ck("exact_request",c.requestPin.blob==="cc19ffd0289089abf1c9d4bb0ca9034399cd4766"&&q.host==="mac"&&q.timeout_seconds===60&&typeof q.stdin==="string"&&!("stdin_text" in q));
   ck("actual_ACK",v.job.id===s.job&&v.reused===false&&v.launch.ok===true&&v.job.request_digest==="338bc717ca456dbe1c991e316011be158c63df7101aad265c080beb31b60d71a"&&v.job.request_fingerprint.$exactInteger==="3714281222688828862");
  }else if(c.kind==="operation_start"){
   ck(key+":original_job",q.operation.arguments.host==="mac"&&q.operation.arguments.job_id===s.job);
   ck(key+":fresh_observer_ACK",v.reused===false&&v.automatic_retry===false&&v.tool_name===q.operation.tool&&!admissions.has(v.operation_id));
   admissions.set(v.operation_id,{query:q,value:v});
  }else if(c.kind==="operation_status"){
   ck(key+":sameID_closed",v.operation_id===q.operation_id&&v.automatic_retry===false&&v.async_state==="completed"&&v.owned_future_active===false&&v.result_state==="stored_observed"&&v.payload_available===true);
   const a=statusRows.get(q.operation_id)||[];a.push(v);statusRows.set(q.operation_id,a);
  }else if(c.kind==="operation_result"){
   const b=unb64(v.data_base64);
   ck(key+":immutable_identity",v.operation_id===q.operation_id&&v.offset===q.offset&&v.immutable_snapshot===true&&v.payload_kind==="native_result");
   ck(key+":page_bound",q.limit===8192&&b.length<=8192&&v.total_bytes<=1048576);
   ck(key+":extent_EOF",v.next_offset===v.offset+b.length&&v.eof===(v.next_offset===v.total_bytes));
   const a=pageRows.get(q.operation_id)||[];a.push({key,value:v,bytes:b});pageRows.set(q.operation_id,a);
  }else ck(key+":supported_kind",false);
 }
 ck("exact_call_counts",eq(counts,{process_start:1,operation_start:2,operation_status:2,operation_result:6}));
 let stdout="",stderr="",outOffset=0,errOffset=0,statusObservers=0,readObservers=0;
 for(const o of s.completedObservers){
  const a=admissions.get(o.id),st=statusRows.get(o.id)||[],pages=(pageRows.get(o.id)||[]).sort((a,b)=>a.value.offset-b.value.offset),x=input.payloads[o.id];
  ck(o.id+":admission_tool",a?.value.tool_name===o.tool);ck(o.id+":status_closed",st.length===1&&st.every(x=>x.tool_name===o.tool)&&o.completedInactive===true);
  ck(o.id+":page_count",pages.length===o.pages&&pages.length<=128);
  let offset=0,total=null,digest=null,bytes=[];
  for(const p of pages){ck(p.key+":contiguous",p.value.offset===offset);bytes.push(...p.bytes);offset=p.value.next_offset;if(total===null){total=p.value.total_bytes;digest=p.value.result_sha256;}ck(p.key+":stable_total_digest",p.value.total_bytes===total&&p.value.result_sha256===digest);}
  const raw=utf8Text(bytes),p=parseLosslessIntegers(raw);
  ck(o.id+":whole_payload",offset===total&&pages.at(-1).value.eof===true&&raw===x.payloadRaw&&meta(raw,o.payload)&&gitBlobMeta(raw).sha256===digest);
  ck(o.id+":payload_tree",tree({"payload.original.json":raw})===o.payloadTree);
  ck(o.id+":native_envelope",p.resultType==="complete"&&p.isError===false&&p.content?.length===1&&p.content[0].type==="text"&&p.content[0].text===x.nativeRaw);
  ck(o.id+":native_whole",meta(x.nativeRaw,o.nativeText));
  const v=parseLosslessIntegers(x.nativeRaw);ck(o.id+":native_job",v.job_id===s.job);
  if(o.tool==="process_status"){statusObservers++;ck(o.id+":authority",x.nativeRaw===input.authorityRaw);}
  else if(o.tool==="process_read"){
   readObservers++;
   ck(o.id+":native_read_cap",a.query.operation.arguments.limit===16384);
   for(const name of ["stdout","stderr"]){const z=v[name],b=[];for(let i=0;i<z.bytes_hex.length;i+=2)b.push(parseInt(z.bytes_hex.slice(i,i+2),16));
    ck(o.id+":"+name+":hex_text",z.bytes_hex.length===b.length*2&&utf8Text(b)===z.text);
    ck(o.id+":"+name+":extent",z.offset===a.query.operation.arguments[name+"_offset"]&&b.length<=16384&&z.next_offset===z.offset+b.length&&z.size===terminal.log_bytes[name].stored);
    ck(o.id+":"+name+":contiguous",z.offset===(name==="stdout"?outOffset:errOffset));ck(o.id+":"+name+":EOF",z.eof===(z.next_offset===z.size));
    if(name==="stdout"){stdout+=z.text;outOffset=z.next_offset;}else{stderr+=z.text;errOffset=z.next_offset;}
   }
  }else ck(o.id+":expected_observer",false);
 }
 ck("observer_counts",statusObservers===1&&readObservers===1);
 ck("complete_original_streams",stdout===input.stdoutRaw&&stderr===input.stderrRaw&&outOffset===11778&&errOffset===0);
 ck("terminal_authority",terminal.state==="failed"&&terminal.exit_code===1&&terminal.output_complete===true&&terminal.output_durable===true&&terminal.terminal_publication_confirmed===true&&!terminal.timed_out);
 ck("terminal_full_lengths",terminal.log_bytes.stdout.seen===11778&&terminal.log_bytes.stdout.stored===11778&&terminal.log_bytes.stderr.seen===0&&terminal.log_bytes.stderr.stored===0&&!terminal.log_truncated.stdout&&!terminal.log_truncated.stderr&&terminal.log_synced.stdout&&terminal.log_synced.stderr);
 const r=JSON.parse(stdout);
 ck("completed_observation_unknown_preserved",r.ok===false&&r.observationComplete===true&&r.outcomeUnknown===true&&r.stage==="complete"&&!Object.hasOwn(r,"error"));
 ck("managed_scope_unknown_preserved",r.registrationClosureClaimed===false&&r.currentManagedScopeStillUnknown===true&&!r.managedProcessReaped&&!r.bootstrapBootoutOrSignalCalled&&!r.pidExitOrReapClaimed);
 ck("history_preserved",!r.historicalFailedPrintBytesRecovered&&!r.historicalFailureRewritten&&!r.currentIdentityIsOriginalReadyIdentityClaimed);
 ck("read_only_scope",!r.privatePlansCapsuleOrCredentialsRead&&!r.sdkFactoryProviderOrRefreshCalled&&!r.newFilesOrDirectoriesCreated&&!r.productBusinessOrCleanupDispatched&&!r.stderrBodyRead&&!r.stdioTailExported&&r.noReadsBeyondFirstBoundedPrefix===true);
 ck("original_budget",r.sharedSeconds===45&&r.helperAdmissionEndSeconds===35&&r.outerSeconds===60&&r.deadlineMetAfterClosure&&r.elapsedSeconds<45);
 ck("all22_FDs",r.io.fdRows.length===22&&r.io.fdRows.every(x=>x.closeAttempted&&x.closed&&x.closeError===null)&&r.io.allClosed&&r.allReturnedApplicationFdsClosed&&r.io.openLedger.pending===0&&r.io.openLedger.registrationUnknown===false&&r.io.openLedger.registered===22);
 ck("two_direct_helpers",r.directHelperAttempts===2&&r.directHelpersReturnedIntoLedger===2&&r.allDirectHelpersClosed&&r.directHelpers.allOwnedCommandsStopped&&r.directHelpers.unknownCommandCount===0&&r.directHelpers.commands.length===2);
 ck("both_helpers_exact_missing",r.directHelpers.commands.every(x=>x.exitCode===113&&x.stdoutBytes===0&&x.stderrBytes===115&&x.streamsClosed&&!x.outcomeUnknown&&x.argvExact&&x.cleanup.ok&&x.cleanup.directChildReaped&&x.cleanup.signalAttemptCount===0));
 ck("signals_restored",r.signalRestoreErrors.length===0&&r.pendingSignalAfterRestore===null);
 ck("two_fresh_missing_registration_observations",r.prints.length===2&&r.prints.every((x,i)=>x.ordinal===i+1&&x.knownCommand&&x.registrationAbsent===true&&x.projection===null)&&r.currentLabelAbsentBoth===true);
 ck("two_independent_missing_classifications",r.labelAndFixedPidObservationsIndependent===true&&eq(r.registrationMappings,[{classification:"exact_missing_registration",sameFixedRunningPid:false},{classification:"exact_missing_registration",sameFixedRunningPid:false}]));
 const m=r.currentPidMetadata;
 ck("complete_finite_numeric_sampling",r.currentPidSamplingCompleted===true&&m.fixedPid===32527&&m.numericCalls===6&&m.pathCalls===0&&m.directChildCountCalls===0&&m.rows.length===6&&m.allAttemptedCallsReturned===true);
 ck("self_complete_136_errno0",m.selfCrosschecked===true&&m.rows[0].pid===m.rows[1].pid&&m.rows[0].pid!==32527&&m.rows.slice(0,2).every(x=>x.kind==="bsdinfo-arg1"&&x.attempted&&x.returned&&x.result===136&&x.errno===0));
 ck("four_fixed_target_ESRCH_results",m.rows.slice(2).every(x=>x.pid===32527&&x.kind==="bsdinfo-arg1"&&x.attempted&&x.returned&&x.result===0&&x.errno===3));
 ck("ordinal_sample_order",m.rows.every((x,i)=>x.ordinal===i));
 ck("two_ESRCH_pairs_no_identity",m.pairs.length===2&&m.pairs.every((x,i)=>x.ordinal===i+1&&x.pid===32527&&x.classification==="esrch_returned_twice"&&x.before===null&&x.after===null&&x.beforeClassification==="esrch_returned"&&x.afterClassification==="esrch_returned"&&x.sameLifetimeWithinPair===false&&x.qualifiedKnownPython===false&&x.pidExitOrHistoricalReapClaimed===false));
 ck("no_path_or_child_read_after_incomplete_first",m.pairs.every(x=>x.imageMatches===null&&x.directChildCount===null&&x.pathResult==="not_attempted_without_complete_before"&&x.childCountResult==="not_attempted_without_complete_before"));
 ck("no_unknown_path_child_argv_exports",m.rawUnknownPathPublished===false&&m.childPidsPublished===false&&m.childProcessesFollowed===false&&m.otherProcessArgumentsRead===false&&m.bsdExitStatusIsNotLaunchdExitCode===true);
 ck("identity_unknown_not_absence_qualification",r.currentIdentityKernelMetadataComplete===false&&r.currentIdentityQualifiedForFutureCleanupReview===false&&r.currentKnownPythonIdentityMatched===false&&r.sameCurrentLifetimeAcrossSamples===false&&r.currentIdentityOutcomeUnknown===true&&r.currentLabelMappingSameFixedPidBoth===false);
 ck("fixed_public_files_all_observed",eq(Object.keys(r.publicFiles).sort(),["exec-ready","ready","stderr-metadata","stdout-first-lf"]));
 ck("ready_exact_ENOENT",["ready","exec-ready"].every(k=>r.publicFiles[k].present===false&&r.publicFiles[k].errno===2&&r.publicFiles[k].identity===null&&r.publicFiles[k].projection===null&&r.publicFiles[k].contentSha256Published===false));
 ck("stdout_present_empty_firstLF",r.publicFiles["stdout-first-lf"].present===true&&r.publicFiles["stdout-first-lf"].empty===true&&r.publicFiles["stdout-first-lf"].identity[6]==="0"&&r.publicFiles["stdout-first-lf"].prefixBytesRead===0&&r.publicFiles["stdout-first-lf"].projection===null&&r.publicFiles["stdout-first-lf"].contentSha256Published===false);
 ck("stderr_metadata_only_empty",r.publicFiles["stderr-metadata"].present===true&&r.publicFiles["stderr-metadata"].identity[6]==="0"&&r.publicFiles["stderr-metadata"].bodyRead===false&&r.publicFiles["stderr-metadata"].contentSha256Published===false);
 ck("three_exact_public_controls",r.pinnedInputs.length===3&&r.pinnedInputs[0].bytes===34640&&r.pinnedInputs[1].bytes===14052&&r.pinnedInputs[2].bytes===3970);
 ck("no_write_and_exact_read_counts",r.io.counts.metadata===253&&r.io.counts.readBytes===52662&&r.io.counts.readCalls===6&&r.io.counts.writeBytes===0&&r.io.counts.writeCalls===0);
 return {schema:"heptabao.current-home-r2-independent-pid-original-chain-verification.r3",passed:checks.every(x=>x.pass),checkCount:checks.length,checks,nativeCalls:counts,statusObservers,readObservers,stdoutBytes:gitBlobMeta(stdout).bytes,stderrBytes:gitBlobMeta(stderr).bytes,scope:"completed_current_bounded_observations_and_own_closure_historical_managed_UNKNOWN",observationComplete:true,currentIdentityQualified:false,managedScopeQualifiedClosed:false,historicalReapQualified:false,productSuccess:false,newNativeCalls:0};
}
