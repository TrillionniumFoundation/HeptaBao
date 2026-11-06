function verifyRootCurrentIdentityActual(files,go,author) {
  const rows=[],ck=(name,v)=>{rows.push({name,passed:v===true});if(v!==true)throw Error(name);},eq=(x,y)=>JSON.stringify(x)===JSON.stringify(y);
  const r=JSON.parse(files["actual--stdout.original.txt"]),t=parseLosslessIntegers(files["actual--authority.original.json"]),start=parseLosslessIntegers(files["actual--start.native.original.json"]),rel=JSON.parse(files["RELEASE.public.json"]),st=JSON.parse(files["journal-final-state.original.json"]);
  ck("full_original159_reproduced",author.exact&&author.value.passed&&author.value.checkCount===159);
  ck("GO_original_whole",files["reference-GO.original.json"]===go.text&&gitBlobMeta(go.text).blob==="a7212b6b7a17c7e21bed8e51ecdff50b27a5b561");
  ck("exact_original_job",start.job.id===t.job_id&&t.job_id==="1a1b148990b-fc05-7784"&&start.reused===false);
  ck("lossless_fingerprint",start.job.request_fingerprint.$exactInteger==="17969954890120134621");
  ck("exact_typed_digest",start.job.request_digest==="f9621ac37f677fdd6c411224005fac66fac40a9517ceacffb2d0c83af8dd8f64");
  ck("terminal_failed_not_success",t.state==="failed"&&t.exit_code===1&&t.timed_out===false&&r.ok===false);
  ck("whole_durable_streams",t.output_complete===true&&t.output_durable===true&&t.terminal_publication_confirmed===true&&!t.log_truncated.stdout&&!t.log_truncated.stderr);
  ck("whole_exact_stdout",gitBlobMeta(files["actual--stdout.original.txt"]).sha256==="31faf614bcb64eeb5e6339bd73ce7025a92df424ef7a846c728ebee548fd3040"&&t.log_bytes.stdout.stored===6920);
  ck("stderr_empty",files["actual--stderr.original.txt"]===""&&t.log_bytes.stderr.stored===0);
  ck("journal_no_active_call_future",st.pending===null&&st.activeObserver===null&&st.nativeCallInFlight===false&&st.completedObservers.length===2);
  ck("one_print_only",r.prints.length===1&&r.prints[0].registrationAbsent===true&&r.prints[0].projection===null);
  ck("original_exact_print_exit113",r.directHelpers.commands.length===1&&r.directHelpers.commands[0].argvExact&&r.directHelpers.commands[0].exitCode===113&&r.directHelpers.commands[0].stdoutBytes===0);
  ck("mapping_refusal_stage",r.error.code==="current_pid_exact_registration_mapping"&&r.stage==="fixed_current_pid_before");
  ck("no_PID_sample_or_public_file_result",r.currentPidMetadata===null&&eq(r.publicFiles,{}));
  ck("identity_and_managed_unknown_preserved",r.currentIdentityOutcomeUnknown&&r.currentManagedScopeStillUnknown&&!r.currentIdentityQualifiedForFutureCleanupReview&&!r.managedProcessReaped&&!r.pidExitOrReapClaimed&&!r.registrationClosureClaimed);
  ck("helper_closed_reaped",r.allDirectHelpersClosed&&r.directHelpers.commands[0].cleanup.directChildReaped&&r.directHelpers.commands[0].streamsClosed);
  ck("17_application_FDs_closed",r.allReturnedApplicationFdsClosed&&r.io.fdRows.length===17&&r.io.fdRows.every(x=>x.closed&&x.closeError===null)&&r.io.openLedger.pending===0&&!r.io.openLedger.registrationUnknown);
  ck("no_write_or_signal",r.io.counts.writeBytes===0&&r.io.counts.writeCalls===0&&!r.bootstrapBootoutOrSignalCalled&&!r.newFilesOrDirectoriesCreated&&r.directHelpers.commands[0].cleanup.signalAttemptCount===0);
  ck("no_private_or_business_effect",!r.privatePlansCapsuleOrCredentialsRead&&!r.productBusinessOrCleanupDispatched&&!r.sdkFactoryProviderOrRefreshCalled);
  ck("bounded_deadlines",r.sharedSeconds===45&&r.helperAdmissionEndSeconds===35&&r.outerSeconds===60&&r.deadlineMetAfterClosure);
  ck("release_not_managed_closure",rel.observationLaneReleased===true&&rel.managedScope.currentManagedScopeStillUnknown===true&&rel.managedScope.pidExitOrReapClaimed===false);
  return {schema:"heptabao.root-current-identity-original-qualification.r1",passed:true,checks:rows.length,rows,originalFullTree:"206c42ff194bb7d43bea3636d3d504968a4b68a7",original159Reproduced:true,nativeObservationLaneReleased:true,currentPIDQualified:false,historicalManagedScopeClosed:false,fullReplacement:false};
 }