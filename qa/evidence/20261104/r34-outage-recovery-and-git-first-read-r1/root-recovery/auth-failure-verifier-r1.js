function qualifyOriginalAuthFailure(){
 const f=load("r34_auth_full_stdout"),r=load("r34_auth_release"),a=load("r34_auth_worker_authority"),source=load("r34_review_auth_launchd");
 const v=f.value,q=r.value,t=a.value,c=v.ownedCommands.commands,reg=v.manager.registrations[0],checks=[];
 function check(name,ok){checks.push({name,passed:ok===true});}
 const canonical=x=>JSON.stringify(x,(_k,z)=>z&&typeof z==="object"&&!Array.isArray(z)?Object.fromEntries(Object.keys(z).sort().map(k=>[k,z[k]])):z);
 check("whole_original_stdout_bytes",gitBlobMeta(f.text).bytes===132132);
 check("whole_original_stdout_sha256",gitBlobMeta(f.text).sha256==="feae46e33bc62427b8317780cf38ca73acd80124b1ad157caa20cbb0f3677748");
 check("same_original_job",t.job_id==="1a1ae51309d-fc05-5ef8");
 for(const k of ["output_complete","output_durable","terminal_publication_confirmed","audit_recorded"])check("authority_"+k,t[k]===true);
 for(const k of ["automatic_retry","cancelled","timed_out"])check("authority_"+k+"_false",t[k]===false);
 check("original_failed_exit_1",t.state==="failed"&&t.exit_code===1);
 for(const [k,n] of [["stdout",132132],["stderr",0]]){check(k+"_actual_lengths",t.log_bytes[k].seen===n&&t.log_bytes[k].stored===n);check(k+"_synced_untruncated",t.log_synced[k]===true&&t.log_truncated[k]===false&&t.log_errors[k]===null);}
 check("actual_failure",v.ok===false&&v.outcomeUnknown===true&&v.errorType==="ManagerRefused"&&v.errorCode===null);
 check("exact_failure_frames",canonical(v.errorFrames)===canonical([{file:"mac_current_outer_wal_r1.py",line:1030},{file:"mac_owned_launchd_r3.py",line:374},{file:"mac_owned_launchd_r3.py",line:263},{file:"mac_owned_launchd_r3.py",line:143},{file:"mac_owned_launchd_r3.py",line:76},{file:"mac_owned_launchd_r3.py",line:39}]));
 const sourceText=typeof source==="string"?source:source.text;
 check("bound_manager_source",gitBlobMeta(sourceText).blob==="96fe347f2edbda1718b2fd683041b88be8f41e30");
 check("line_76_is_typed_integer",sourceText.split("\n")[75].includes("typed_launchctl_integer"));
 check("line_73_is_separate_arguments_check",sourceText.split("\n")[72].includes("complete_launchctl_arguments"));
 check("no_completed_business_operations",v.manager.completedOperationCount===0&&v.ownedPhases.length===0&&v.checks.length===0);
 check("single_registration",v.manager.registrations.length===1);
 check("original_exact_label",reg.label==="org.heptabao.qa.mac-authbus-4e808-owner-r1.server");
 check("single_original_bootstrap",Object.keys(reg.attempts).length===1&&reg.attempts.bootstrap.attempted===true&&reg.attempts.bootstrap.complete===true&&reg.attempts.bootstrap.exitCode===0);
 check("cleanup_integer_parser_error",reg.cleanupErrorCode==="typed_launchctl_integer"&&reg.cleanupErrorType==="ManagerRefused");
 check("wrapper_exec_unobserved",reg.wrapperIdentity===null&&reg.execIdentity===null&&reg.knownOwnedGroups.length===0);
 check("registration_and_lineage_not_closed",reg.registrationClosed===false&&reg.lineagesClosed===false&&v.manager.allRegistrationsClosed===false&&v.manager.allKnownLineagesClosed===false&&v.allOwnedRegistrationsLineagesHelpersClosed===false);
 check("single_shared_helper_ledger",canonical(v.ownedCommands)===canonical(v.manager.ownedCommands));
 check("eleven_unique_helpers",c.length===11&&new Set(c.map(x=>x.pid)).size===11);
 check("helpers_known_closed",v.ownedCommands.allOwnedCommandsStopped===true&&v.ownedCommands.unknownCommandCount===0);
 for(let i=0;i<c.length;i++){const x=c[i];check("helper_"+i+"_reaped_empty_known_streams_closed",x.streamsClosed===true&&x.outcomeUnknown===false&&x.cleanup?.directChildReaped===true&&x.cleanup?.allGroupRowsEmptyAfterReap===true&&x.cleanup?.remainingGroupRows?.length===0&&x.cleanup?.outcomeUnknown===false);}
 check("all_34_outer_descriptors_closed",v.outerDescriptorClosure.descriptorCount===34&&v.outerDescriptorClosure.allOuterReadDescriptorsClosed===true&&v.outerDescriptorClosure.closeErrors.length===0);
 check("ephemeral_socket_closed",v.outerDescriptorClosure.allEphemeralPortReservationSocketsClosed===true&&v.outerDescriptorClosure.portReservation.closed===true);
 check("finite_inputs_closed",v.finiteInputClosure.allOwnedInputDescriptorsClosed===true&&v.finiteInputClosure.closeErrors.length===0);
 check("T5_descriptors_closed",v.heldT5Final.allDescriptorsClosed===true&&v.heldT5Final.closeErrors.length===0);
 check("manager_read_descriptors_closed",v.manager.allManagerReadDescriptorsClosed===true);
 check("public_proof_capture_libraries_closed",v.allPublicProofAndCaptureLibraryClosuresKnown===true);
 check("original_deadline_flag",v.originalOuterDeadlineMetAfterAllClosure===true);
 check("failure_release_matches_frames",canonical(q.failure.errorFrames)===canonical(v.errorFrames));
 check("specific_rejected_literal_unknown",q.failure.integerFieldActuallyRejected===null&&q.failure.firstFailureCauseValueNotReconstructed===true&&q.failure.originalPrintRawAvailableInReport===false);
 check("original_prints_hash_only",q.registration.originalPrints.length===2&&q.registration.originalPrints.every(x=>x.exitCode===0&&x.stdoutBytes===4198&&x.stdoutSha256==="588b9781cf64a432ab5ef8378de462bc7b3b4cce64f618257c89fa82e6018ae5"));
 for(const k of ["credentialValuesPublished","productionChangedByController","productionServiceOperationDispatched","providerRequested","j3160Contacted","allAccountsQualified","fullReplacementQualified","currentProviderAvailabilityQualified"])check("actual_"+k+"_false",v[k]===false);
 const obs=q.readClosure.allOriginalObservers;
 check("ten_original_observers",obs.length===10);
 check("all_observers_closed_original_payloads_archived",obs.every(x=>x.completed===true&&x.stored===true&&x.ownedFutureActive===false&&x.fullPayloadVerified===true&&x.archiveWholeVerified===true));
 check("fifty_five_original_pages",obs.reduce((n,x)=>n+x.pages.length,0)===55);
 check("continuous_original_stdout_EOF",q.readClosure.stdoutContinuousBytes===132132&&q.readClosure.stdoutEOF===true&&q.readClosure.stdoutHexEqualsText===true);
 check("continuous_empty_stderr_EOF",q.readClosure.stderrContinuousBytes===0&&q.readClosure.stderrEOF===true&&q.readClosure.stderrHexEqualsText===true);
 check("lane_idle",q.readClosure.currentRuntimeCalls===0&&q.readClosure.currentNativeFutures===0);
 return {schema:"heptabao.root-original-AuthBus-failure-qualification.v1",qualified_original_complete_failure:checks.every(x=>x.passed),checks,original_stdout:{blob:f.blob,bytes:f.bytes,sha256:f.sha256},original_authority:{blob:a.blob,bytes:a.bytes,sha256:a.sha256},owner_release:{blob:r.blob,bytes:r.bytes,sha256:r.sha256},failure:"typed launchctl integer parser frame; rejected field and literal remain unobserved",actual_registration_closed:false,actual_wrapper_or_exec_identity_observed:false,helper_and_descriptor_closure_qualified:true,AuthBus_business_qualified:false,full_replacement:false,production_cutover:false,cleanup:false,root_Runtime_calls:0,diagnostic_required_before_cleanup_or_worker_rerun:true};
}