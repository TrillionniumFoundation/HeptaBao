function verifyActual(i,sha256,sha1){
 const checks=[];const need=(ok,caseName)=>{checks.push({case:caseName,passed:!!ok});if(!ok)throw Error(caseName)};
 const utf8=s=>unescape(encodeURIComponent(s));
 const pin=s=>{const b=utf8(s);return {bytes:b.length,sha256:sha256(b),blob:sha1("blob "+b.length+"\0"+b)}};
 const same=(x,y)=>JSON.stringify(x)===JSON.stringify(y);
 for(const [name,x] of Object.entries(i.rawRecords))need(same(pin(x.raw),{bytes:x.bytes,sha256:x.sha256,blob:x.blob}),"raw_pin."+name);
 for(const [name,sdk,native] of i.sdkPairs){const c=JSON.parse(sdk).content.filter(x=>x.type==="text");need(c.length===1&&c[0].text===native,"sdk_native_exact."+name);}
 const request=JSON.parse(i.rawRecords.request.raw),go=JSON.parse(i.rawRecords.go.raw),ack=JSON.parse(i.rawRecords.ack.raw),authority=JSON.parse(i.rawRecords.authority.raw),stream=JSON.parse(i.rawRecords.read.raw),r=JSON.parse(i.rawRecords.stdout.raw);
 need(request.host==="mac"&&request.executable==="/opt/homebrew/bin/python3"&&request.cwd==="/Users/qianqi"&&request.timeout_seconds===60,"exact_dispatch");
 need(request.idempotency_key==="heptabao-mac-captured-harness-predicates-2b999a66-20261105-r1","fixed_key");
 need(same(request.args,["-I","-S","-B","-c",i.source]),"exact_source_in_argv");
 need(go.request.blob===i.rawRecords.request.blob&&go.source.sha256===pin(i.source).sha256,"root_go_exact_source_request");
 need(ack.reused===false&&ack.job.host===request.host&&ack.job.executable===request.executable&&ack.job.cwd===request.cwd&&same(ack.job.args,request.args)&&ack.job.idempotency_key===request.idempotency_key,"ack_exact_binding_no_reuse");
 need(ack.job.launch_state==="launched"&&ack.launch.ok===true&&ack.job.launch_error===null,"ack_launched");
 need(ack.job.id===authority.job_id&&authority.job_id===stream.job_id,"one_original_job");
 need(authority.exit_code===0&&authority.state==="succeeded"&&authority.output_complete===true&&authority.output_durable===true&&authority.terminal_publication_confirmed===true,"known_zero_full_durable");
 need(authority.cancelled===false&&authority.timed_out===false&&authority.automatic_retry===false,"no_timeout_cancel_retry");
 for(const name of ["stdout","stderr"]){
  const s=stream[name],raw=i.rawRecords[name].raw,b=utf8(raw);
  need(s.offset===0&&s.next_offset===b.length&&s.size===b.length&&s.eof===true,"whole_stream_offsets."+name);
  need(s.text===raw&&s.bytes_hex===Array.from(b,c=>c.charCodeAt(0).toString(16).padStart(2,"0")).join(""),"whole_hex_text."+name);
  need(authority.log_bytes[name].seen===b.length&&authority.log_bytes[name].stored===b.length&&authority.log_errors[name]===null&&authority.log_truncated[name]===false&&authority.log_synced[name]===true,"authority_stream."+name);
 }
 need(i.rawRecords.stderr.bytes===0,"empty_stderr");
 need(r.schema==="heptabao.mac-captured-harness-predicate-observation.r1"&&r.observationComplete===true,"diagnostic_complete");
 need(r.errorCode===null&&r.errorType===null&&r.errno===null&&r.failureStage===null,"diagnostic_no_error");
 need(r.pendingSignal===null&&r.handlerRestoreErrors.length===0&&r.authoritativeExitZeroAfterHandlerRestoreRequired===true,"handler_restore_and_authority");
 need(r.newSoftSeconds===5&&r.newSupervisorSeconds===60&&r.elapsedSeconds>=0&&r.elapsedSeconds<5&&r.deadlineMetAfterClosure===true,"original_deadline_after_closure");
 need(r.sourceRuntimeJobId===i.originRuntimeJob&&r.sourceRuntimeStdoutSha256===i.originRuntimeSha&&r.sourceEntryStdoutSha256===i.originEntrySha,"exact_failed_origin");
 need(r.capsulePath===i.capsule.path&&r.capsuleBytes===i.capsule.bytes&&r.capsuleSha256===i.capsule.sha256,"exact_capsule_bytes_hash_path");
 const c=r.closure;
 need(same(c.capsuleIdentity,i.capsule.identity),"capsule_all_nine_strings");
 need(c.allOwnedDescriptorsClosed===true&&c.closeErrors.length===0&&c.lastNamedFullNineFence===true,"all_fd_closure_known");
 need(c.descriptorsRegistered===9&&c.descriptorLedger.length===9,"nine_registered_descriptors");
 need(c.metadataCalls===72&&c.readCalls===4&&c.privateBytesRead===195155,"actual_original_io_counts");
 need(same(c.descriptorLedger.map(x=>x.path),i.parentPaths.concat([i.capsule.path])),"exact_descriptor_paths");
 for(const [n,x] of c.descriptorLedger.entries())need(x.created===true&&x.closeAttempted===true&&x.closed===true&&x.closeError===null&&x.kind===(n<8?"directory":"private_capsule"),"descriptor_once_closed."+n);
 need(c.parentObservations.length===8&&same(c.parentObservations.map(x=>x.path),i.parentPaths),"eight_parent_observations");
 for(let n=0;n<3;n++)need(same(c.parentObservations[n],i.anchors[n]),"original_anchor_nine."+n);
 for(let n=0;n<8;n++)need(c.parentObservations[n].identity.length===9&&c.parentObservations[n].identity.every(x=>typeof x==="string"&&/^[0-9]+$/.test(x)),"parent_nine_string_shape."+n);
 need(c.t5UuidRemeasuredInThisDiagnostic===false,"no_new_uuid_claim");
 for(const key of ["captureOrFixtureReplayed","currentProductionFilesOpened","currentSqliteOpened","filesystemWritesByProgram","historicalUnknownsChanged","libraryOrSdkImported","networkUsed","privateCapsuleBodyPublished","providerOrJ3160","runtimeQualificationGranted","subprocessStarted"])need(r[key]===false,"scope_false."+key);
 const p=r.predicateProjection;
 need(p.registryPluginCount===75&&p.originalEnabledHarnessOwnerCount===2&&p.enabledHarnessOwners.length===2,"actual_registry_denominator");
 need(p.actualSelectedHarnessSetKnown===false&&p.enabledDoesNotMeanSelected===true&&p.unselectedHarnessClaimed===false,"selection_unknown");
 need(p.pluginIdsPublished===false&&p.privateDocumentBodyPublished===false&&p.unknownCodePathsPublished===false&&p.rootGuardRelaxed===false,"bounded_public_projection");
 need(p.firstCompositeRejectionOrdinal===0&&r.allOriginalPredicatesPassed===false,"original_composite_known_false");
 for(const [n,x] of p.enabledHarnessOwners.entries()){
  need(x.enabledOrdinal===n&&x.registryOrdinal===[22,68][n]&&x.originalEnabledStartupAgentHarnesses===true,"enabled_original_order."+n);
  need(x.actualSelectedForCurrentAgents===null&&x.selectionEvidence==="NOT_OBSERVED_NO_NATIVE_WORKER_RAN","owner_selected_unknown."+n);
  need(x.identifierIsString===true&&x.identifierMatchesOriginalRegex===true&&x.rootConstructionSupported===true&&x.rootIsAbsolute===true&&x.rootIsNormalized===true,"other_original_clauses_true."+n);
  need(x.rootInOriginalNpmProjectsNamespace===(n===1)&&x.originalCompositePredicate===(n===1),"namespace_only_actual_failure."+n);
  need(x.rootEqualsAlreadyPinnedCodexRoot===(n===1)&&x.publicCodeRoot===(n===1?i.knownCodexRoot:null),"approved_root_literal_only."+n);
  for(const key of ["identifierValueSha256","rootValueSha256","agentHarnessesMetadataSha256"])need(/^[0-9a-f]{64}$/.test(x[key]),"public_digest."+n+"."+key);
 }
 need(same(p.configuredFiveAgentModelBindings.map(x=>x.agentId),["main","trnm","hepta-ui","hepta","hepta-backend"]),"five_original_agents");
 for(const x of p.configuredFiveAgentModelBindings)need(x.actualSelectedHarness===null&&x.selectorExecuted===false&&x.matchesAlreadyPublicConfigModel===true&&same(x.alreadyPublicModel,{id:"gpt-5.6-sol",provider:"openai"})&&/^[0-9a-f]{64}$/.test(x.declaredModelSha256),"agent_model_not_selection."+x.agentId);
 return {schema:"heptabao.mac-captured-harness-predicate-actual-review.r1",qualification:"PASS_READONLY_DIAGNOSTIC_ONLY_ORIGINAL_COMPOSITE_FALSE",actualJobId:authority.job_id,checksPassed:checks.length,checks,actualEnabledOwnerCount:2,firstRegistryOrdinal:22,firstFailure:"rootInOriginalNpmProjectsNamespace",otherOriginalClausesPassed:true,selectedHarnessSet:"NOT_OBSERVED",newHostRequestsByVerifier:0,privateBodyReadByVerifier:false,originalRuntimeReplayed:false,currentRuntimeQualified:false,productionQualified:false};
}
