function verifyMacCurrentWalTerminal(files,sha,h1,decode,topTokens){
 const checks=[];
 function need(caseName,condition){if(!condition)throw Error(caseName);checks.push({case:caseName,passed:true});}
 function binary(s){return unescape(encodeURIComponent(s));}
 function pin(s){const b=binary(s);return{bytes:b.length,sha256:sha(b),blob:h1("blob "+b.length+"\0"+b)};}
 function json(path){return JSON.parse(files[path]);}
 function pair(stem){const sdk=json(stem+".sdk-snapshot.json"),raw=files[stem+".native.json"],blocks=sdk.content.filter(c=>c.type==="text");need("sdk_native."+stem,sdk.isError!==true&&blocks.length===1&&blocks[0].text===raw);return JSON.parse(raw);}
 const go=json("root-go.original.public.json"),req=json("request.original.public.json"),intent=json("intent.public.json"),ack=pair("actual/start"),authority=pair("actual/authority"),r=json("actual/stdout.original.json"),child=json("entry-before/stdout.original.json"),anchor=json("references/t5-anchor.original.json");
 const requestPin=pin(files["request.original.public.json"]);
 need("one_exact_runtime_go",go.decision==="GO_ONE_EXACT_ISOLATED_RUNTIME"&&go.maximum_submissions===1&&go.exact_request.blob===requestPin.blob&&go.exact_request.sha256===requestPin.sha256&&go.exact_request.bytes===requestPin.bytes);
 need("external_intent_exact",intent.exactRequest.blob===requestPin.blob&&intent.rootGo.blob===pin(files["root-go.original.public.json"]).blob&&intent.maximumProcessStartCalls===1);
 need("fixed_job_and_key",ack.job.id==="1a1abb090b9-fc05-4fc5"&&authority.job_id===ack.job.id&&ack.job.idempotency_key===req.idempotency_key&&go.idempotency_key===req.idempotency_key);
 need("exact_start_binding",ack.job.host===req.host&&req.host==="mac"&&ack.job.executable===req.executable&&ack.job.cwd===req.cwd&&JSON.stringify(ack.job.args)===JSON.stringify(req.args));
 need("one_fresh_submission",ack.reused===false&&ack.launch.ok===true&&ack.job.launch_error===null);
 need("original_outer1080",req.timeout_seconds===1080);
 need("known_terminal_exit1",authority.exit_code===1&&authority.state==="failed"&&authority.output_complete===true&&authority.output_durable===true&&authority.terminal_publication_confirmed===true&&authority.timed_out===false&&authority.cancelled===false);
 let whole="",chunkCount=0;
 for(const off of [0,16384,32768,49152,65536,81920]){
   const p=pair("actual/read-"+String(off).padStart(5,"0")),s=p.stdout,e=p.stderr;
   const b=s.bytes_hex.match(/../g)?.map(x=>String.fromCharCode(parseInt(x,16))).join("")??"";
   need("page."+off,p.job_id===ack.job.id&&s.offset===off&&s.next_offset===Math.min(off+16384,91043)&&s.size===91043&&s.eof===(off===81920)&&b.length===s.next_offset-off&&b===binary(s.text));
   need("stderr."+off,e.offset===0&&e.next_offset===0&&e.size===0&&e.eof===true&&e.bytes_hex===""&&e.text==="");
   whole+=s.text;chunkCount++;
 }
 need("whole91043",whole===files["actual/stdout.original.json"]&&pin(whole).bytes===91043&&pin(whole).sha256==="8d3f357bf75b11c1ce37e34bb7304460271a1cb74d1bd5200031d2f2bd3f9302");
 for(const s of ["stdout","stderr"])need("authority_stream."+s,authority.log_bytes[s].stored===(s==="stdout"?91043:0)&&authority.log_bytes[s].seen===authority.log_bytes[s].stored&&authority.log_synced[s]===true&&authority.log_truncated[s]===false&&authority.log_errors[s]===null);
 const info=pair("entry-before/file-info"),read=pair("entry-before/read"),rq=json("entry-before/read.request.json"),body=decode(read.data_base64);
 need("entry_info_full",info.size===30308&&info.sha256==="88883315e4d9f343cbbc967224fc7a177f5cc8e216d09f811ef1c59c5de5fbd4"&&info.mode===384&&info.metadata.uid===501&&info.metadata.gid===20&&info.metadata.link_count===1);
 need("entry_whole_pinned_read",rq.expected_version===info.version&&rq.path===info.path&&rq.offset===0&&rq.limit===30308&&read.path===info.path&&read.version===info.version&&read.offset===0&&read.next_offset===30308&&read.size===30308&&read.eof===true&&body===binary(files["entry-before/stdout.original.json"])&&sha(body)===info.sha256&&read.chunk_sha256===info.sha256);
 const capturesToken=topTokens(whole).captureReports,attemptToken=capturesToken.trim().slice(1,-1);
 need("one_capture_original_token_exact",r.captureReports.length===1&&topTokens(attemptToken).report===files["entry-before/stdout.original.json"].trim());
 need("known_outer_input_refusal",r.ok===false&&r.errorType==="InputRefused"&&r.errorCode===null&&r.outcomeUnknown===false&&r.elapsedSeconds<900&&r.originalOuterDeadlineMetAfterAllClosure===true);
 need("exact_public_failure_frames",JSON.stringify(r.errorFrames)===JSON.stringify([{file:"mac_current_outer_wal_r1.py",line:956},{file:"mac_current_outer_inputs_r2.py",line:363},{file:"mac_current_outer_inputs_r2.py",line:64}]));
 const inputLines=files["references/inputs.original.py"].split("\n"),outerLines=files["references/outer.original.py"].split("\n");
 need("static_composite_guard_location",outerLines[955].includes("admit_actual_harnesses")&&inputLines[362].includes("re.fullmatch")&&inputLines[364].includes("actual_finite_harness_code_root"));
 need("original_business_caps",r.newOuterSeconds===900&&r.newManagerSeconds===600&&r.newManagerCleanupSeconds===60&&r.originalPhaseSeconds===120&&r.originalCaptureSeconds===45&&r.originalHttpSeconds===10&&JSON.stringify(r.originalNativeSeconds)==="[15,8,3]");
 need("no_business_phase",r.ownedPhases.length===0&&r.outerDescriptorClosure.portReservation===null&&r.productionServiceOperationDispatched===false&&r.productionManagerQualification===false);
 for(const k of ["productionChangedByController","providerRequested","j3160Contacted","credentialValuesPublished","automaticBusinessRetry","allAccountsQualified","fullReplacementQualified"])need("qualification_false."+k,r[k]===false);
 need("current_capture_attempted",r.productionCaptureAttempted===true);
 need("outer_closure",r.allOwnedRegistrationsLineagesHelpersClosed===true&&r.allPublicProofAndCaptureLibraryClosuresKnown===true&&r.outerDescriptorClosure.allOuterReadDescriptorsClosed===true&&r.outerDescriptorClosure.allEphemeralPortReservationSocketsClosed===true&&r.outerDescriptorClosure.descriptorCount===28&&r.outerDescriptorClosure.closeErrors.length===0&&r.finiteInputClosure.allOwnedInputDescriptorsClosed===true&&r.finiteInputClosure.closeErrors.length===0);
 function t5(name,t){need("t5."+name,t.allDescriptorsClosed===true&&t.closeErrors.length===0&&t.lastAnchorCheckPassed===true&&t.volumeUUIDVerified===true&&t.expectedVolumeDevice===anchor.expectedVolumeDevice&&JSON.stringify(t.anchors.map(x=>[x.path,x.identity]))===JSON.stringify(anchor.anchors.map(x=>[x.path,x.identity])));}
 t5("outer",r.heldT5Final);t5("entry",child.heldT5Final);
 function command(name,c){const z=c.cleanup;need("command_terminal."+name,c.exitCode===0&&c.completeBeforeDeadline===true&&c.outcomeUnknown===false&&c.streamsClosed===true&&c.stderrBytes===0&&c.errorType===null);need("command_owned_cleanup."+name,z.ok===true&&z.directChildReaped===true&&z.ownedLiveGroupEmptyBeforeReap===true&&z.allGroupRowsEmptyAfterReap===true&&z.remainingGroupRows.length===0&&z.outcomeUnknown===false&&z.postReapSignalSent===false&&z.exitCode===0);need("command_caps."+name,JSON.stringify(z.cleanupCaps)===JSON.stringify({group:3,psMax:4,term:1,wait:5}));}
 need("two_outer_one_nested_command",r.ownedCommands.commands.length===2&&r.ownedCommands.allOwnedCommandsStopped===true&&r.ownedCommands.unknownCommandCount===0&&child.ownedCommands.commands.length===1&&child.ownedCommands.allOwnedCommandsStopped===true&&child.ownedCommands.unknownCommandCount===0);
 r.ownedCommands.commands.forEach((c,i)=>command("outer"+i,c));child.ownedCommands.commands.forEach((c,i)=>command("entry"+i,c));
 const attempt=r.captureReports[0],obs=child.observation;
 need("entry_actual_success",child.ok===true&&child.outcomeUnknown===false&&child.stage==="before"&&child.captureLibraryAttempted===true&&child.captureLibraryReturned===true&&child.captureLibraryLedgerAvailable===true&&child.captureLibraryFailureLedgerAvailable===true&&child.allCaptureLibraryResourcesClosed===true&&child.entryOwnedDescriptorsClosed===true&&child.allOwnedDescriptorsClosed===true&&child.originalDeadlineMetAfterPrivatePublicationAndClosure===true&&child.elapsedSeconds<45&&attempt.terminalKnown===true&&attempt.typedReportAvailable===true);
 need("kernel_four_denied",child.kernelSandboxProof.allFourDenied===true&&child.kernelSandboxProof.checks.length===4&&child.kernelSandboxProof.checks.every(c=>c.denied===true&&c.errno===1)&&child.kernelSandboxProof.onlyOwnedWriteProbes===true&&child.kernelSandboxProof.externalAddressAttempted===false);
 need("capsule_public_binding_only",child.capsule.bytes===195155&&child.capsule.bytes<4194304&&child.capsule.sha256===attempt.privateCapsuleSha256&&child.capsule.bytes===attempt.privateCapsuleBytes&&child.capsule.identity.every(x=>typeof x==="string")&&!Object.keys(files).some(p=>p.endsWith("capsule.private.json")));
 need("seven_sql_closed",obs.connections.length===7&&obs.sqliteConnectionsOpened===7&&obs.sqliteConnectionsClosed===7&&obs.allReturnedConnectionsClosed===true);
 for(const [name,rows,count]of [["connection",obs.connections,7],["cursor",obs.cursors,11],["held_fd",obs.descriptors,46],["public_code_fd",obs.publicCodeDescriptors,6]]){
   need("ledger_count."+name,rows.length===count);
   rows.forEach((x,i)=>need("closed_once."+name+"."+i,x.closeAttempted===true&&x.closed===true&&x.closeError===null&&(name!=="held_fd"||x.closeBlockedByUnconfirmedConnection===null)));
 }
 need("capture_complete_closure",obs.ok===true&&obs.observationComplete===true&&obs.observationUnknown===false&&obs.allHeldNamesVerified===true&&obs.allHeldDescriptorsClosed===true&&obs.allPublicCodeDescriptorsClosed===true&&obs.allExplicitCursorsClosed===true&&obs.allOwnedDescriptorsClosed===true&&obs.closeErrors.length===0&&obs.originalDeadlineMetAfterClosure===true&&obs.completedMonotonic<obs.originalDeadlineMonotonic);
 need("exact_registry_wal_byte_bound",obs.files["/Users/qianqi/.openclaw/state/openclaw.sqlite-wal"].identity[6]==="5969912");
 const query=obs.queries[0];need("one_original_3s_query",obs.queries.length===1&&query.route==="registry_named_readonly_wal"&&query.success===true&&query.queryClosureKnown===true&&query.rolledBack===true&&query.completedMonotonic<query.deadlineMonotonic&&Math.abs(query.deadlineMonotonic-query.startedMonotonic-3)<0.00001);
 need("row_and_aggregate_bounds",obs.boundedReadAndReturnedBytes===205284&&obs.boundedReadAndReturnedBytes<8388608&&obs.sqlReturnedRows.filter(x=>x.label==="registry-fixed-row").length===1&&obs.sqlReturnedRows.find(x=>x.label==="registry-fixed-row").bytes===110871&&110871<1048576&&obs.sqlReturnedRows.every(x=>x.countedInAggregate===true));
 need("original_connect_unknown_scope",obs.originalImmutableRouteInvoked===true&&obs.originalImmutableConnectAttemptCount===null&&obs.internalSqliteDescriptorsIndividuallyObserved===false);
 need("observation_not_backup_or_atomic",obs.sqliteTransactionSnapshotClaimed===false&&obs.crossAgentAtomicSnapshotClaimed===false&&obs.wholeDatabaseBackupQualified===false&&obs.wholeDatabaseCopied===false&&child.crossAgentAtomicSnapshotClaimed===false&&child.wholeDatabaseBackupQualified===false);
 need("no_credential_write_or_provider",child.productionWriteAttempted===false&&child.providerRequestSent===false&&child.j3160Contacted===false);
 return{schema:"heptabao.mac-current-wal-runtime-actual-review.r1",decision:"PASS_KNOWN_FAILED_RUNTIME_ARCHIVE_WITH_CAPTURE_COMPONENT_SUCCESS",checksPassed:checks.length,checks,jobId:ack.job.id,authority:pin(files["actual/authority.native.json"]),stdout:pin(whole),entryStdout:pin(files["entry-before/stdout.original.json"]),streamPages:chunkCount,sdkNativePairs:10,actualOutcome:"Outer InputRefused at composite actual_finite_harness_code_root; no which-clause conclusion from public data.",publicCaptureSuccess:{returnedConnections:7,cursors:11,heldDescriptors:46,publicCodeDescriptors:6,aggregateReturnedBytes:205284,registryWalBytes:5969912},noPrivateCapsuleBodyArchived:true,wholeConsumerQualification:false,rootReleaseDecisionSeparate:true,noHostReplay:true};
}
