function verifyFixedPsCustodyR1OriginalChain(files) {
 const checks=[];
 const stable=x=>Array.isArray(x)?x.map(stable):x&&typeof x==="object"?Object.fromEntries(Object.keys(x).sort().map(k=>[k,stable(x[k])])):x;
 const eq=(name,a,b)=>checks.push({name,passed:JSON.stringify(stable(a))===JSON.stringify(stable(b))});
 const yes=(name,x)=>checks.push({name,passed:x===true});
 const parse=path=>parseLosslessIntegers(files[path]);
 const meta=gitBlobMeta;
 const go=parse("GO.original.json"),calls=parse("calls.index.public.json"),obs=parse("observers.index.public.json");
 eq("controls/exact-source",meta(files["source.original.py"]),go.source);
 eq("controls/exact-request",meta(files["request.original.json"]),go.exact_request);
 eq("controls/exact-journal",meta(files["journal.original.js"]),go.journal);
 const state=parse("final-state.public.json"),release=parse("RELEASE.public.json"),report=parse("stdout.original.json");
 const job="1a1b39a2fb0-fc05-83ca";
 const integer=x=>Number.isSafeInteger(x)?String(x):x&&typeof x.$exactInteger==="string"?x.$exactInteger:null;
 eq("go/original-whole",meta(files["GO.original.json"]),{"blob":"d53a5d17fa64bfde10a642a3527f4360e7d444af","bytes":8491,"sha256":"fc660396b4c50330af20a1a61f2092cddc7006ded40002ab3a1c57a8db83be31"});
 eq("exact/counts",[calls.length,obs.length,obs.reduce((n,o)=>n+o.pages,0)],[9,2,4]);
 const observerById=new Map(obs.map(o=>[o.id,o])),keys=new Set(),ids=new Set(),counts={};
 let started=false,active=null,stdout="",stderr="",nextOut=0,nextErr=0,authority=null,finished=0;
 function tree(name,expected,texts){
  try{
   const rows=Object.entries(texts).map(([path,raw])=>({path,mode:"100644",type:"blob",sha:meta(raw).blob}));
   const a=gitTreeAudit({sha:expected,truncated:false,tree:rows});
   eq(name,[a.root_sha,a.leaf_count],[expected,rows.length]);
  }catch(e){checks.push({name,passed:false,error:String(e.message)});}
 }
 function finish(a){
  const o=observerById.get(a.id),raw=utf8Text(a.bytes);
  yes("observer/"+a.id+"/listed",!!o);
  eq("observer/"+a.id+"/payload-whole",raw,files[o.paths.payload]);
  eq("observer/"+a.id+"/payload-pin",meta(raw),o.payload);
  eq("observer/"+a.id+"/payload-sha-and-bytes",[meta(raw).sha256,meta(raw).bytes],[a.digest,a.total]);
  eq("observer/"+a.id+"/pages",[a.pages,o.pages],[o.pages,a.pages]);
  tree("observer/"+a.id+"/payload-tree",o.payloadTree,{"payload.original.json":raw});
  const p=parseLosslessIntegers(raw);
  yes("observer/"+a.id+"/native-success",p.resultType==="complete"&&p.isError===false&&p.content?.length===1&&p.content[0].type==="text");
  const native=p.content[0].text,v=parseLosslessIntegers(native);
  eq("observer/"+a.id+"/native-original",native,files[o.paths.native]);
  eq("observer/"+a.id+"/native-pin",meta(native),o.nativeText);
  eq("observer/"+a.id+"/job",v.job_id,job);
  eq("observer/"+a.id+"/tool",o.tool,a.tool);
  yes("observer/"+a.id+"/closed",a.futureClosed&&o.completedInactive===true);
  if(a.tool==="process_status"){
   authority=v;eq("authority/original",native,files["authority.original.json"]);
   yes("authority/terminal",v.state==="failed"&&v.exit_code===1&&v.output_complete===true&&v.output_durable===true&&v.terminal_publication_confirmed===true);
   yes("authority/no-cancel-timeout",v.cancelled===false&&v.timed_out===false);
   for(const n of ["stdout","stderr"]){
    const expected=n==="stdout"?5208:0;
    eq("authority/"+n+"/complete",[v.log_bytes[n].seen,v.log_bytes[n].stored],[expected,expected]);
    yes("authority/"+n+"/durable",v.log_synced[n]===true&&v.log_errors[n]===null&&v.log_truncated[n]===false);
   }
  }else{
   for(const n of ["stdout","stderr"]){
    const row=v[n],asked=a.request.operation.arguments[n+"_offset"],expected=n==="stdout"?nextOut:nextErr;
    eq("stream/"+a.id+"/"+n+"/cursor",[asked,row.offset],[expected,expected]);
    yes("stream/"+a.id+"/"+n+"/hex",typeof row.bytes_hex==="string"&&/^(?:[0-9a-f]{2})*$/.test(row.bytes_hex));
    const bytes=[];for(let i=0;i<row.bytes_hex.length;i+=2)bytes.push(parseInt(row.bytes_hex.slice(i,i+2),16));
    yes("stream/"+a.id+"/"+n+"/16K",bytes.length<=16384);
    eq("stream/"+a.id+"/"+n+"/text",utf8Text(bytes),row.text);
    eq("stream/"+a.id+"/"+n+"/extent",row.next_offset,row.offset+bytes.length);
    eq("stream/"+a.id+"/"+n+"/size",row.size,n==="stdout"?5208:0);
    eq("stream/"+a.id+"/"+n+"/eof",row.eof,row.next_offset===row.size);
    if(n==="stdout"){stdout+=row.text;nextOut=row.next_offset;}else{stderr+=row.text;nextErr=row.next_offset;}
   }
  }
  finished++;active=null;
 }
 for(let i=0;i<calls.length;i++){
  const c=calls[i],q=parse(c.paths.request),intent=parse(c.paths.intent),armed=parse(c.paths.armed),sdk=JSON.parse(files[c.paths.sdk]);
  eq("call/"+i+"/ordinal",c.ordinal,i);yes("call/"+i+"/unique",!keys.has(c.key));keys.add(c.key);
  counts[c.kind]=(counts[c.kind]||0)+1;
  eq("call/"+i+"/request-pin",meta(files[c.paths.request]),c.requestPin);
  eq("call/"+i+"/sdk-pin",meta(files[c.paths.sdk]),c.sdkPin);
  eq("call/"+i+"/native-pin",meta(files[c.paths.native]),c.nativePin);
  eq("call/"+i+"/intent-binding",[intent.callKey,intent.kind,intent.request,intent.rootGo],[c.key,c.kind,c.requestPin,meta(files["GO.original.json"])]);
  yes("call/"+i+"/armed-once",intent.maximumNativeCalls===1&&intent.nativeNotYetCalled===true&&intent.lossOfAcknowledgmentNeverGrantsReplay===true&&armed.mayHaveDispatchedAfterThisCheckpoint===true);
  eq("call/"+i+"/arm-identity",[armed.callKey,armed.kind,armed.request,armed.rootGo],[c.key,c.kind,c.requestPin,meta(files["GO.original.json"])]);
  tree("call/"+i+"/arm-merkle",c.armTree,{"request.json":files[c.paths.request],"intent.json":files[c.paths.intent],"armed.json":files[c.paths.armed]});
  tree("call/"+i+"/sdk-merkle",c.sdkTree,{"original.sdk.json":files[c.paths.sdk]});
  yes("call/"+i+"/actual-called-accepted",c.calledOnce===true&&c.phase==="accepted");
  yes("call/"+i+"/sdk-success",sdk.isError!==true&&sdk.content?.length===1&&sdk.content[0].type==="text");
  eq("call/"+i+"/native-raw",sdk.content[0].text,files[c.paths.native]);
  const v=parseLosslessIntegers(files[c.paths.native]);
  if(c.kind==="process_start"){
   yes("start/unique-first",i===0&&!started&&!active);started=true;
   eq("start/exact-request",meta(files[c.paths.request]),go.exact_request);
   eq("start/source",meta(q.stdin),go.source);
   eq("start/identity",[v.job.id,v.job.host,v.job.idempotency_key,v.job.executable,v.job.args,v.job.cwd],[job,"mac",q.idempotency_key,q.executable,q.args,q.cwd]);
   eq("start/typed-binding",[v.job.request_digest,integer(v.job.request_fingerprint)],[go.digest,go.fingerprint]);
   yes("start/unique-success",v.reused===false&&v.launch?.ok===true&&v.audit_recorded===true&&v.local_record_pending===false);
  }else if(c.kind==="operation_start"){
   yes("op/"+i+"/previous-closed",started&&!active);
   yes("op/"+i+"/key-prefix",q.idempotency_key.startsWith("heptabao-mac-fixed-setuid-ps-custody-c0c5f671-"));
   yes("op/"+i+"/scope",["process_status","process_read"].includes(q.operation.tool)&&q.operation.arguments.host==="mac"&&q.operation.arguments.job_id===job);
   if(q.operation.tool==="process_read")eq("op/"+i+"/original-cursors",[q.operation.arguments.stdout_offset,q.operation.arguments.stderr_offset,q.operation.arguments.limit],[nextOut,nextErr,16384]);
   yes("op/"+i+"/admitted-once",v.reused===false&&v.automatic_retry===false&&v.tool_name===q.operation.tool&&/^[0-9a-f]{64}$/.test(v.operation_id)&&!ids.has(v.operation_id));
   ids.add(v.operation_id);active={id:v.operation_id,tool:v.tool_name,request:q,futureClosed:false,statuses:0,pages:0,total:null,digest:null,bytes:[]};
  }else if(c.kind==="operation_status"){
   yes("status/"+i+"/same-id",!!active&&q.operation_id===active.id&&v.operation_id===active.id&&v.tool_name===active.tool&&v.automatic_retry===false);
   active.statuses++;yes("status/"+i+"/bound",active.statuses<=8);
   yes("status/"+i+"/closed",v.async_state==="completed"&&v.owned_future_active===false&&v.result_state==="stored_observed"&&v.payload_available===true);
   active.futureClosed=true;
  }else if(c.kind==="operation_result"){
   yes("page/"+i+"/same-closed-id",!!active&&active.futureClosed&&q.operation_id===active.id&&v.operation_id===active.id);
   eq("page/"+i+"/original-width",q.limit,8192);
   eq("page/"+i+"/offset",[q.offset,v.offset],[active.bytes.length,active.bytes.length]);
   yes("page/"+i+"/native-immutable",v.immutable_snapshot===true&&v.payload_kind==="native_result"&&v.format==="serialized_original_native_sdk_payload_before_operation_metadata_and_transport_normalization");
   yes("page/"+i+"/payload-bound",Number.isSafeInteger(v.total_bytes)&&v.total_bytes>=0&&v.total_bytes<=1048576);
   const bytes=unb64(v.data_base64);yes("page/"+i+"/size-bound",bytes.length<=8192);
   eq("page/"+i+"/extent",v.next_offset,v.offset+bytes.length);
   eq("page/"+i+"/eof",v.eof,v.next_offset===v.total_bytes);
   if(active.total!==null)eq("page/"+i+"/one-payload",[v.total_bytes,v.result_sha256],[active.total,active.digest]);
   active.total=v.total_bytes;active.digest=v.result_sha256;active.bytes.push(...bytes);active.pages++;
   yes("page/"+i+"/page-bound",active.pages<=128);
   if(v.eof)finish(active);
  }else yes("call/"+i+"/closed-kind",false);
 }
 eq("counts/native",counts,{process_start:1,operation_start:2,operation_status:2,operation_result:4});
 yes("final/all-observers-closed",active===null&&finished===2);
 eq("final/stdout-original",stdout,files["stdout.original.json"]);eq("final/stderr-original",stderr,files["stderr.original.txt"]);
 eq("final/extents",[nextOut,nextErr],[5208,0]);
 eq("final/whole-stdout",meta(stdout),{"blob":"57c9ac037053bc2163db3f12083529c02244c9df","bytes":5208,"sha256":"27b72de7619e9579fbcfeac27757087877a287429cda0e8e70d750fc503bb8fc"});
 yes("final/context-zero",state.job===job&&state.nativeCallInFlight===false&&state.pending===null&&state.activeObserver===null&&state.paused===false);
 yes("final/release-zero",release.activeNativeCalls===0&&release.knownActiveNativeFutures===0&&release.pendingCall===null&&release.activeObserver===null&&release.laneReleased===true);
 eq("final/release-counts",[release.originalNativeCalls,release.originalObservers,release.immutablePages],[9,2,4]);





 const lane=parse("lane-GO.original.json");
 eq("lane/original-whole",meta(files["lane-GO.original.json"]),{"blob":"8f1f8fc77c0af587085b31cfc12c8119136a0a69","bytes":1804,"sha256":"acc345b99b1186aa3c451107204ef40f1e64d0e720122ab537e4e0fa57525711"});
 eq("lane/execution-GO",lane.originalExecutionGO,meta(files["GO.original.json"]));
 yes("lane/scheduling-only",lane.authorization==="GO"&&lane.sourceAndRequestAndKeyUnchanged===true&&lane.supersedesOnlySchedulingCondition===true&&lane.AInitializeAndArmNowAuthorized===true&&lane.maximumAStarts===1&&lane.noNewPublicOrPrivateScope===true&&lane.noDeadlineOrByteBoundChange===true);
 eq("lane/same-slot-key",[lane.originalSlot,lane.originalKey],[go.slot,go.start.idempotencyKey]);
 const binding=eval(files["actual-stdin-binding.original.js"]+";actualStdinProcessStartBinding")(parse("request.original.json"));
 eq("binding/correct-actual-stdin",[binding.sha256,binding.native_fingerprint],[go.digest,go.fingerprint]);
 eq("binding/exact-key",parse("request.original.json").idempotency_key,go.start.idempotencyKey);
 eq("report/schema",report.schema,"heptabao.fixed-setuid-ps-custody-validation.r1");
 eq("report/known-failure",[report.ok,report.observationComplete,report.executionSucceeded,report.outcomeUnknown],[false,false,false,false]);
 eq("report/exact-error",report.error,{code:"typed_process_row",errno:null,type:"Refused",unknownErrorTextWithheld:false});
 eq("report/final-fence-not-passed",report.allFixedHeldNamedFencesPassed,false);
 yes("report/table-not-exposed",!Object.hasOwn(report,"table")&&report.rawProcessTableExported===false&&report.processTableHashExported===false);
 const c=report.command,cl=c.cleanup,ad=c.fixedPsAdmissionEvidence;
 eq("primary/argv",c.argv,go.execution.argv);
 eq("primary/label",c.label,go.execution.label);
 eq("primary/admitted-ps",report.admittedPs,{path:"/bin/ps",...go.exact_input_pins["/bin/ps"]});
 eq("primary/command-admission",c.fixedSetuidPsAdmission,report.admittedPs);
 eq("primary/exact-observed-admission",ad,{effectiveUidMatches:true,expectedEffectiveUid:0,expectedGroup:74835,expectedParent:74832,groupMatches:true,observedEffectiveUid:0,observedGroup:74835,observedParent:74832,parentMatches:true,pid:74835});
 eq("primary/known-result",[c.exitCode,c.expectedEffectiveUid,c.stdoutBytes,c.stderrBytes,c.completeBeforeDeadline,c.streamsClosed,c.outcomeUnknown,c.errorCode,c.errorType,c.setuidPsNameFull9FencesPassed],[0,0,21402,0,true,true,false,null,null,true]);
 eq("primary/name-race-not-eliminated",c.execByNameNotAtomicExecByFd,true);
 yes("primary/bounded-command",c.elapsedSeconds>=0&&c.elapsedSeconds<go.budgets.primaryCommandSeconds&&c.stdoutBytes<=go.budgets.streamingStdoutBytes);
 eq("primary/custody",[cl.pid,cl.pgid,cl.custody.ps.pid,cl.custody.ps.ppid,cl.custody.ps.pgid,cl.custody.ps.uid,cl.custody.sid_observed_while_live],[74835,74835,74835,74832,74835,0,74835]);
 eq("primary/birth",cl.custody.ps.start,"Sat Nov  7 09:23:09 2026    ");
 eq("primary/custody-admitted-ps",cl.custody.fixedSetuidPs,report.admittedPs);
 eq("primary/custody-euid",cl.custody.expectedEffectiveUid,0);
 eq("primary/retained-exit",cl.retainedExit,{code:1,pid:74835,signo:20,status:0});
 yes("primary/real-cleanup",cl.ok===true&&cl.outcomeUnknown===false&&cl.directChildReaped===true&&cl.ownedLiveGroupEmptyBeforeReap===true&&cl.allGroupRowsEmptyAfterReap===true&&cl.stopAttempted===true&&cl.exitCode===0);
 eq("primary/no-signal",[cl.signals,cl.initialLiveGroup,cl.remainingGroupRows,cl.postReapSignalSent],[[],[],[],false]);
 eq("primary/cleanup-caps",cl.cleanupCaps,go.budgets.cleanupCaps);
 yes("primary/cleanup-finite",cl.elapsedSeconds>=0&&cl.elapsedSeconds<go.budgets.cleanupReserveSeconds);
 eq("commands/exact-one",report.commands.commands,[c]);
 eq("commands/closed",[report.commands.allOwnedCommandsStopped,report.commands.unknownCommandCount,report.commandOutcomeKnown],[true,0,true]);
 eq("inputs/exact",report.inputs,{allReturnedInputFdsClosed:true,closeErrors:[],fixedInputCount:2,metadataCalls:12,readBytes:205072,readCalls:6,returnedFdLedger:{attempts:2,knownNoReturnErrors:0,pending:0,registered:2,registrationUnknown:false}});
 yes("inputs/unchanged-caps",report.inputs.fixedInputCount===go.budgets.applicationHeldInputFds&&report.inputs.metadataCalls<=go.budgets.inputMetadataCalls&&report.inputs.readCalls<=go.budgets.inputReadCalls&&report.inputs.readBytes===go.budgets.publicInputBodyBytes);
 eq("closure/known",[report.allOwnDescriptorsAndChildrenClosed,report.handlersRestored,report.pendingSignalObserved,report.original45SecondDeadlineMetAfterClosure],[true,true,false,true]);
 yes("closure/finite",report.elapsedSeconds>=0&&report.elapsedSeconds<go.budgets.afterClosureSeconds);
 eq("closure/stream-cap",report.originalStreamingCapEach,go.budgets.streamingStdoutBytes);
 for(const k of ["SDKOrCredentialsRequested","T5ReadOrWriteRequested","directoryScanRequested","launchdRequested","oldManagedCleanupClaimed","oldProcessReadFailureProvedESRCH","oldPs84947And85012Reclassified","sameProgramFutureBusinessQualification","stderrTextOrHashExported"])eq("scope/"+k,report[k],false);
 eq("scope/no-write",report.fixedPublicFileWrites,0);
 eq("scope/only-fixed-group-projection",report.onlyFixedGroupProjection,true);
 eq("scope/child-internal-fds-not-enumerated",report.childInternalFdsNotEnumerated,true);
 eq("release/actual-error",release.actual.error,report.error);
 eq("release/current-closure",release.actual.allOwnDescriptorsAndChildrenClosed,report.allOwnDescriptorsAndChildrenClosed);
 eq("release/not-whole-diagnostic-pass",[release.actual.observationComplete,release.actual.executionSucceeded,release.actual.allFixedHeldNamedFencesPassed],[false,false,false]);
 eq("release/exact-state-pin",release.finalState,meta(files["final-state.public.json"]));
 eq("release/exact-stream-pins",[release.stdout,release.stderr,release.authority],[meta(files["stdout.original.json"]),meta(files["stderr.original.txt"]),meta(files["authority.original.json"])]);
 eq("state/exact-call-order",Object.keys(state.calls),calls.map(c=>c.key));
 eq("state/observer-index",state.completedObservers,obs.map(({paths,...x})=>x));
 yes("state/no-paused-failure",state.paused===false&&state.nativeCallInFlight===false&&state.pending===null&&state.activeObserver===null);
 return {schema:"heptabao.fixed-setuid-ps-r1-original-chain-pure-checks.r1",passed:checks.every(x=>x.passed),checkCount:checks.length,checks,originalCalls:9,returnedObservers:2,immutablePages:4,NativeCallsAdded:0,execution:"pure V8 exact original SDK/intent/payload/stream verification only",knownOriginalDiagnosticFailure:true,fixedPsPrimaryCustodyObserved:true,offendingProcessTableFieldObserved:false,SDKQualified:false,historicalUnknownPreserved:true};
}
