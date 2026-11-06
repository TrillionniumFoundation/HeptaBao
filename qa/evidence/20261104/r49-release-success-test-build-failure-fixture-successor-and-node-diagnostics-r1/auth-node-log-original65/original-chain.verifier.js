function verifyNodeIgnitionLogR1OriginalChain(files) {
 const checks=[];
 const stable=x=>Array.isArray(x)?x.map(stable):x&&typeof x==="object"?Object.fromEntries(Object.keys(x).sort().map(k=>[k,stable(x[k])])):x;
 const eq=(name,a,b)=>checks.push({name,passed:JSON.stringify(stable(a))===JSON.stringify(stable(b))});
 const yes=(name,x)=>checks.push({name,passed:x===true});
 const parse=path=>parseLosslessIntegers(files[path]);
 const meta=gitBlobMeta;
 const go=parse("GO.original.json"),calls=parse("calls.index.public.json"),obs=parse("observers.index.public.json");
 const state=parse("final-state.public.json"),release=parse("RELEASE.public.json"),report=parse("stdout.original.json");
 const job="1a1b2e40a05-fc05-8023";
 const integer=x=>Number.isSafeInteger(x)?String(x):x&&typeof x.$exactInteger==="string"?x.$exactInteger:null;
 eq("go/original-whole",meta(files["GO.original.json"]),{"blob":"f8c0b5d7c79d68a2f5acd66802e8967f7036ee25","bytes":10350,"sha256":"1af9964a574a0816b67ea7d31aa3ad6b329f7b0b057b65ef8bd32781e750d128"});
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
   yes("authority/terminal",v.state==="succeeded"&&v.exit_code===0&&v.output_complete===true&&v.output_durable===true&&v.terminal_publication_confirmed===true);
   yes("authority/no-cancel-timeout",v.cancelled===false&&v.timed_out===false);
   for(const n of ["stdout","stderr"]){
    const expected=n==="stdout"?5588:0;
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
    eq("stream/"+a.id+"/"+n+"/size",row.size,n==="stdout"?5588:0);
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
   eq("start/exact-request",meta(files[c.paths.request]),go.exactRequest);
   eq("start/source",meta(q.stdin),go.source);
   eq("start/identity",[v.job.id,v.job.host,v.job.idempotency_key,v.job.executable,v.job.args,v.job.cwd],[job,"mac",q.idempotency_key,q.executable,q.args,q.cwd]);
   eq("start/typed-binding",[v.job.request_digest,integer(v.job.request_fingerprint)],[go.native_binding.sha256,go.native_binding.native_fingerprint]);
   yes("start/unique-success",v.reused===false&&v.launch?.ok===true&&v.audit_recorded===true&&v.local_record_pending===false);
  }else if(c.kind==="operation_start"){
   yes("op/"+i+"/previous-closed",started&&!active);
   yes("op/"+i+"/key-prefix",q.idempotency_key.startsWith("heptabao-mac-public-node-ignition-f9b88153-"));
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
 eq("final/extents",[nextOut,nextErr],[5588,0]);
 eq("final/whole-stdout",meta(stdout),{"blob":"5966bedd4adce3e0dc12ac3d26c1280ab6c97c22","bytes":5588,"sha256":"71594fae5203a35c10c54de55e0ea04f821db4616935ae0db591fccc6b716f09"});
 yes("final/context-zero",state.job===job&&state.nativeCallInFlight===false&&state.pending===null&&state.activeObserver===null&&state.paused===false);
 yes("final/release-zero",release.currentNativeState.nativeCallInFlight===false&&release.currentNativeState.activeFutures===0&&release.currentNativeState.laneReleased===true);
 eq("final/release-counts",[release.originalCallCount,release.originalObserverCount,release.immutablePageCount],[9,2,4]);



 yes("report/no-error",!Object.hasOwn(report,"error"));
 eq("report/schema",report.schema,"heptabao.mac-public-node-ignition-log-diagnosis.r1");
 eq("report/known-observation",[report.ok,report.outcomeUnknown],[true,false]);
 yes("report/own-closure",report.allApplicationDescriptorsClosed===true&&report.allOwnedLogChildrenClosed===true&&report.deadlineMetAfterClosure===true);
 eq("report/no-close-signal-errors",[report.closeErrors,report.signalRestoreErrors,report.pendingSignalAfterRestore],[[],[],null]);
 eq("report/four-application-fds",report.fileDescriptors.length,4);
 yes("report/every-fd-once-closed",report.fileDescriptors.every(x=>x.openAttempted===true&&x.created===true&&x.closeAttempted===true&&x.closed===true));
 eq("report/tool",report.toolCode,{bytes:807536,execByPathIsNotAtomicExecByFd:true,sameHeldFileRetainedThroughChildCleanup:true,sha256:"2fa7b04615546f0964dd1ddedab04a07e3e026f76959e7f44cbd30bfa48a5974",wholeCurrentFileObserved:true});
 eq("report/io-counts",report.budget,{codeBytesReturned:807536,codeReadCalls:14,metadata:40});
 eq("report/command-count",[report.commands.commands.length,report.commands.unknownCommandCount,report.commands.allOwnedCommandsStopped],[1,0,true]);
 const c=report.commands.commands[0],cl=c.cleanup;
 eq("command/original-fixed-argv",c.argv,go.query.argv);
 eq("command/actual-terminal",[c.pid,c.exitCode,c.stdoutBytes,c.stderrBytes,c.outcomeUnknown,c.streamsClosed,c.completeBeforeDeadline],[5094,0,25,0,false,true,true]);
 eq("command/actual-retained-exit",cl.retainedExit,{code:1,pid:5094,signo:20,status:0});
 yes("command/owned-closure",cl.ok===true&&cl.outcomeUnknown===false&&cl.directChildReaped===true&&cl.ownedLiveGroupEmptyBeforeReap===true&&cl.allGroupRowsEmptyAfterReap===true);
 eq("command/no-signals-or-remaining",[cl.signals,cl.initialLiveGroup,cl.remainingGroupRows,cl.postReapSignalSent],[[],[],[],false]);
 eq("command/actual-custody",[cl.custody.ps.pid,cl.custody.ps.ppid,cl.custody.ps.pgid,cl.custody.ps.uid,cl.custody.sid_observed_while_live],[5094,5092,5094,501,5094]);
 yes("command/within-caps",c.elapsedSeconds<10&&cl.elapsedSeconds<14&&report.elapsedSeconds<45);
 const p=report.logEventObservation;
 eq("projection/exact-counts",[p.observedObjects,p.admittedEvents,p.rejectedUnknownObjects,p.rows.length],[1,0,1,1]);
 eq("projection/fixed-subject-window",[p.fixedPublicNodePid,p.originalWindowMilliseconds],[51494,2000]);
 const row=p.rows[0];
 eq("projection/unknown-ordinal",[row.ordinal,row.admitted,row.meaning,row.origin],[0,false,"unknown_object_not_admitted",null]);
 eq("projection/exact-known-keys",Object.keys(row.knownFields).sort(),["composedMessage","eventMessage","message","pid","process","processID","processIdentifier","processImagePath","timestamp"].sort());
 yes("projection/all-nine-absent",Object.values(row.knownFields).every(x=>x.present===false&&x.jsonType==="absent"));
 eq("projection/eight-predicates",Object.keys(row.admissionPredicates).length,8);
 yes("projection/all-eight-false",Object.values(row.admissionPredicates).every(x=>x===false));
 eq("projection/closed-reasons",row.rejectionReasons,["message_semantics_unknown","process_origin_unknown","timestamp_unknown","outside_original_window","fixed_node_subject_not_admitted"]);
 for(const k of ["rawLogTextExported","rawOrUnknownLogHashExported","startupCauseQualified","wholeLogFullyClassified","unknownObjectSemanticsQualified","originalBusinessProgressQualified","originalCrashPathCorrelationQualified","historicalLineageClosureQualified"])eq("projection/"+k,p[k],false);
 yes("projection/no-absence-inference",p.noMatchesDoesNotProveAbsence===true&&p.freshLogObservationNotOriginalCapturedStreamRecovery===true);
 eq("projection/no-arbitrary-content",[row.arbitraryFieldValuesPublished,row.unknownKeyNamesPublished],[false,false]);
 for(const k of ["directApplicationPrivateFileOrCapsuleRead","directoryEnumeration","historicalLineageClosureQualified","oldLabelCleanupAttempted","sdkOrProviderExecuted","serviceMutationAttempted","startupCauseQualified"])eq("scope/"+k,report[k],false);
 eq("scope/authority-streams-count-release",[release.originalCallCount,release.originalObserverCount,release.immutablePageCount,release.additionalNativeAuthorized],[9,2,4,false]);
 return {schema:"heptabao.node-ignition-log-r1-original-chain-pure-checks.r1",passed:checks.every(x=>x.passed),checkCount:checks.length,checks,originalCalls:9,returnedObservers:2,immutablePages:4,NativeCallsAdded:0,execution:"pure V8 original public SDK/intent/payload/stream verification only",observedObjects:1,admittedEvents:0,rejectedUnknownObjects:1,causeQualified:false,businessQualified:false,historicalUnknownPreserved:true};
}
