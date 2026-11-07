function verifyLiveDenialR2OriginalChain(files) {
 const checks=[];
 const stable=x=>Array.isArray(x)?x.map(stable):x&&typeof x==="object"?Object.fromEntries(Object.keys(x).sort().map(k=>[k,stable(x[k])])):x;
 const eq=(name,a,b)=>checks.push({name,passed:JSON.stringify(stable(a))===JSON.stringify(stable(b))});
 const yes=(name,x)=>checks.push({name,passed:x===true});
 const parse=path=>parseLosslessIntegers(files[path]);
 const meta=gitBlobMeta;
 const go=parse("GO.original.json"),calls=parse("calls.index.public.json"),obs=parse("observers.index.public.json");
 const state=parse("final-state.public.json"),release=parse("RELEASE.public.json"),report=parse("stdout.original.json");
 const job="1a1b33bc0d5-fc05-814d";
 const integer=x=>Number.isSafeInteger(x)?String(x):x&&typeof x.$exactInteger==="string"?x.$exactInteger:null;
 eq("go/original-whole",meta(files["GO.original.json"]),{"blob":"d6ae07de2d1e8249267f38c452f9475624b7f285","bytes":13290,"sha256":"165ebeb49eaaa8a4abf2c0d922075ed60e45d51a9c24084e99d501b6cba8a83e"});
 eq("exact/counts",[calls.length,obs.length,obs.reduce((n,o)=>n+o.pages,0)],[13,2,8]);
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
    const expected=n==="stdout"?16263:0;
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
    eq("stream/"+a.id+"/"+n+"/size",row.size,n==="stdout"?16263:0);
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
   yes("op/"+i+"/key-prefix",q.idempotency_key.startsWith("heptabao-mac-public-node-live-denial-19a394ee-"));
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
 eq("counts/native",counts,{process_start:1,operation_start:2,operation_status:2,operation_result:8});
 yes("final/all-observers-closed",active===null&&finished===2);
 eq("final/stdout-original",stdout,files["stdout.original.json"]);eq("final/stderr-original",stderr,files["stderr.original.txt"]);
 eq("final/extents",[nextOut,nextErr],[16263,0]);
 eq("final/whole-stdout",meta(stdout),{"blob":"3e108153abca1f3951a457cbe6dde2e5aeaa492e","bytes":16263,"sha256":"36b7dd75bed14fa6047d722f50dbc73fae1218b19e93eda6533848dbc55d6186"});
 yes("final/context-zero",state.job===job&&state.nativeCallInFlight===false&&state.pending===null&&state.activeObserver===null&&state.paused===false);
 yes("final/release-zero",release.lane.activeRuntimeCall===false&&release.lane.knownFuture===false&&release.lane.A===0);
 eq("final/release-counts",[release.NativeCalls,release.originalObservers.length,release.immutablePages],[13,2,8]);





 eq("source/full-exact",meta(files["source.original.py"]),go.source);
 eq("request/full-exact",meta(files["request.original.json"]),go.exactRequest);
 eq("journal/full-exact",meta(files["journal.original.js"]),go.journal);
 eq("start/file-identical",files[calls[0].paths.request],files["request.original.json"]);
 yes("report/no-error",!Object.hasOwn(report,"error"));
 eq("report/schema",report.schema,"heptabao.mac-public-node-live-denial.r1");
 eq("report/outcome",[report.ok,report.observationComplete,report.outcomeUnknown],[true,true,false]);
 eq("report/profile-original",[report.profileActual.bytes,report.profileActual.sha256,report.profileBytesUnchanged],[6909,"acfbd336488f774e3acb87392bf5305f62004a0f529cbcd876593407989e7a12",true]);
 const control="/Users/qianqi/heptabao-public-node-live-denial-20261106-r1-control",empty="/Users/qianqi/heptabao-public-node-live-denial-20261106-r1-empty";
 eq("report/roots-cwd",[report.controlRoot,report.emptyHomeAndCwd,report.cwd],[control,empty,empty]);
 eq("report/closed-env",report.environment,{HOME:empty,TMPDIR:empty,PATH:"/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",LANG:"C",LC_ALL:"C"});
 eq("profile/held-identity",report.profileActual.identity,["16777233","593610126","501","20","33152","1","6909","1794008400307992038","1794008400307992038"]);
 eq("profile/fixed-path",report.profileActual.path,control+"/consumer.sb");
 const cc=report.commands.commands,pc=report.pairCustody,q=pc.queue;
 eq("children/counts",[cc.length,report.commands.unknownCommandCount,pc.spawnAttempts,pc.spawnPending,pc.spawnRegistrationUnknown],[2,0,2,0,false]);
 yes("children/all-stopped",report.commands.allOwnedCommandsStopped===true);
 const expected=[[29053,-6,53,0,2,6],[29055,0,167,0,1,0]];
 for(let i=0;i<cc.length;i++){
  const c=cc[i],e=expected[i],cl=c.cleanup;
  eq("child/"+i+"/actual",[c.pid,c.exitCode,c.stdoutBytes,c.stderrBytes,cl.retainedExit.code,cl.retainedExit.status],e);
  eq("child/"+i+"/retained",cl.retainedExit,{code:e[4],pid:e[0],signo:20,status:e[5]});
  yes("child/"+i+"/full-before-deadline",c.streamsClosed===true&&c.completeBeforeDeadline===true&&c.outcomeUnknown===false);
  eq("child/"+i+"/captured-custody",[cl.custody.ps.pid,cl.custody.ps.ppid,cl.custody.ps.pgid,cl.custody.ps.uid,cl.custody.sid_observed_while_live],[e[0],29051,e[0],501,e[0]]);
  eq("child/"+i+"/birth",cl.custody.ps.start,"Sat Nov  7 07:40:00 2026    ");
  eq("child/"+i+"/caps",cl.cleanupCaps,{group:3,psMax:4,term:1,wait:5});
  yes("child/"+i+"/known-reaped",cl.ok===true&&cl.outcomeUnknown===false&&cl.directChildReaped===true&&cl.ownedLiveGroupEmptyBeforeReap===true&&cl.allGroupRowsEmptyAfterReap===true);
  eq("child/"+i+"/no-signals-or-survivors",[cl.signals,cl.initialLiveGroup,cl.remainingGroupRows,cl.postReapSignalSent],[[],[],[],false]);
  yes("child/"+i+"/within-cleanup-cap",cl.elapsedSeconds>=0&&cl.elapsedSeconds<9);
  yes("child/"+i+"/first-completion-in-time",q[(i===0?"node":"log")+"FirstCompleteMonotonic"]<=c.commandDeadlineMonotonic);
 }
 const predicate='(process == "node" OR process == "kernel" OR process == "sandboxd") AND message CONTAINS "node(29053)"';
 eq("log/exact-argv",cc[1].argv,["/usr/bin/log","stream","--level","debug","--style","ndjson","--predicate",predicate,"--timeout","8"]);
 eq("node/exact-exec-argv",report.node.fixedExecArgv,["/usr/bin/sandbox-exec","-f",control+"/consumer.sb","/opt/homebrew/Cellar/node/25.9.0_1/bin/node","--version"]);
 eq("node/gate-carrier",cc[0].argv,report.node.gateCarrierArgv);
 eq("node/markers",[report.node.gateReadyObserved,report.node.gateReleaseObserved,report.node.fixedExecFailureMarkerObserved],[true,true,false]);
 eq("node/known-failure",[report.node.pid,report.node.observedExitCode,report.node.observedExit],[29053,-6,{code:2,pid:29053,signo:20,status:6}]);
 eq("node/only-markers-no-version",[report.node.version.bytes,report.node.version.publicVersionSyntax,report.node.version.value,report.node.stderrBytes,report.node.versionSucceeded],[0,false,null,0,false]);
 yes("node/53-marker-bytes",utf8Bytes("HEPTA_NODE_GATE_READY 29053\nHEPTA_NODE_GATE_RELEASED\n").length===53);
 eq("node/exec-observation-limit",[report.node.samePidExecAttemptSupportedByMarkersAndSource,report.node.actualNodeImageIndependentlyObserved,pc.samePidExecChainIsSourceControlFlowInference,pc.NodeExecImageIndependentlyObserved],[true,false,true,false]);
 const ordered=["gateReadyMonotonic","logLaunchBeforeMonotonic","gateWriteBeforeMonotonic","gateWriteAfterMonotonic","nodeExitObservedMonotonic","nodeFirstCompleteMonotonic","logExitObservedMonotonic","logFirstCompleteMonotonic","allPipeEOFObservedMonotonic"];
 yes("timing/observed-order",ordered.every((k,i)=>typeof q[k]==="number"&&(!i||q[ordered[i-1]]<=q[k])));
 yes("timing/ready-log-before-gate",q.gateReadyWallUs<=q.logLaunchBeforeWallUs&&q.logLaunchBeforeWallUs<=q.logCustodyCapturedWallUs&&q.logCustodyCapturedWallUs<=q.gateWriteBeforeWallUs);
 yes("timing/latch-survived-node-deadline",q.nodeFirstCompleteMonotonic<=cc[0].commandDeadlineMonotonic&&q.logFirstCompleteMonotonic>cc[0].commandDeadlineMonotonic&&cc[0].completeBeforeDeadline);
 yes("timing/log-live-after-node",q.logLiveObservedAfterNodeExit===true&&q.lastLogLiveObservationMonotonic>=q.nodeExitObservedMonotonic);
 eq("pipe/ledger",[pc.returnedPipeCount,pc.pipePending,pc.pipeRegistrationUnknown,pc.pipes.length,pc.readCalls,pc.returnedBytes],[5,0,false,5,8,220]);
 eq("pipe/returned-byte-sum",pc.returnedBytes,cc.reduce((n,c)=>n+c.stdoutBytes+c.stderrBytes,0));
 eq("pipe/order",pc.pipes.map(x=>[x.role,x.name]),[["node","stdin"],["node","stdout"],["node","stderr"],["log","stdout"],["log","stderr"]]);
 for(let i=0;i<pc.pipes.length;i++){const f=pc.pipes[i];yes("pipe/"+i+"/once-closed",f.returned===true&&f.closeAttempted===true&&f.closed===true);eq("pipe/"+i+"/EOF",f.eof,i!==0);}
 yes("pair/once-gate-and-owned-close",pc.gateAttempted&&pc.gateByteSent&&pc.allReturnedPipesClosed&&pc.logCleanupAttemptedBeforeNodeReap&&pc.logKnownClosedBeforeNodeReap&&pc.unreapedNodePidReservedDuringAllCapturedPipeReads);
 eq("pair/close-error",report.pairCloseError,null);
 eq("input/ledger",report.inputs.returnedFdLedger,{attempts:5,knownNoReturnErrors:0,pending:0,registered:5,registrationUnknown:false});
 eq("input/counters",[report.inputs.fixedInputCount,report.inputs.readBytes,report.inputs.readCalls,report.inputs.metadataCalls],[5,1183360,26,49]);
 yes("input/all-closed",report.inputs.allReturnedInputFdsClosed===true&&report.inputs.closeErrors.length===0);
 eq("home/count",report.homeResources.length,2);
 let homeFDs=0;
 for(let i=0;i<report.homeResources.length;i++){
  const h=report.homeResources[i],cl=h.closure;homeFDs+=cl.fdRows.length;
  yes("home/"+i+"/full-closure",h.initializationStarted&&h.initializationCompleted&&h.finalFencePassed&&h.closeError===null&&cl.initComplete&&cl.allFiniteLeavesClosed&&cl.allReturnedDescriptorsClosed&&!cl.effectUnknown&&!cl.registrationUnknown&&cl.openPending===0);
  eq("home/"+i+"/open-registered",cl.openAttempts,cl.fdRows.length);
  eq("home/"+i+"/no-close-error",cl.closeErrors,[]);
  for(let j=0;j<cl.fdRows.length;j++)yes("home/"+i+"/fd/"+j+"/once-closed",cl.fdRows[j].closeAttempted===true&&cl.fdRows[j].closed===true);
  eq("home/"+i+"/unclaimed-inventory",cl.directoryContentsExhaustivelyInventoried,false);
 }
 eq("home/fd-count",homeFDs,10);
 eq("fd/total-enumerated",5+homeFDs+pc.returnedPipeCount,20);
 const emptyR=report.homeResources.find(x=>x.name==="empty").closure,controlR=report.homeResources.find(x=>x.name==="control").closure;
 eq("home/empty-full9-stable",emptyR.currentRootIdentity,report.emptyRootInitialFull9);
 eq("home/empty-no-io",emptyR.counts,{metadata:46,readBytes:0,readCalls:0,writeBytes:0,writeCalls:0});
 eq("home/control-fixed-io",controlR.counts,{metadata:82,readBytes:6909,readCalls:2,writeBytes:6909,writeCalls:1});
 const own=controlR.lastOwnCreateRootObservation;
 yes("home/create-exact-first5",own.sameRootObjectFirst5===true&&own.heldNamedFull9Equal===true);
 eq("home/current-named-exact",own.currentFull9,own.namedFull9);
 eq("home/after-create-full9",controlR.currentRootIdentity,own.currentFull9);
 eq("home/first5-before-after",own.beforeFull9.slice(0,5),own.currentFull9.slice(0,5));
 eq("log/counts",[report.log.observedRows,report.log.admittedDenialEvents,report.log.rejectedUnknownRows,report.log.rows.length],[2,0,2,2]);
 eq("log/window",report.log.measuredWindowUs,{start:q.gateWriteBeforeWallUs,end:q.allPipeEOFObservedWallUs});
 eq("log/process-predicate",[report.log.exactCurrentCarrierPid,report.log.logPredicate,report.log.logChildKnownExit,report.log.logExitedZero],[29053,predicate,0,true]);
 for(let i=0;i<report.log.rows.length;i++){const r=report.log.rows[i];eq("log/row/"+i+"/ordinal",r.ordinal,i);eq("log/row/"+i+"/admitted",r.admitted,false);eq("log/row/"+i+"/unknown-not-exported",r.unknownTextOrHashExported,false);}
 eq("log/row0/nonJSON-only",report.log.rows[0].rejectionReasons,["unadmitted_json_line_shape"]);
 eq("log/row0/semantics-unclassified",report.log.rows[0].unknownLineSemanticClassification,null);
 eq("log/row1/known-keys",Object.keys(report.log.rows[1].knownFields).sort(),["composedMessage","eventMessage","message","pid","process","processID","processIdentifier","processImagePath","timestamp"].sort());
 yes("log/row1/known-keys-all-absent",Object.values(report.log.rows[1].knownFields).every(x=>x.present===false&&x.jsonType==="absent"));
 yes("log/row1/all-admission-predicates-false",Object.values(report.log.rows[1].admissionPredicates).every(x=>x===false));
 eq("log/row1/rejection-reasons",report.log.rows[1].rejectionReasons,["message_semantics_unknown","process_origin_unknown","exact_pid_subject_not_admitted","timestamp_unknown","outside_measured_window"]);
 for(const key of ["SDKOrBusinessQualified","rawTextOrUnknownHashExported","startupRootCauseQualified","subscriptionAcknowledged","wholeSystemLogCoverageClaimed","operatingSystemLoggingConfigurationChanged","historicalOutcomesRewritten"])eq("log/limited/"+key,report.log[key],false);
 for(const key of ["noMatchesDoesNotProveNoDenial","unknownRowsAreNotClassifiedAsHeadersOrStatistics","exactPidTokenPrefilterMayExcludeRedactedOrOtherReporterEvents","filterIsNotProofOfExclusiveOSDelivery"])eq("log/limit-explicit/"+key,report.log[key],true);
 for(const key of ["NodeExecImageIndependentlyObserved","SDKOrProviderOrCredentialOperationRequested","businessQualificationClaimed","controllerDirectoryEnumeration","currentEmptyDirectoryContentsEnumerated","environmentInheritance","historicalOutcomesRewritten","launchdOperation","oldRootsOrProfilesModified","oldT5OrPrivateFilesReadByController","operatingSystemLoggingConfigurationChanged","originalAbortCauseProved","pendingSignalObserved","portOrListenerOperation","subscriptionAcknowledged"])eq("scope/"+key,report[key],false);
 yes("closure/report",report.allOwnDescriptorsAndChildrenClosed&&report.allFixedHeldNamedFencesPassed&&report.handlersRestored&&report.original45SecondDeadlineMetAfterClosure);
 yes("closure/elapsed",report.elapsedSeconds>=0&&report.elapsedSeconds<45);
 eq("release/current-outcomes",[release.actual.node.exit,release.actual.log.exit,release.actual.log.observedRows,release.actual.log.admittedDenialEvents,release.actual.log.rejectedUnknownRows],[-6,0,2,0,2]);
 eq("release/enumFDs",release.closure.parentEnumeratedFDs,20);
 for(const key of ["subscriptionAcknowledged","startupCauseQualified","SDKOrCredentialWorkExecuted","historicalUnknownUpgraded","legacyManagedCleanup","additionalNativeAuthorized"])eq("release/limited/"+key,release[key],false);
 return {schema:"heptabao.live-denial-r2-original-chain-pure-checks.r1",passed:checks.every(x=>x.passed),checkCount:checks.length,checks,originalCalls:13,returnedObservers:2,immutablePages:8,NativeCallsAdded:0,execution:"pure V8 verification of original public SDK, intents, immutable payloads, streams and bounded observation only",newPublicObservationOnly:true,admittedDenialEvents:0,unknownLogRows:2,zeroAdmittedDoesNotProveNoDenial:true,SDKQualified:false,causeQualified:false,historicalUnknownPreserved:true};
}
