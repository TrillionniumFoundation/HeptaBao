function verifyNodeVersionComparisonR1OriginalChain(files) {
 const checks=[];
 const stable=x=>Array.isArray(x)?x.map(stable):x&&typeof x==="object"?Object.fromEntries(Object.keys(x).sort().map(k=>[k,stable(x[k])])):x;
 const eq=(name,a,b)=>checks.push({name,passed:JSON.stringify(stable(a))===JSON.stringify(stable(b))});
 const yes=(name,x)=>checks.push({name,passed:x===true});
 const parse=path=>parseLosslessIntegers(files[path]);
 const meta=gitBlobMeta;
 const go=parse("GO.original.json"),calls=parse("calls.index.public.json"),obs=parse("observers.index.public.json");
 const state=parse("final-state.public.json"),release=parse("RELEASE.public.json"),report=parse("stdout.original.json");
 const job="1a1b2feebf1-fc05-8067";
 const integer=x=>Number.isSafeInteger(x)?String(x):x&&typeof x.$exactInteger==="string"?x.$exactInteger:null;
 eq("go/original-whole",meta(files["GO.original.json"]),{"blob":"be3fda34d624811838bfd20bfe3fe018c90f7213","bytes":17618,"sha256":"8fcd3db2db26e5a86117b2b0435673a5a19f6d14538c369ba72ebb7893596901"});
 eq("exact/counts",[calls.length,obs.length,obs.reduce((n,o)=>n+o.pages,0)],[11,2,6]);
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
    const expected=n==="stdout"?11541:0;
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
    eq("stream/"+a.id+"/"+n+"/size",row.size,n==="stdout"?11541:0);
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
   yes("op/"+i+"/key-prefix",q.idempotency_key.startsWith("heptabao-mac-public-node-version-b131f14c-"));
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
 eq("counts/native",counts,{process_start:1,operation_start:2,operation_status:2,operation_result:6});
 yes("final/all-observers-closed",active===null&&finished===2);
 eq("final/stdout-original",stdout,files["stdout.original.json"]);eq("final/stderr-original",stderr,files["stderr.original.txt"]);
 eq("final/extents",[nextOut,nextErr],[11541,0]);
 eq("final/whole-stdout",meta(stdout),{"blob":"78cd8bf07cd5ad277bed942eb61819ace932716e","bytes":11541,"sha256":"9b80b771febdca6c9434779056248639b49c2acc545e2a1df186c4529b7432c3"});
 yes("final/context-zero",state.job===job&&state.nativeCallInFlight===false&&state.pending===null&&state.activeObserver===null&&state.paused===false);
 yes("final/release-zero",release.currentNativeState.nativeCallInFlight===false&&release.currentNativeState.activeFutures===0&&release.currentNativeState.laneReleased===true);
 eq("final/release-counts",[release.originalCallCount,release.originalObserverCount,release.immutablePageCount],[11,2,6]);



 yes("report/no-error",!Object.hasOwn(report,"error"));
 eq("report/schema",report.schema,"heptabao.mac-public-node-version-profile-comparison.r1");
 eq("report/result",[report.ok,report.observationComplete,report.bothVersionArmsSucceeded,report.outcomeUnknown,report.comparison],[true,true,false,false,"baseline-version-ok-restricted-sigabrt"]);
 yes("report/own-closure",report.allOwnDescriptorsAndChildrenClosed===true&&report.allFixedHeldNamedFencesPassed===true&&report.handlersRestored===true&&report.pendingSignalObserved===false&&report.original45SecondDeadlineMetAfterClosure===true);
 yes("report/deadline",report.elapsedSeconds>=0&&report.elapsedSeconds<45);
 const node="/opt/homebrew/Cellar/node/25.9.0_1/bin/node",control="/Users/qianqi/heptabao-public-node-version-20261106-r1-control",empty="/Users/qianqi/heptabao-public-node-version-20261106-r1-empty";
 eq("report/fresh-fixed-roots",[report.controlRoot,report.emptyHomeAndCwd,report.cwd],[control,empty,empty]);
 eq("report/exact-env",report.environment,{HOME:empty,TMPDIR:empty,PATH:"/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",LANG:"C",LC_ALL:"C"});
 eq("report/env-cwd-profile",[report.environmentInheritance,report.sameEnvironmentAndCwdForBothArms,report.noNodeOptionsOrDyldVariables,report.profileBytesUnchanged],[false,true,true,true]);
 eq("report/profile-actual",[report.profileActual.path,report.profileActual.bytes,report.profileActual.sha256],[control+"/consumer.sb",6909,"acfbd336488f774e3acb87392bf5305f62004a0f529cbcd876593407989e7a12"]);
 eq("report/profile-actual-full9",report.profileActual.identity,["16777233","593591711","501","20","33152","1","6909","1794004421162461048","1794004421162461048"]);
 eq("report/arms-command-count",[report.arms.length,report.commands.commands.length,report.commands.unknownCommandCount,report.commands.allOwnedCommandsStopped],[2,2,0,true]);
 const expected=[
  {label:"restricted-version",argv:["/usr/bin/sandbox-exec","-f",control+"/consumer.sb",node,"--version"],pid:11162,exit:-6,stdout:0,profile:true,version:false,value:null,retained:{code:2,pid:11162,signo:20,status:6}},
  {label:"baseline-version",argv:[node,"--version"],pid:11171,exit:0,stdout:8,profile:false,version:true,value:"v25.9.0",retained:{code:1,pid:11171,signo:20,status:0}}
 ];
 for(let i=0;i<2;i++){
  const arm=report.arms[i],c=arm.command,cl=c.cleanup,e=expected[i];
  eq("arm/"+i+"/label-profile-version",[arm.label,arm.testProfileApplied,arm.versionSucceeded],[e.label,e.profile,e.version]);
  eq("arm/"+i+"/command-original",c,report.commands.commands[i]);
  eq("arm/"+i+"/exact-argv",c.argv,e.argv);
  eq("arm/"+i+"/known-outcome",[c.pid,c.exitCode,c.stdoutBytes,c.stderrBytes,c.outcomeUnknown,c.streamsClosed,c.completeBeforeDeadline],[e.pid,e.exit,e.stdout,0,false,true,true]);
  eq("arm/"+i+"/public-stdout",arm.stdout,{bytes:e.stdout,publicVersionSyntax:e.version,unknownTextOrHashExported:false,value:e.value});
  eq("arm/"+i+"/stderr",[arm.stderrBytes,arm.stderrEmpty,arm.stderrTextOrHashExported],[0,true,false]);
  eq("arm/"+i+"/retained-exit",cl.retainedExit,e.retained);
  yes("arm/"+i+"/owned-closure",cl.ok===true&&cl.outcomeUnknown===false&&cl.directChildReaped===true&&cl.ownedLiveGroupEmptyBeforeReap===true&&cl.allGroupRowsEmptyAfterReap===true);
  eq("arm/"+i+"/signals-groups",[cl.signals,cl.initialLiveGroup,cl.remainingGroupRows,cl.postReapSignalSent],[[],[],[],false]);
  eq("arm/"+i+"/custody",[cl.custody.ps.pid,cl.custody.ps.ppid,cl.custody.ps.pgid,cl.custody.ps.uid,cl.custody.sid_observed_while_live],[e.pid,11160,e.pid,501,e.pid]);
  eq("arm/"+i+"/observed-birth",cl.custody.ps.start,"Sat Nov  7 06:33:41 2026    ");
  eq("arm/"+i+"/unchanged-cleanup-caps",cl.cleanupCaps,{group:3,psMax:4,term:1,wait:5});
  yes("arm/"+i+"/within-deadlines",c.elapsedSeconds>=0&&c.elapsedSeconds<10&&cl.elapsedSeconds>=0&&cl.elapsedSeconds<14);
 }
 eq("report/input-closure",report.inputs,{allReturnedInputFdsClosed:true,closeErrors:[],fixedInputCount:4,metadataCalls:74,readBytes:375824,readCalls:12,returnedFdLedger:{attempts:4,knownNoReturnErrors:0,pending:0,registered:4,registrationUnknown:false}});
 eq("report/home-count",report.homeResources.length,2);
 let homeFD=0;
 for(const h of report.homeResources){
  const cl=h.closure,n=h.name;
  yes("home/"+n+"/known-initialized-fenced-closed",h.initializationStarted===true&&h.initializationCompleted===true&&h.finalFencePassed===true&&h.closeError===null&&cl.initStarted===true&&cl.initComplete===true&&cl.rootCreationAttempted===true&&cl.rootCreated===true&&cl.allReturnedDescriptorsClosed===true&&cl.allFiniteLeavesClosed===true&&cl.effectUnknown===false&&cl.registrationUnknown===false&&cl.openPending===0);
  eq("home/"+n+"/path",[h.root,cl.path],[n==="empty"?empty:control,n==="empty"?empty:control]);
  eq("home/"+n+"/no-close-errors",cl.closeErrors,[]);
  yes("home/"+n+"/every-returned-closed-once",cl.fdRows.every(x=>x.closeAttempted===true&&x.closed===true));
  eq("home/"+n+"/attempts-and-rows",[cl.openAttempts,cl.fdRows.length],n==="empty"?[4,4]:[6,6]);
  yes("home/"+n+"/scope",cl.directoryContentsExhaustivelyInventoried===false&&cl.privateCredentialPlansMovedHere===false&&cl.interpreterAndDynamicLoaderInternalFdsNotEnumerated===true&&cl.sharedParentsUseFirst5ObjectIdentity===true&&cl.currentRootFull9UpdatedOnlyAfterOwnExclusiveCreate===true);
  if(n==="empty"){
   eq("home/empty/no-controller-leaf-io",cl.counts,{metadata:70,readBytes:0,readCalls:0,writeBytes:0,writeCalls:0});
   eq("home/empty/no-ownleaf-update",cl.lastOwnCreateRootObservation,null);
   eq("home/empty/full9-kept",cl.currentRootIdentity,report.emptyRootInitialFull9);
  }else{
   eq("home/control/one-public-profile-io",cl.counts,{metadata:109,readBytes:6909,readCalls:2,writeBytes:6909,writeCalls:1});
   const o=cl.lastOwnCreateRootObservation;
   eq("home/control/current-named-full9",o.currentFull9,o.namedFull9);
   eq("home/control/root-updated",cl.currentRootIdentity,o.currentFull9);
   eq("home/control/object-first5",o.currentFull9.slice(0,5),o.beforeFull9.slice(0,5));
   eq("home/control/observed-equality",o.fieldEqualToBefore,o.currentFull9.map((x,i)=>x===o.beforeFull9[i]));
   yes("home/control/explicit-match",o.sameRootObjectFirst5===true&&o.heldNamedFull9Equal===true);
  }
  homeFD+=cl.fdRows.length;
 }
 eq("report/application-fd-total",homeFD+report.inputs.returnedFdLedger.registered,14);
 for(const k of ["JavaScriptEntryPointRequested","SDKOrProviderOrCredentialOperationRequested","baselineWithoutTestProfileQualifiesSDK","businessQualificationClaimed","controllerDirectoryEnumeration","currentEmptyDirectoryContentsEnumerated","environmentInheritance","historicalOutcomeRewritten","launchdOperation","oldPublicProbeReplayed","oldRootsOrProfilesModified","oldT5OrPrivateFilesReadByController","originalAbortCauseProved","originalBusinessReplay","portOrListenerOperation"])eq("scope/"+k,report[k],false);
 yes("scope/no-internal-io-overclaim",report.childInternalIoNotSyscallTraced===true&&report.execByPathIsNotAtomicExecByFd===true&&report.emptyAtExclusiveDirectoryCreation===true);
 eq("release/original-report-facts",[release.actualDiagnostic.comparison,release.ownClosure.applicationDescriptors,release.additionalNativeAuthorized,release.historicalManagedOrHelperUnknownUpgraded],["baseline-version-ok-restricted-sigabrt",14,false,false]);
 return {schema:"heptabao.node-version-comparison-r1-original-chain-pure-checks.r1",passed:checks.every(x=>x.passed),checkCount:checks.length,checks,originalCalls:11,returnedObservers:2,immutablePages:6,NativeCallsAdded:0,execution:"pure V8 original public SDK/intent/payload/stream verification only",comparison:"baseline-version-ok-restricted-sigabrt",specificRuleCauseQualified:false,oldBusinessProgressQualified:false,SDKQualified:false,baselineAloneQualifiesSDK:false,historicalUnknownPreserved:true};
}
