async function verifyOracleR2Body02RecoverySource(x) {
 const checks=[];function ck(name,v){checks.push({name,passed:!!v});if(!v)throw Error(name);}
 const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b),old=JSON.parse(x.pausedRaw),id=x.originalID,slot="official271_x230_acl23_r2_body02_status_reconcile_r1",oldSlot="official271_x230_acl23_oracle_gitfirst_r2";
 ck("strict source forward",applyStrict(x.before,x.diff,false)===x.after);
 ck("strict source reverse",applyStrict(x.after,x.diff,true)===x.before);
 ck("exact original paused state pin",same(gitBlobMeta(x.pausedRaw),{blob:"652b0103388657f5515e30c077ce927c24b19cf2",bytes:454676,sha256:"dd4a465e95e91c8aa23ddcde138d4541a52e79e7482297eb418bb89e16f83aa3"}));
 ck("exact original returned ID and request",old.activeObserver.id===id&&id==="6220e2762757d7afa1ba315c7beb2a985c59c147ac7cb3852aa17ba9c21c7a9e"&&old.activeObserver.tool==="binary_read"&&same(old.activeObserver.request,JSON.parse(x.originalAdmitRaw)));
 ck("original exact BODY2 range",old.activeObserver.request.operation.arguments.offset===131072&&old.activeObserver.request.operation.arguments.limit===65536&&old.activeObserver.request.operation.arguments.expected_version===x.need.version);
 ck("original status0 failure and budget one retained",old.paused&&old.pending===x.originalStatusKey&&old.calls[x.originalStatusKey].called===true&&old.calls[x.originalStatusKey].phase==="native_interpretation_refused"&&old.calls[x.originalStatusKey].sdkArchive.whole===true&&JSON.parse(x.oldStatusSDK).isError===true);
 ck("original status SDK raw pin",gitBlobMeta(x.oldStatusSDK).blob===old.calls[x.originalStatusKey].sdkPin.blob);
 ck("original three starts/two completed ranges",old.oracleReportBodyStarted===3&&old.oracleReportBodyRanges.length===2&&old.completedObservers.length===5&&Object.keys(old.calls).length===28);
 ck("one exact status query same arguments",same(JSON.parse(x.requestRaw),{operation_id:id})&&same(gitBlobMeta(x.requestRaw),x.requestPin));
 function defs(raw){const m=[...raw.matchAll(/^(?:async )?function (\w+)\(/gm)],o={};m.forEach((a,i)=>{o[a[1]]=raw.slice(a.index,i+1<m.length?m[i+1].index:raw.length).trimEnd();});return o;}
 const a=defs(x.before),b=defs(x.after),changed=["gfInitializeOnlyAfterRootGO","gfValidateRequest","gfAcceptArchivedSDK","gfCloseOriginalObserver"];
 ck("same thirteen functions",Object.keys(a).length===13&&Object.keys(b).length===13);
 for(const n of Object.keys(a).filter(n=>!changed.includes(n)))ck("unchanged "+n,a[n]===b[n]);
 ck("closed dispatch only status/result",!b.gfInvokePreparedOnce.includes("controller_operation_start")&&!b.gfInvokePreparedOnce.includes("controller_process_start")&&b.gfInvokePreparedOnce.includes("controller_operation_status")&&b.gfInvokePreparedOnce.includes("controller_operation_result"));
 ck("accept unchanged except new16K page cap",b.gfAcceptArchivedSDK===a.gfAcceptArchivedSDK.replace("b.length<=8192","b.length<=16384"));
 ck("full payload external before native parse",b.gfCloseOriginalObserver.indexOf("await archiveFlatPublicTextsOnce")<b.gfCloseOriginalObserver.indexOf("const p=parseLosslessIntegers(raw)"));
 ck("chunk exact bytes/version/hash guards",b.gfCloseOriginalObserver.includes("v.version===t.version")&&b.gfCloseOriginalObserver.includes("bodyBytes.length===65536")&&b.gfCloseOriginalObserver.includes("sha256Latin1(byteString(bodyBytes))===v.chunk_sha256"));
 ck("no partial report semantic parsing",!b.gfCloseOriginalObserver.includes("JSON.parse(utf8Text(bodyBytes))")&&!b.gfCloseOriginalObserver.includes("parseLosslessIntegers(utf8Text(bodyBytes))"));
 const g={authorization:"GO",scope:"official271_r2_original_body02_same_id_status_reconciliation_only",original_job:old.job,original_operation_id:id,maximum_new_operation_status_calls:1,original_operation_status_calls:1,maximum_combined_operation_status_calls:8,maximum_operation_result_calls:128,maximum_operation_start_calls:0,maximum_process_start_calls:0,immutable_page_bytes:16384,maximum_payload_bytes:1048576,exact_status_request:x.requestPin},goRaw=JSON.stringify(g)+"\n",goPin=gitBlobMeta(goRaw);
 function factory(){const memory=new Map([[oldSlot,JSON.parse(x.pausedRaw)],[oldSlot+":original_sdk_raw:"+x.originalStatusKey,x.oldStatusSDK]]),archives=[];
  const archive=async q=>{archives.push(q);return {whole:true,tree:"b".repeat(40)};};
  const api=new Function("tools","store","load","archiveFlatPublicTextsOnce",x.pure+"\n"+x.after+"\nreturn {init:gfInitializeOnlyAfterRootGO,state:gfState,validate:gfValidateRequest,prepare:gfPrepareOne};")({},(k,v)=>memory.set(k,v),k=>memory.get(k),archive);
  return {memory,archives,api,get:()=>memory.get(slot)};
 }
 const init=f=>f.api.init({goRaw,goPin,goWholeReadback:true,originalStateRaw:x.pausedRaw});
 function rejects(fn){try{fn();return false;}catch{return true;}}
 const f=factory();init(f);
 ck("new context retains old immutable",JSON.stringify(f.memory.get(oldSlot),null,2)+"\n"===x.pausedRaw&&f.get().originalStatusCalls===1&&f.get().reconcileStatusCalls===0);
 ck("observer cloned without resetting old future",f.get().activeObserver.id===id&&f.get().activeObserver.futureClosed===false&&f.get().activeObserver.nextPageOffset===0&&f.get().activeObserver.pages.length===0);
 ck("new context cannot reinitialize",rejects(()=>init(f)));
 f.api.validate(f.get(),"operation_status",JSON.parse(x.requestRaw),x.requestRaw);ck("one exact status guard accepted",true);
 ck("wrong ID refused",rejects(()=>f.api.validate(f.get(),"operation_status",{operation_id:"f".repeat(64)},JSON.stringify({operation_id:"f".repeat(64)}))));
 ck("operation_start refused",rejects(()=>f.api.validate(f.get(),"operation_start",JSON.parse(x.originalAdmitRaw),x.originalAdmitRaw)));
 ck("process_start refused",rejects(()=>f.api.validate(f.get(),"process_start",{},"{}")));
 ck("payload before closure refused",rejects(()=>f.api.validate(f.get(),"operation_result",{operation_id:id,offset:0,limit:16384},"{}")));
 f.get().reconcileStatusCalls=1;ck("second new status refused",rejects(()=>f.api.validate(f.get(),"operation_status",JSON.parse(x.requestRaw),x.requestRaw)));
 f.get().activeObserver.futureClosed=true;const page={operation_id:id,offset:0,limit:16384};f.api.validate(f.get(),"operation_result",page,JSON.stringify(page));ck("closed original first16K page guard accepted",true);
 ck("wrong original page cursor refused",rejects(()=>f.api.validate(f.get(),"operation_result",{operation_id:id,offset:16384,limit:16384},"{}")));
 f.get().activeObserver.pages=Array(128).fill({sourceOnlyFake:true});ck("129th original page refused",rejects(()=>f.api.validate(f.get(),"operation_result",page,"{}")));
 const arm=factory();init(arm);await arm.api.prepare({callKey:"oracle-r2-body02-status-recovery-fake",kind:"operation_status",requestRaw:x.requestRaw});
 ck("actual prepare new GO arm whole",arm.archives.length===1&&JSON.parse(arm.archives[0].texts["armed.json"]).rootGo.blob===goPin.blob&&JSON.parse(arm.archives[0].texts["intent.json"]).rootGo.blob===goPin.blob);
 ck("actual prepare leaves original exact state",JSON.stringify(arm.memory.get(oldSlot),null,2)+"\n"===x.pausedRaw);
 const bad=factory();init(bad);bad.memory.get(oldSlot).paused=false;ck("every further step detects old context change",rejects(()=>bad.api.state()));
 return {schema:"heptabao.official271.r2.body02.same-ID-recovery.source-checks.r1",pass:true,check_count:checks.length,checks,NativeCalls:0,PythonRuns:0,oldStatusConsumed:1,newStatusMaximum:1,originalStatusTotalMaximum:8,originalPayloadPagesMaximum:128,immutablePageBytes:16384,payloadBytesMaximum:1048576,operationStartMaximum:0,processStartMaximum:0,handbackAuthorized:false,reportSemanticParsing:false,sourceOnlyFake:true};
}
