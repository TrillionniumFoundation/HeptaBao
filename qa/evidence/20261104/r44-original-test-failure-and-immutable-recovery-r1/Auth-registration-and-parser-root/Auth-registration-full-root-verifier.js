
function qualifyRegistrationActual(p,go,minimum){
 const checks=[],ck=(name,ok)=>checks.push({name,pass:ok===true});
 const pin=(raw,expected)=>{const m=gitBlobMeta(raw);return m.blob===expected.blob&&m.bytes===expected.bytes&&m.sha256===expected.sha256;};
 const s=JSON.parse(p.raw["journal-final-state.original.json"]),ci=JSON.parse(p.raw["original-calls.index.public.json"]),oi=JSON.parse(p.raw["original-observers.index.public.json"]),manifest=JSON.parse(p.raw["MANIFEST.public.json"]);
 ck("whole_packet_pinned",p.audit.tree==="061b2fe4336d34e50943fd216c2b2166df1b3a64"&&p.pins.length===86&&p.pins.reduce((n,x)=>n+x.bytes,0)===585889);
 ck("exact_manifest",manifest.entries.length===85&&manifest.countExcludingManifest===85&&manifest.entries.every(x=>pin(p.raw[x.path],x))&&manifest.entries.reduce((n,x)=>n+x.bytes,0)===manifest.bytesExcludingManifest);
 ck("root_GO_exact",pin(p.raw["reference-GO.original.json"],go.pins)&&p.raw["reference-GO.original.json"]===go.text&&go.pins.blob==="5b49bee04a4203169b7858f2e1be1b93f96d6b37");
 ck("minimal_actual_members_unchanged",Object.keys(minimum.raw).every(k=>p.raw[k]===minimum.raw[k]));
 ck("calls_index_all_original",ci.length===12&&ci.every(x=>s.calls[x.key]&&s.calls[x.key].kind===x.kind)&&new Set(ci.map(x=>x.key)).size===12&&Object.keys(s.calls).length===12);
 ck("observers_index_all_original",oi.length===2&&s.completedObservers.length===2&&oi.every(x=>s.completedObservers.some(y=>y.id===x.id&&y.tool===x.tool&&y.payload.blob===x.payload.blob&&y.nativeText.blob===x.nativeText.blob&&y.payloadTree===x.payloadTree)));
 const rawCalls={},rawPayloads={},byBlob={};
 for(const [path,raw] of Object.entries(p.raw))byBlob[gitBlobMeta(raw).blob]=raw;
 const calls=ci.map(x=>{const c=s.calls[x.key];const z={};for(const [k,path] of Object.entries(x.paths))z[k]=p.raw[path];rawCalls[x.key]=z;
 ck(x.key+"_index_pins",pin(z.requestRaw,x.request)&&pin(z.sdkRaw,x.sdk)&&pin(z.nativeRaw,x.native)&&x.armedTree===c.armed.tree&&x.sdkTree===c.sdkArchive.tree);
 return {key:x.key,kind:c.kind,phase:c.phase,requestPin:c.requestPin,sdkPin:c.sdkPin,nativePin:c.nativePin,requestText:z.requestRaw,intentText:z.intentRaw,armedText:z.armedRaw,sdkText:z.sdkRaw,nativeText:z.nativeRaw,armedTree:c.armed.tree};});
 for(const o of oi)rawPayloads[o.id]={payloadRaw:p.raw[o.paths.payloadRaw],nativeRaw:p.raw[o.paths.nativeRaw]};
 const author=verifyCurrentRegistrationOriginalEvidence({state:s,calls:rawCalls,payloads:rawPayloads,authorityRaw:p.raw["actual--authority.original.json"],stdoutRaw:p.raw["actual--stdout.original.txt"],stderrRaw:p.raw["actual--stderr.original.txt"]});
 ck("author_207_exact_reproduction",author.passed===true&&author.checkCount===207&&JSON.stringify(author)===JSON.stringify(JSON.parse(p.raw["actual-pure-verifier-result.public.json"])));
 const rows=verifyOriginalJournal({label:"original_registration",calls,observers:s.completedObservers,blob:sha=>byBlob[sha],goPins:[go.pins],pageLimit:()=>8192,ck});
 const start=rows.find(x=>x.c.kind==="process_start"),binding=processStartBinding(start.q),g=JSON.parse(go.text);
 ck("typed_start_whole_and_exact",pin(start.c.requestText,g.exactProcessStart)&&gitBlobMeta(start.q.stdin).blob===g.exactSource.blob&&gitBlobMeta(start.q.stdin).sha256===g.exactSource.sha256&&binding.sha256===g.nativeBinding.sha256&&binding.native_fingerprint===g.nativeBinding.native_fingerprint&&utf8Bytes(binding.canonical).length===g.nativeBinding.canonicalBytes);
 ck("ACK_exact_job_and_binding",start.n.job.id==="1a1b12864e2-fc05-765c"&&start.n.reused===false&&start.n.job.request_digest===binding.sha256&&start.n.job.request_fingerprint.$exactInteger===binding.native_fingerprint);
 const admissions=rows.filter(x=>x.c.kind==="operation_start");
 ck("only_original_observer_scope",admissions.length===2&&admissions.every(x=>x.q.operation.arguments.host==="mac"&&x.q.operation.arguments.job_id===start.n.job.id&&["process_status","process_read"].includes(x.q.operation.tool)));
 ck("observation_count_caps",admissions.filter(x=>x.q.operation.tool==="process_status").length<=g.observations.maximumProcessStatusObservers&&admissions.filter(x=>x.q.operation.tool==="process_read").length<=g.observations.maximumProcessReadObservers&&oi.every(x=>x.pages<=g.observations.maximumImmutablePagesPerObserver&&x.payload.bytes<=g.observations.maximumSerializedOriginalPayloadBytes));
 ck("journal_idle",s.pending===null&&s.activeObserver===null&&!s.nativeCallInFlight&&!s.paused);
 const r=JSON.parse(p.raw["actual--stdout.original.txt"]),a=JSON.parse(p.raw["actual--authority.original.json"]);
 ck("diagnosis_succeeded_owned_resources_closed",a.state==="succeeded"&&a.exit_code===0&&a.output_complete&&a.output_durable&&a.terminal_publication_confirmed&&r.ok&&r.observationComplete&&r.allReturnedApplicationFdsClosed&&r.allDirectHelpersClosed);
 ck("live_registration_not_claimed_closed",r.currentManagedScopeStillUnknown===true&&r.registrationClosureClaimed===false&&r.managedProcessReaped===false&&r.bootstrapBootoutOrSignalCalled===false);
 ck("actual_blocker_exactly_never_exited",r.prints.length===2&&r.prints.every(x=>x.projection.fieldFacts["last exit code"].recognizedLiteral==="(never exited)"&&x.projection.fieldFacts.pid.typedInteger===32527&&x.projection.fieldFacts.runs.typedInteger===1&&x.projection.fieldFacts.state.knownState==="running"&&JSON.stringify(x.projection.rejectedFixedIntegerFields)==='["last exit code"]'));
 ck("no_credential_or_production_phase",!r.privatePlansCapsuleOrCredentialsRead&&!r.sdkFactoryProviderOrRefreshCalled&&!r.productBusinessOrCleanupDispatched&&!r.newFilesOrDirectoriesCreated);
 const result={schema:"heptabao.root.original-registration-diagnostic-full86-qualification.r44",passed:checks.every(x=>x.pass),checkCount:checks.length,checks,packet:p.audit.tree,originalJob:"mac/1a1b12864e2-fc05-765c",originalCalls:12,originalObservers:2,originalPages:7,stdoutBytes:13957,stderrBytes:0,authorChecksReproduced:207,observedFailureLiteral:"(never exited)",observedPid:32527,observedRuns:1,observationClosed:true,managedScope:"UNKNOWN",credentialCycleSuccess:false,newNativeCalls:0,fullReplacement:false};
 return {result,author};
}
