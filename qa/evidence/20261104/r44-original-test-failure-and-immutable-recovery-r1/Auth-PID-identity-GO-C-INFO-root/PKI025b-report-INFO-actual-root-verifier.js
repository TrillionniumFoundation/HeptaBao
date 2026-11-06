
function qualifyBuildReportInfoActual(p,sourcePacket,go){
 const checks=[],ck=(name,ok)=>checks.push({name,pass:ok===true}),pin=(raw,expected)=>{const m=gitBlobMeta(raw);return m.blob===expected.blob&&m.bytes===expected.bytes&&m.sha256===expected.sha256;};
 const r=JSON.parse(p.raw["RELEASE.public.json"]),b=JSON.parse(p.raw["STATE.before.original.json"]),a=JSON.parse(p.raw["STATE.after.original.json"]),v=parseLosslessIntegers(p.raw["metadata.native.original.json"]),md=r.metadata;
 ck("whole_actual23",p.audit.tree==="26581e676cae80a0433de0d793c27bcb6d724c58"&&p.pins.length===23&&p.pins.reduce((n,x)=>n+x.bytes,0)===264091);
 ck("same_original_INFO_GO_and_journal",p.raw["ROOT-GO.original.json"]===go.text&&pin(p.raw["ROOT-GO.original.json"],go.pins)&&p.raw["journal.executed.original.js"]===sourcePacket.raw["journal.after.source.js"]);
 ck("original_boundary_state_exact",p.raw["STATE.before.original.json"]===sourcePacket.raw["STATE.before.original.json"]);
 ck("all_original_31_calls_unchanged",Object.keys(b.calls).length===31&&Object.keys(a.calls).length===34&&Object.entries(b.calls).every(([k,x])=>JSON.stringify(x)===JSON.stringify(a.calls[k])));
 ck("original_10_observers_unchanged",b.completedObservers.length===10&&a.completedObservers.length===11&&b.completedObservers.every((x,i)=>JSON.stringify(x)===JSON.stringify(a.completedObservers[i])));
 const byBlob={};for(const raw of Object.values(p.raw))byBlob[gitBlobMeta(raw).blob]=raw;
 const calls=r.calls.map((x,i)=>{const key=x.key,pre=String(i+1).padStart(2,"0")+"."+key+".",c=a.calls[key];return {key,kind:c.kind,phase:c.phase,requestPin:c.requestPin,sdkPin:c.sdkPin,nativePin:c.nativePin,requestText:p.raw[pre+"request.json"],intentText:p.raw[pre+"intent.json"],armedText:p.raw[pre+"armed.json"],sdkText:p.raw[pre+"original.sdk.json"],nativeText:p.raw[pre+"original.native.json"],armedTree:c.armed.tree};});
 const cs=verifyOriginalJournal({label:"PKI025b_report_INFO",calls,observers:[r.original],blob:sha=>byBlob[sha],goPins:[go.pins],pageLimit:()=>8192,ck});
 ck("one_original_INFO_start",cs.length===3&&cs[0].q.operation.tool==="file_info"&&pin(cs[0].c.requestText,go.value.exact_request)&&cs[0].n.reused===false);
 ck("whole_payload_and_native_metadata",pin(p.raw["metadata.native.original.json"],r.original.nativeText)&&pin(p.raw["payload.original.json"],r.original.payload)&&JSON.parse(p.raw["payload.original.json"]).content[0].text===p.raw["metadata.native.original.json"]);
 ck("fresh_report_exact_path_hash",v.path===go.value.report.path&&v.sha256===go.value.report.whole_sha256&&v.size===49775&&v.size<=go.value.report.maximum_size);
 ck("actual_linux_permissions_and_owner",v.mode===384&&v.metadata.metadata_platform==="linux"&&v.metadata.mode===384&&v.metadata.uid===1000&&v.metadata.gid===1000&&v.metadata.link_count===1);
 const parts=v.version.split(":");
 ck("lossless_actual_version",parts.length===5&&parts.every(x=>/^[0-9]+$/.test(x))&&parts[2]==="49775"&&v.version==="66306:33202271:49775:1793974567959218921:1793974567959218921");
 const full9=[parts[0],parts[1],"1000","1000","33152","1",parts[2],parts[3],parts[4]];
 ck("metadata_binding_exact",md.path===v.path&&md.size===v.size&&md.sha256===v.sha256&&md.version===v.version&&JSON.stringify(md.full9Strings)===JSON.stringify(full9)&&md.originalOperation===r.original.id&&md.regularFileFromNativeFileInfoContract===true&&md.binaryReadAuthorized===false);
 ck("call_accounting_and_idle",r.new_native_calls===3&&r.new_observers===1&&r.new_pages===1&&r.total_calls===34&&r.total_closed_observers===11&&a.pending===null&&a.activeObserver===null&&!a.nativeCallInFlight&&!a.paused&&r.pending===null&&r.active_observer===null&&!r.native_call_in_flight&&r.lane_released);
 ck("report_body_not_yet_observed",r.body_observed===false&&r.body_authorized===false&&r.target_reuse_authorized===false&&r.failure_cause===null&&r.actual_test_results===null);
 return {schema:"heptabao.root.PKI025b-original-report-INFO-actual23-qualification.r44",passed:checks.every(x=>x.pass),checkCount:checks.length,checks,packet:p.audit.tree,originalJob:"rog/1a1b10cad9b-fc05-7560",originalInfoOperation:r.original.id,originalNativeCalls:3,originalPages:1,originalObserversClosed:1,metadata:md,nativeLaneReleased:true,reportBodyObserved:false,failureCause:null,actualTestsQualified:false,cargoTargetReuseQualified:false,newNativeCalls:0};
}
