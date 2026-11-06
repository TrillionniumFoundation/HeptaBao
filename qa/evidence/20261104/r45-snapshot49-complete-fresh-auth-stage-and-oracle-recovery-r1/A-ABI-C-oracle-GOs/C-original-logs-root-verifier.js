function rootTwoLogBodiesActual(f,go,author){
 const rows=[],ck=(name,v)=>{rows.push({name,passed:v===true});if(v!==true)throw Error(name);},p=gitBlobMeta,before=JSON.parse(f["INFO.STATE.before.original.json"]),after=JSON.parse(f["STATE.after.original.json"]),blobs={};for(const raw of Object.values(f))blobs[p(raw).blob]=raw;
 ck("author72_exact",author.exact&&author.value.pass&&author.value.check_count===72);
 ck("exact_BODY_GO_and_R2_journal",f["BODY.GO.original.json"]===go.text&&p(f["journal.executed.original.js"]).blob===go.value.source.blob);
 ck("old_six_calls_exact",Object.keys(before.calls).length===6&&Object.entries(before.calls).every(([k,v])=>JSON.stringify(v)===JSON.stringify(after.calls[k])));
 ck("old_two_INFO_observers_exact",JSON.stringify(before.completedObservers)===JSON.stringify(after.completedObservers.slice(0,2)));
 ck("prior_BUILD41_exact",f["prior-BUILD.original.json"]===load("r34_packet_PKI025b-report-BODY-actual-full51").raw["STATE.after.original.json"]);
 const calls=Object.entries(after.calls).filter(([k])=>!Object.hasOwn(before.calls,k)).map(([key,c])=>({key,kind:c.kind,phase:c.phase,requestPin:c.requestPin,sdkPin:c.sdkPin,nativePin:c.nativePin,requestText:f[key+".request.json"],intentText:f[key+".intent.json"],armedText:f[key+".armed.json"],sdkText:f[key+".sdk.original.json"],nativeText:f[key+".native.original.json"],armedTree:c.armed.tree}));
 const cs=verifyOriginalJournal({label:"original_test2_log_BODY",calls,observers:after.completedObservers.slice(2),blob:k=>blobs[k],goPins:[go.pins],pageLimit:()=>16384,ck});
 ck("exact_two_requests",cs.filter(x=>x.c.kind==="operation_start").every((x,i)=>p(x.c.requestText).blob===go.value.exact_requests[i].blob));
 for(let i=0;i<2;i++){const role=i===0?"stderr":"stdout",n=JSON.parse(f[role+".body.native.original.json"]),e=go.value.expected[i],raw=f[role+".original.txt"];
 ck("exact_versioned_whole_"+role,n.path===e.path&&n.version===e.version&&n.offset===0&&n.next_offset===e.bytes&&n.size===e.bytes&&n.eof===true&&n.chunk_sha256===e.sha256&&utf8Text(unb64(n.data_base64))===raw&&p(raw).bytes===e.bytes&&p(raw).sha256===e.sha256);}
 ck("actual_error_preserved",f["stderr.original.txt"].endsWith('Error: "Identity projection"\n')&&f["stdout.original.txt"].includes("0 passed; 1 failed;")&&f["stdout.original.txt"].includes("3574 filtered out"));
 ck("all_closed",Object.keys(after.calls).length===12&&after.completedObservers.length===4&&after.pending===null&&after.activeObserver===null&&!after.nativeCallInFlight&&!after.paused);
 return {schema:"heptabao.root-original-test2-two-log-bodies.r1",passed:true,checks:rows.length,rows,tree:"27fa5080fa0e3ee02a872463fa694707896b9ec1",stderr:p(f["stderr.original.txt"]),stdout:p(f["stdout.original.txt"]),exactObservedError:"Identity projection",underlyingSerializationCauseProven:false,newCalls:6,newObservers:2,newPages:2,observationLaneReleased:true,oldBuildNotRerun:true,targetReuseQualified:false,fullReplacement:false};
 }