async function verifyOfficialPki12ReportBodySource(files){
 const checks=[];function ok(v,label){checks.push({label,pass:!!v});if(!v)throw Error(label);}
 const p=JSON.parse(files["PLAN.public.json"]),before=files["journal.before.js"],after=files["journal.source.js"];
 ok(JSON.stringify(gitBlobMeta(after))===JSON.stringify(p.journal)&&JSON.stringify(gitBlobMeta(files["request.exact.json"]))===JSON.stringify(p.exactRequest),"exact new source request");
 ok(applyStrict(before,files["journal.forward.diff"])===after&&applyStrict(after,files["journal.reverse.diff"])===before,"strict bidirectional original INFO delta");
 ok((files["journal.forward.diff"].match(/^@@ /gm)||[]).length===7,"seven exact bounded hunks");
 const stateRaw=files["INFO-state.original.json"],s=JSON.parse(stateRaw),n=JSON.parse(files["INFO-native.original.json"]);
 ok(JSON.stringify(gitBlobMeta(stateRaw))===JSON.stringify(p.state),"exact actual closed state");
 ok(Object.keys(s.calls).length===10&&s.completedObservers.length===3&&!s.paused&&s.pending===null&&s.activeObserver===null&&!s.nativeCallInFlight,"ten original calls and three original observers closed");
 ok(n.path===p.target.path&&n.size===41509&&n.sha256===p.target.sha256&&n.version===p.target.version&&s.oracleReportInfo.originalOperation===p.originalInfo,"actual independent INFO exact identity");
 ok(n.metadata.metadata_platform==="linux"&&n.mode===384&&n.metadata.uid===1000&&n.metadata.gid===1000&&n.metadata.link_count===1,"same actual Linux full9 owner mode");
 const q=JSON.parse(files["request.exact.json"]),a=q.operation.arguments;
 ok(q.operation.tool==="binary_read"&&a.host==="x230"&&a.path===n.path&&a.offset===0&&a.limit===n.size&&a.expected_version===n.version,"single actual-version whole-body range");
 ok(after.includes('key:"gfr-"+a.id')&&!after.includes('key:"successor')&&!after.includes("canonical-bundle-chunk"),"no inherited fixed output archive key");
 ok(after.includes("rootGo:s.oracleReportBodyGO?.pin??s.oracleReportInfoGO?.pin??s.goPin"),"new exact GO selected for all later arms");
 ok(after.includes('if(c.kind==="operation_start" && q.operation.tool==="binary_read")s.oracleReportBodyStarted=true;'),"once marker immediately before original dispatch");
 const m=new Map([[p.existingSlot,JSON.parse(stateRaw)],[p.existingSlot+":closed_native:"+p.originalInfo,files["INFO-native.original.json"]]]),archives=[];
 const noTools=new Proxy({}, {get(){throw Error("no actual tool in pure source verification");}});
 const archive=async x=>{archives.push(x);return {whole:true,tree:"private-fake",entries:[]};};
 const api=new Function("store","load","tools","archiveFlatPublicTextsOnce",files["pure_helpers.original.js"]+"\n"+after+"\nreturn{gfRun,gfValidateRequest};")((k,v)=>m.set(k,v),k=>m.get(k),noTools,archive);
 const g={authorization:"GO",scope:p.scope,original_job:p.originalJob,info_operation:p.originalInfo,maximum_binary_read_operations:1,maximum_file_info_operations:0,maximum_process_start_calls:0,immutable_body_page_bytes:16384,exact_request:p.exactRequest,fixed_report:{path:n.path,bytes:n.size,sha256:n.sha256,version:n.version},pureOnly:true};
 const goRaw=JSON.stringify(g,null,2)+"\n",goPin=gitBlobMeta(goRaw);
 const auth=await api.gfRun("authorize_oracle_report_body",{goRaw,goPin,goWholeReadback:true});
 ok(auth.ok&&JSON.stringify(m.get(p.existingSlot).calls)===JSON.stringify(s.calls),"private authorization keeps ten original calls");
 for(const [label,change] of [["path",x=>x.operation.arguments.path+="/other"],["version",x=>x.operation.arguments.expected_version="0:0:0:0:0"],["offset",x=>x.operation.arguments.offset=1],["limit",x=>x.operation.arguments.limit--],["metadata",x=>x.operation.tool="file_info"]]){
  const bad=JSON.parse(JSON.stringify(q));change(bad);let rejected=false;try{api.gfValidateRequest(m.get(p.existingSlot),"operation_start",bad,JSON.stringify(bad,null,2)+"\n");}catch{rejected=true;}ok(rejected,"reject wrong "+label);
 }
 let processRejected=false;try{api.gfValidateRequest(m.get(p.existingSlot),"process_start",{},"{}\n");}catch{processRejected=true;}ok(processRejected,"reject process restart");
 const prep=await api.gfRun("prepare",{kind:"operation_start",requestRaw:files["request.exact.json"],callKey:"pure-pki12-body"});
 ok(prep.ok&&archives.length===1&&JSON.parse(archives[0].texts["armed.json"]).rootGo.blob===goPin.blob,"actual private prepare selects new BODY GO");
 ok(JSON.stringify(Object.fromEntries(Object.keys(s.calls).map(k=>[k,m.get(p.existingSlot).calls[k]])))===JSON.stringify(s.calls),"private prepare preserves original call map");
 ok(after.includes('s.activeObserver.tool==="binary_read"?GF_ORACLE_REPORT_BODY_PAGE_BYTES:8192')&&p.immutableBodyPageBytes===16384&&p.oldPageBytes===8192,"new body16K old pages8K");
 ok(after.includes('length<8,"original_status_budget_eight"')&&after.includes('length<128,"original_page_budget_128"')&&after.includes("v.total_bytes<=1048576"),"finite status page and payload limits");
 ok(after.indexOf('texts:{"report.original.json":bodyRaw}')<after.indexOf('s.oracleReportBody={path:t.path'),"decoded body external before published observation");
 return {schema:"heptabao.pki12-report-body-source-checks.v1",pass:true,check_count:checks.length,checks,NativeCalls:0,GitCalls:0,realSlotsMutated:false};
}
