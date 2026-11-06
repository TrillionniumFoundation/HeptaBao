async function verifyOracleReportInfoSource(files) {
 const checks=[];function check(name,v){checks.push({name,passed:!!v});if(!v)throw Error(name);}
 const meta=gitBlobMeta,same=(a,b)=>JSON.stringify(a)===JSON.stringify(b),plan=JSON.parse(files["PLAN.public.json"]),before=files["journal.before.js"],after=files["journal.after.js"];
 check("strict forward whole",applyStrict(before,files["journal.strict.diff"],false)===after);
 check("strict reverse whole",applyStrict(after,files["journal.strict.diff"],true)===before);
 check("exact after source",same(meta(after),plan.source));
 check("exact original journal",same(meta(before),plan.before));
 check("exact original prior state",same(meta(files["PRIOR-STATE.original.json"]),plan.originalState));
 check("actual stdout exact",same(meta(files["STDOUT.original.txt"]),plan.originalStdout));
 check("one exact request",same(meta(files["REQUEST.exact.json"]),plan.exact_request));
 const q=JSON.parse(files["REQUEST.exact.json"]),prior=JSON.parse(files["PRIOR-STATE.original.json"]),terminal=JSON.parse(files["STDOUT.original.txt"]);
 check("fixed one file_info",q.operation.tool==="file_info"&&q.operation.arguments.host==="x230"&&q.operation.arguments.path===plan.target.path);
 check("actual size SHA full9 binding",terminal.report.bytes===36658&&terminal.report.bytes===plan.target.bytes&&terminal.report.sha256===plan.target.sha256&&same(terminal.report.full9_decimal,plan.target.full9Strings));
 check("no body authority",plan.maximum_binary_read_operations===0&&plan.maximum_process_start_calls===0&&plan.maximum_file_info_operations===1);
 check("same closed seven-call slot",Object.keys(prior.calls).length===7&&prior.completedObservers.length===2&&prior.pending===null&&!prior.paused&&!prior.nativeCallInFlight&&prior.activeObserver===null);
 function def(text,name){const starts=[...text.matchAll(/^(?:async )?function ([A-Za-z0-9_]+)\(/gm)];const i=starts.findIndex(m=>m[1]===name);if(i<0)throw Error(name);return text.slice(starts[i].index,i+1<starts.length?starts[i+1].index:text.length);}
 for(const name of ["gfNeed","gfMetaEquals","gfState","gfSave","gfIntegerText","gfInitializeOnlyAfterRootGO","gfAcceptArchivedSDK","gfReconcileSameGitArchiveReadOnly"])check("unchanged "+name,def(before,name)===def(after,name));
 const infoGO={authorization:"GO",scope:plan.scope,original_job:plan.original_job,maximum_file_info_operations:1,maximum_process_start_calls:0,maximum_binary_read_operations:0,exact_request:plan.exact_request};
 const goRaw=JSON.stringify(infoGO,null,2)+"\n",goPin=meta(goRaw);
 function fixture(){
  const data=new Map([[plan.slot,JSON.parse(files["PRIOR-STATE.original.json"])]]),archives=[];
  const fakeArchive="async function archiveFlatPublicTextsOnce(args){ __archives.push(JSON.parse(JSON.stringify(args)));return {tree:'1111111111111111111111111111111111111111',whole:true,count:Object.keys(args.texts).length};}";
  const api=new Function("tools","store","load","__archives",files["pure.original.js"]+"\n"+fakeArchive+"\n"+after+"\nreturn {run:gfRun,validate:gfValidateRequest};")(
   new Proxy({},{get(){throw Error("Native forbidden in pure test");}}),(k,v)=>data.set(k,v),k=>data.get(k),archives);
  return {data,archives,api};
 }
 const authArgs={goRaw,goPin,goWholeReadback:true,priorStateRaw:files["PRIOR-STATE.original.json"],stdoutRaw:files["STDOUT.original.txt"]};
 const f=fixture(),authorized=await f.api.run("authorize_oracle_report_info",authArgs);
 check("actual authorize function passes closed original fixture",authorized.ok===true);
 check("original call map unchanged by attachment",same(f.data.get(plan.slot).calls,prior.calls));
 check("original observer history unchanged by attachment",same(f.data.get(plan.slot).completedObservers,prior.completedObservers));
 const prepared=await f.api.run("prepare",{callKey:"pure-oracle-info-admit",kind:"operation_start",requestRaw:files["REQUEST.exact.json"]});
 check("actual prepare accepts exact once request",prepared.ok===true&&f.archives.length===1);
 check("actual new admit intent selects new GO",same(JSON.parse(f.archives[0].texts["intent.json"]).rootGo,goPin)&&same(JSON.parse(f.archives[0].texts["armed.json"]).rootGo,goPin));
 check("prepare does not invoke Native",f.data.get(plan.slot).calls["pure-oracle-info-admit"].called===false&&!f.data.get(plan.slot).nativeCallInFlight);
 check("old seven calls byte-values remain",Object.keys(prior.calls).every(k=>same(f.data.get(plan.slot).calls[k],prior.calls[k])));
 async function rejected(label,change){const x=fixture();await x.api.run("authorize_oracle_report_info",authArgs);const request=JSON.parse(files["REQUEST.exact.json"]);change(request);const r=await x.api.run("prepare",{callKey:"pure-oracle-info-reject",kind:"operation_start",requestRaw:JSON.stringify(request,null,2)+"\n"});check(label,r.ok===false&&x.archives.length===0);}
 await rejected("reject changed report path",q=>q.operation.arguments.path+="-other");
 await rejected("reject binary_read instead of metadata",q=>q.operation.tool="binary_read");
 await rejected("reject process_status instead of metadata",q=>q.operation={tool:"process_status",arguments:{host:"x230",job_id:plan.original_job}});
 const noGO=fixture();let r=await noGO.api.run("prepare",{callKey:"pure-no-go",kind:"operation_start",requestRaw:files["REQUEST.exact.json"]});check("reject new calls before separate GO",r.ok===false&&noGO.archives.length===0);
 const repeated=fixture();await repeated.api.run("authorize_oracle_report_info",authArgs);repeated.data.get(plan.slot).oracleReportInfoStarted=true;r=await repeated.api.run("prepare",{callKey:"pure-duplicate-admit",kind:"operation_start",requestRaw:files["REQUEST.exact.json"]});check("reject second info admission",r.ok===false&&repeated.archives.length===0);
 const process=fixture();await process.api.run("authorize_oracle_report_info",authArgs);r=await process.api.run("prepare",{callKey:"pure-process-start",kind:"process_start",requestRaw:"{}\n"});check("reject process_start",r.ok===false&&process.archives.length===0);
 for(const kind of ["operation_status","operation_result"]){
  const x=fixture();await x.api.run("authorize_oracle_report_info",authArgs);const s=x.data.get(plan.slot);s.oracleReportInfoStarted=true;s.activeObserver={id:"a".repeat(64),tool:"file_info",futureClosed:kind==="operation_result",nextPageOffset:0,eof:false};
  const request=kind==="operation_status"?{operation_id:s.activeObserver.id}:{operation_id:s.activeObserver.id,offset:0,limit:8192};
  r=await x.api.run("prepare",{callKey:"pure-"+kind.replaceAll("_","-"),kind,requestRaw:JSON.stringify(request,null,2)+"\n"});
  check("actual "+kind+" new scope arm",r.ok===true&&same(JSON.parse(x.archives[0].texts["intent.json"]).rootGo,goPin));
  check("actual "+kind+" preserves original historical calls",Object.keys(prior.calls).every(k=>same(x.data.get(plan.slot).calls[k],prior.calls[k])));
 }
 return {schema:"heptabao.official271.report-info.source-checks.r1",pass:true,check_count:checks.length,checks,NativeCalls:0,productExecuted:false,newCandidateExecuted:false,fakeJournalFunctionsExecuted:["authorize_oracle_report_info","prepare"],allToolsThrow:true};
}
