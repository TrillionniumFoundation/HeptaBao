function verify4aBodySource(i){
 const checks=[];function ck(n,v){checks.push({name:n,pass:v===true});if(v!==true)throw Error(n);}
 const equal=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
 const known={before:"5d74cdef5db802aa3accefdde721f2ea26c3906a",base:"90ac83d6e48744399e1508f0b86ac4a8c62f33cb",after:"be146f7191451c264e374facd59611dc061d5ca4",request:"b6048e8adb57144a814f2935978114b136958396",info:"c99781d25798c2a3a299c51bfa43aa96ba2e0402"};
 for(const[k,b]of Object.entries(known))ck("whole-"+k,gitBlobMeta(i[k]).blob===b);
 ck("twelve-declared-substitutions",i.edits.length===12);
 let rebuilt=i.before;
 for(const e of i.edits){ck("literal-count-"+e.label,rebuilt.split(e.oldText).length-1===e.count);rebuilt=rebuilt.split(e.oldText).join(e.newText);}
 ck("exact-donor-rebuild",rebuilt===i.after);
 ck("donor-forward",snapshotApply(i.before,i.diff)===i.after);
 ck("donor-reverse",snapshotApply(i.after,i.diff,true)===i.before);
 ck("current-forward",snapshotApply(i.base,i.incrementalDiff)===i.after);
 ck("current-reverse",snapshotApply(i.after,i.incrementalDiff,true)===i.base);
 ck("donor-three-hunks",(i.diff.match(/^@@ /gm)||[]).length===3);
 ck("current-six-hunks",(i.incrementalDiff.match(/^@@ /gm)||[]).length===6);
 function defs(raw){const m=[...raw.matchAll(/^(?:async )?function (\w+)\(/gm)];return Object.fromEntries(m.map((v,n)=>[v[1],raw.slice(v.index,m[n+1]?.index??raw.length)]));}
 const b=defs(i.before),a=defs(i.after);ck("same-functions",equal(Object.keys(b),Object.keys(a)));
 for(const n of Object.keys(b).filter(n=>!["gfAuthorizeStageResultInfoOnly","gfAuthorizeStageResultBodyOnly","gfValidateRequest"].includes(n)))ck("donor-function-whole-"+n,b[n]===a[n]);
 const s=JSON.parse(i.state),md=s.stageResultInfo,info=parseLosslessIntegers(i.info),q=JSON.parse(i.request),e=i.expected;
 ck("original-slot-closed",s.job==="1a1b3307dc2-fc05-80f8"&&!s.paused&&!s.nativeCallInFlight&&s.pending===null&&s.activeObserver===null&&s.stageResultInfoStarted===true);
 ck("ten-original-calls-retained",Object.keys(s.calls).length===10&&Object.values(s.calls).every(c=>c.phase==="accepted"&&c.called));
 ck("three-closed-observers",s.completedObservers.length===3&&s.completedObservers.every(o=>o.completedInactive));
 ck("original-local-error-retained",s.outerFailure.action==="close"&&s.outerFailure.message==="closed_gfRun_action");
 ck("actual-info-whole-binding",equal(gitBlobMeta(i.info),md.nativeText)&&md.originalOperation===e.infoOperation&&s.completedObservers[2].id===e.infoOperation);
 ck("metadata-exact31257",md.size===31257&&info.size===31257&&e.bytes===31257&&info.sha256===e.sha256&&md.sha256===e.sha256);
 ck("metadata-original-version",info.version==="66306:34603472:31257:1794007676686666010:1794007676686666010"&&e.version===info.version&&md.version===info.version);
 ck("metadata-owner-mode-link",info.mode===384&&info.metadata.uid===1000&&info.metadata.gid===1000&&info.metadata.link_count===1&&info.metadata.metadata_platform==="linux");
 ck("fixed-body-extent",q.operation.tool==="binary_read"&&q.operation.arguments.host==="rog"&&q.operation.arguments.path===md.path&&q.operation.arguments.offset===0&&q.operation.arguments.limit===31257&&q.operation.arguments.expected_version===md.version);
 ck("no-old-page-cap-change",i.after.includes("q.limit===8192")&&i.after.includes("1048576"));
 ck("exact-request-pin",equal(gitBlobMeta(i.request),i.requestPin));
 const slot="combined_4a49405b_rog_source_gitfirst_r1";let toolsCalled=0;
 const factory=eval("(function(load,store,tools){"+i.after+";return {authorize:gfAuthorizeStageResultBodyOnly,validate:gfValidateRequest,initialize:gfInitializeOnlyAfterRootGO};})");
 function fresh(){const m=new Map([[slot,JSON.parse(i.state)],[slot+":closed_native:"+e.infoOperation,i.info]]);return {m,g:factory(k=>m.get(k),(k,v)=>m.set(k,v),new Proxy({},{get(){toolsCalled++;throw Error("NO_TOOLS");}})),s:m.get(slot)};}
 const testGO=JSON.stringify({test_only:true,authorization:"GO",scope:"stage_result_binary_read_only",original_job:s.job,info_operation:e.infoOperation,maximum_binary_read_starts:1,exact_request:i.requestPin})+"\n";
 function auth(c,raw=testGO,whole=true){c.g.authorize({goRaw:raw,goPin:gitBlobMeta(raw),goWholeReadback:whole});}
 function rejects(n,fn){let rejected=false;try{fn();}catch{rejected=true;}ck(n,rejected);}
 rejects("INFO-GO-alone-no-BODY",()=>{const c=fresh();c.g.validate(c.s,"operation_start",q,i.request);});
 {const c=fresh();auth(c);c.g.validate(c.s,"operation_start",q,i.request);ck("exact-private-model-accepted",c.s.stageResultBodyGO.whole===true);}
 rejects("unread-GO",()=>auth(fresh(),testGO,false));
 rejects("old-INFO-GO",()=>{const c=fresh();auth(c,c.s.stageResultInfoGO.raw);});
 rejects("no-reinitialize",()=>fresh().g.initialize({}));
 rejects("paused",()=>{const c=fresh();c.s.paused=true;auth(c);});
 rejects("metadata-drift",()=>{const c=fresh();c.s.stageResultInfo.version+="-changed";auth(c);});
 rejects("native-info-drift",()=>{const c=fresh();c.m.set(slot+":closed_native:"+e.infoOperation,i.info+" ");auth(c);});
 rejects("open-observer",()=>{const c=fresh();c.s.activeObserver={};auth(c);});
 rejects("repeat-body",()=>{const c=fresh();auth(c);c.s.stageResultBodyStarted=true;c.g.validate(c.s,"operation_start",q,i.request);});
 for(const [name,change]of [["offset",z=>z.operation.arguments.offset=1],["limit",z=>z.operation.arguments.limit=65536],["version",z=>z.operation.arguments.expected_version="other"],["path",z=>z.operation.arguments.path+="-other"],["rekey",z=>z.idempotency_key+="-again"]])rejects("different-"+name,()=>{const c=fresh();auth(c);const z=JSON.parse(i.request);change(z);c.g.validate(c.s,"operation_start",z,JSON.stringify(z));});
 rejects("metadata-refresh",()=>{const c=fresh();auth(c);const z=JSON.parse(i.infoRequest);c.g.validate(c.s,"operation_start",z,i.infoRequest);});
 rejects("new-process",()=>{const c=fresh();auth(c);c.g.validate(c.s,"process_start",{},i.request);});
 ck("zero-tools-private-model-only",toolsCalled===0);
 return {schema:"heptabao.4a.stage-body.source-verification.r1",ok:true,checks:checks.length,results:checks,candidate:gitBlobMeta(i.after),request:gitBlobMeta(i.request),actualMetadata:md.nativeText,NativeCalls:0,actualBody:null,semanticReportQualification:false};
}
