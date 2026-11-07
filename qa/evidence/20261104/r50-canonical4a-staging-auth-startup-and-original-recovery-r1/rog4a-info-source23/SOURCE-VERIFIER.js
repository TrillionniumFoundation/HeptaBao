function verifyInfoSource(i) {
 const checks=[];
 function ok(name,value){checks.push({name,pass:value===true});if(value!==true)throw new Error(name);}
 function same(a,b){return JSON.stringify(a)===JSON.stringify(b);}
 const expected={
  before:"3338ea8993faeca5b061c6921f4d70ca3c14410e",
  base:"254e10fc6158f4952469a427d89b798c2c8873e4",
  after:"90ac83d6e48744399e1508f0b86ac4a8c62f33cb",
  request:"e55cc1096e11c01c5fdfd4a520c4ecef0130017c",
  state:"dfc212dc54995d22ec12cc8c5f140f9e046bec39",
  authority:"1e39f3d224e4a27f2b2cf0fd37a2085b1f43008b",
  streams:"784f4be7e98a228d7162039b25062d9b369fe5da"};
 for(const [k,b] of Object.entries(expected))ok("whole-"+k,gitBlobMeta(i[k]).blob===b);
 ok("exact-request-full-pin",same(gitBlobMeta(i.request),i.requestPin));
 ok("exact-nine-replacements",i.edits.length===9);
 let rebuilt=i.before;
 for(const e of i.edits){ok("unique-literal-"+e.label,rebuilt.split(e.oldText).length===2);rebuilt=rebuilt.replace(e.oldText,e.newText);}
 ok("literal-rebuild-whole",rebuilt===i.after);
 ok("strict-donor-forward",snapshotApply(i.before,i.diff)===i.after);
 ok("strict-donor-reverse",snapshotApply(i.after,i.diff,true)===i.before);
 ok("strict-current-forward",snapshotApply(i.base,i.incrementalDiff)===i.after);
 ok("strict-current-reverse",snapshotApply(i.after,i.incrementalDiff,true)===i.base);
 ok("two-donor-hunks",(i.diff.match(/^@@ /gm)||[]).length===2);
 ok("six-current-hunks",(i.incrementalDiff.match(/^@@ /gm)||[]).length===6);
 function defs(raw){const m=[...raw.matchAll(/^(?:async )?function ([a-zA-Z0-9_]+)\(/gm)];return Object.fromEntries(m.map((v,n)=>[v[1],raw.slice(v.index,m[n+1]?.index??raw.length)]));}
 const bd=defs(i.before),ad=defs(i.after);
 ok("same-function-set",same(Object.keys(bd),Object.keys(ad)));
 for(const n of Object.keys(bd).filter(n=>!["gfAuthorizeStageResultInfoOnly","gfValidateRequest"].includes(n)))ok("donor-function-whole-"+n,bd[n]===ad[n]);
 const s=JSON.parse(i.state),a=parseLosslessIntegers(i.authority),r=parseLosslessIntegers(i.streams),q=JSON.parse(i.request),summary=JSON.parse(r.stdout.text);
 ok("same-original-job",s.job==="1a1b3307dc2-fc05-80f8"&&a.job_id===s.job&&r.job_id===s.job);
 ok("no-live-or-armed-call",s.pending===null&&s.activeObserver===null&&!s.nativeCallInFlight&&!s.paused);
 ok("seven-original-calls-accepted",Object.keys(s.calls).length===7&&Object.values(s.calls).every(c=>c.phase==="accepted"&&c.called===true));
 ok("two-original-observers-closed",s.completedObservers.length===2&&s.completedObservers.every(o=>o.completedInactive===true));
 ok("actual-zero-full-durable",a.exit_code===0&&a.output_complete===true&&a.output_durable===true&&a.terminal_publication_confirmed===true&&!a.timed_out&&!a.cancelled);
 ok("both-full-streams",r.stdout.eof===true&&r.stderr.eof===true&&s.nextStdout===350&&s.nextStderr===0&&gitBlobMeta(r.stdout.text).bytes===350&&r.stderr.text==="");
 ok("exact-fixed-report-path",q.operation.tool==="file_info"&&q.operation.arguments.host==="rog"&&q.operation.arguments.path==="/home/qian-qi/hb-4a49405b-src-20261106-r1/control/stage-result.public.json"&&summary.result_path===q.operation.arguments.path);
 ok("source-stage-summary",summary.status==="prepared"&&summary.all_owned_stopped===true&&summary.compiler_started===false&&summary.server_started===false&&summary.source_commit==="4a49405b93c45ab1c25ecba11cde63a7ede20dce");
 for(const [n,raw] of [[0,i.authority],[1,i.streams]])ok("prerequisite-"+n,s.completedObservers[n].id===i.prior[n].id&&same(gitBlobMeta(raw),i.prior[n].nativeText));
 ok("metadata-cap-and-lossless-full9",i.after.includes("const GF_STAGE_RESULT_MAX_BYTES = 65536;")&&i.after.includes("full9Strings:[parts[0],parts[1]")&&i.after.includes('md.uid===1000 && md.gid===1000 && md.link_count===1'));
 ok("old-payload-page-caps",i.after.includes("q.limit===8192")&&i.after.includes("1048576"));
 const slot="combined_4a49405b_rog_source_gitfirst_r1";
 let apiCalls=0;
 const factory=eval("(function(load,store,tools){"+i.after+";return {authorize:gfAuthorizeStageResultInfoOnly,validate:gfValidateRequest,initialize:gfInitializeOnlyAfterRootGO};})");
 function fresh(){
  const m=new Map([[slot,JSON.parse(i.state)],[slot+":closed_native:"+i.prior[0].id,i.authority],[slot+":closed_native:"+i.prior[1].id,i.streams]]);
  const g=factory(k=>m.get(k),(k,v)=>m.set(k,v),new Proxy({}, {get(){apiCalls++;throw new Error("NO_TOOL_IN_PURE_SOURCE_CHECK");}}));
  return {m,g,s:m.get(slot)};
 }
 const testGo=JSON.stringify({test_only:true,authorization:"GO",scope:"stage_result_file_info_only",original_job:s.job,maximum_file_info_starts:1,binary_read_authorized:false,exact_request:i.requestPin})+"\n";
 function auth(c,raw=testGo,whole=true){return c.g.authorize({goRaw:raw,goPin:gitBlobMeta(raw),goWholeReadback:whole});}
 function rejects(name,fn){let rejected=false;try{fn();}catch{rejected=true;}ok(name,rejected);}
 rejects("original-stage-GO-alone-refuses-INFO",()=>{const c=fresh();c.g.validate(c.s,"operation_start",q,i.request);});
 {const c=fresh();auth(c);c.g.validate(c.s,"operation_start",q,i.request);ok("new-exact-GO-enables-only-request",c.s.stageResultInfoGO.whole===true&&c.s.stageResultInfoStarted===undefined);}
 rejects("unread-GO-refused",()=>auth(fresh(),testGo,false));
 rejects("old-GO-not-new-scope",()=>auth(fresh(),s.goRaw,true));
 rejects("no-reinitialize",()=>{const c=fresh();c.g.initialize({goRaw:testGo,goPin:gitBlobMeta(testGo),goWholeReadback:true,digest:"0".repeat(64),fingerprint:"1"});});
 rejects("paused-refused",()=>{const c=fresh();c.s.paused=true;auth(c);});
 rejects("inflight-refused",()=>{const c=fresh();c.s.nativeCallInFlight=true;auth(c);});
 rejects("wrong-job-refused",()=>{const c=fresh();c.s.job="different";auth(c);});
 rejects("open-observer-refused",()=>{const c=fresh();c.s.activeObserver={};auth(c);});
 rejects("prerequisite-drift-refused",()=>{const c=fresh();c.m.set(slot+":closed_native:"+i.prior[0].id,i.authority+" ");auth(c);});
 rejects("repeat-info-refused",()=>{const c=fresh();auth(c);c.s.stageResultInfoStarted=true;c.g.validate(c.s,"operation_start",q,i.request);});
 rejects("different-path-refused",()=>{const c=fresh();auth(c);const z=JSON.parse(i.request);z.operation.arguments.path+="-other";c.g.validate(c.s,"operation_start",z,JSON.stringify(z));});
 rejects("rekey-refused",()=>{const c=fresh();auth(c);const z=JSON.parse(i.request);z.idempotency_key+="-other";c.g.validate(c.s,"operation_start",z,JSON.stringify(z));});
 rejects("binary-read-refused",()=>{const c=fresh();auth(c);const z=JSON.parse(i.request);z.operation.tool="binary_read";c.g.validate(c.s,"operation_start",z,JSON.stringify(z));});
 rejects("new-process-refused",()=>{const c=fresh();auth(c);c.g.validate(c.s,"process_start",{},i.request);});
 ok("zero-tools-private-model-only",apiCalls===0);
 return {schema:"heptabao.4a.stage-info.source-verification.r1",ok:true,checks:checks.length,results:checks,candidate:gitBlobMeta(i.after),exactRequest:gitBlobMeta(i.request),runtimeCalls:0,liveStateChanged:false,actualMetadata:null,actualBody:null,detailReportQualified:false};
}
