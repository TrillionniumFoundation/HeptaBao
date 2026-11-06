async function verifyOracleR2TenBodySource(input) {
 const checks=[];function ck(name,value){checks.push({name,passed:!!value});if(!value)throw Error(name);}
 const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b),meta=gitBlobMeta,x=input;
 ck("strict forward source diff",applyStrict(x.before,x.diff,false)===x.after);
 ck("strict reverse source diff",applyStrict(x.after,x.diff,true)===x.before);
 const before=parseLosslessIntegers(x.priorStateRaw),info=parseLosslessIntegers(x.infoNativeRaw),need=x.need;
 ck("actual prior INFO closed and preserved",!before.paused&&!before.nativeCallInFlight&&before.pending===null&&before.activeObserver===null&&Object.keys(before.calls).length===10&&before.completedObservers.length===3);
 ck("actual independent INFO input pin",same(meta(x.infoNativeRaw),need.infoNative)&&before.oracleReportInfo.nativeText.blob===need.infoNative.blob);
 ck("actual version path size SHA",info.path===need.path&&info.size===need.bytes&&info.sha256===need.sha256&&info.version===need.version&&need.bytes===651803);
 ck("actual full9 exact terminal",same(need.full9Strings,before.oracleReportInfo.full9Strings)&&need.version==="2053:2098461:651803:1793982810542000556:1793982810542000556");
 ck("exact ten new requests",x.requests.length===10&&x.ranges.length===10);
 let at=0;const keys=new Set();
 for(let i=0;i<10;i++){
  const r=x.ranges[i],req=x.requests[i],q=JSON.parse(req.raw),a=q.operation.arguments;
  ck("range "+i+" exact request pin",same(meta(req.raw),r.request)&&same(meta(req.raw),req.pin));
  ck("range "+i+" contiguous bounded actual version",r.offset===at&&a.offset===at&&a.limit===r.limit&&r.limit===Math.min(65536,need.bytes-at)&&a.host==="x230"&&a.path===need.path&&a.expected_version===need.version&&q.operation.tool==="binary_read");
  ck("range "+i+" fixed fresh key",q.idempotency_key==="heptabao-official271-x230-acl23-r2-report-body-"+String(i).padStart(2,"0")&&!keys.has(q.idempotency_key));keys.add(q.idempotency_key);at+=r.limit;
 }
 ck("whole geometry 9x65536 plus61979",at===need.bytes&&x.ranges[9].offset===589824&&x.ranges[9].limit===61979);
 function defs(raw){const matches=[...raw.matchAll(/^(?:async )?function (\w+)\(/gm)],out={};matches.forEach((m,i)=>{const end=i+1<matches.length?matches[i+1].index:raw.length;out[m[1]]=raw.slice(m.index,end);});return out;}
 const bd=defs(x.before),ad=defs(x.after),changed=["gfValidateRequest","gfPrepareOne","gfInvokePreparedOnce","gfAcceptArchivedSDK","gfCloseOriginalObserver","gfRun"];
 ck("one added body authorization only",Object.keys(ad).length===Object.keys(bd).length+1&&ad.gfAuthorizeOracleReportBody!==undefined);
 for(const name of Object.keys(bd).filter(n=>!changed.includes(n))) {
  const old=bd[name].trimEnd(),now=ad[name].trimEnd();
  ck("unchanged function "+name,old===now);
 }
 ck("whole existing SDK-before-parse dispatch mechanism retained",ad.gfInvokePreparedOnce===bd.gfInvokePreparedOnce.replace('if(c.kind==="operation_start")s.oracleReportInfoStarted=true;','if(c.kind==="operation_start")s.oracleReportBodyStarted+=1;'));
 ck("prepare changes only new GO scope selection",ad.gfPrepareOne===bd.gfPrepareOne.replace("rootGo:s.oracleReportInfoGO?.pin??s.goPin","rootGo:s.oracleReportBodyGO?.pin??s.oracleReportInfoGO?.pin??s.goPin"));
 ck("accept changes only new binary immutable page cap",ad.gfAcceptArchivedSDK===bd.gfAcceptArchivedSDK.replace("gfNeed(b.length<=8192 && v.next_offset===q.offset+b.length","gfNeed(b.length<=(a.tool===\"binary_read\"?GF_ORACLE_BODY_PAGE_BYTES:8192) && v.next_offset===q.offset+b.length"));
 let ref=x.reference.slice(x.reference.indexOf('  if(a.tool==="binary_read") {',x.reference.indexOf("async function gfCloseOriginalObserver")),x.reference.indexOf('  } else if(a.tool==="file_info") {',x.reference.indexOf("async function gfCloseOriginalObserver")));
 ref=ref.replaceAll("GF_CLI_BODY_EXPECTED","GF_ORACLE_BODY_EXPECTED").replaceAll("GF_CLI_BODY_RANGES","GF_ORACLE_BODY_RANGES").replaceAll("cliResultBody","oracleReportBody").replaceAll("CLI_body","oracle_body").replaceAll("CLI_report","oracle_report").replaceAll(":cli_result_body_original",":oracle_report_body_original").replaceAll('"cli-phaseb-r4-public-report-whole"','"official271-acl23-r2-report-whole"');
 ck("existing CLI13 exact range/whole hash/UTF8 close algorithm",ad.gfCloseOriginalObserver===bd.gfCloseOriginalObserver.replace('  if(a.tool==="file_info") {',ref+'  } else if(a.tool==="file_info") {'));
 const slot="official271_x230_acl23_oracle_gitfirst_r2";
 const go={authorization:"GO",scope:"official271_oracle_result_binary_read_ranges_only",original_job:before.job,info_operation:need.infoOperation,maximum_binary_read_starts:10,maximum_file_info_operations:0,maximum_process_start_calls:0,immutable_body_page_bytes:16384,maximum_operation_status_calls_per_id:8,maximum_immutable_pages_per_id:128,fixed_report:{path:need.path,bytes:need.bytes,sha256:need.sha256,version:need.version},exact_requests:x.ranges.map(r=>r.request)};
 const goRaw=JSON.stringify(go)+"\n",goPin=meta(goRaw);
 function factory(){
  const memory=new Map([[slot,JSON.parse(x.priorStateRaw)],[slot+":closed_native:"+need.infoOperation,x.infoNativeRaw]]),archives=[];
  const mockArchive=async arg=>{archives.push(arg);return {tree:"a".repeat(40),whole:true,entries:Object.entries(arg.texts).map(([path,raw])=>({path,...meta(raw),whole:true}))};};
  const api=new Function("tools","store","load","archiveFlatPublicTextsOnce",input.pure+"\n"+x.after+"\nreturn {auth:gfAuthorizeOracleReportBody,validate:gfValidateRequest,prepare:gfPrepareOne};")({},(k,v)=>memory.set(k,v),k=>memory.get(k),mockArchive);
  return {memory,archives,api,get:()=>memory.get(slot)};
 }
 function auth(f){return f.api.auth({goRaw,goPin,goWholeReadback:true,priorStateRaw:x.priorStateRaw});}
 function refuses(fn){try{fn();return false;}catch{return true;}}
 const f=factory();auth(f);
 ck("authorization preserves all original calls/observers",same(f.get().calls,before.calls)&&same(f.get().completedObservers,before.completedObservers));
 ck("authorization only new body state",f.get().oracleReportBodyStarted===0&&f.get().oracleReportBodyRanges.length===0&&f.get().oracleReportBodyGO.pin.blob===goPin.blob&&f.get().onlyOracleReportInfo===false);
 ck("repeat body authorization refused",refuses(()=>auth(f)));
 ck("process admission refused",refuses(()=>f.api.validate(f.get(),"process_start",{},"{}")));
 ck("new INFO admission refused",refuses(()=>f.api.validate(f.get(),"operation_start",{operation:{tool:"file_info",arguments:{host:"x230",path:need.path}}},"{}")));
 ck("out-of-order range refused",refuses(()=>f.api.validate(f.get(),"operation_start",x.requests[1].q,x.requests[1].raw)));
 const wrong=JSON.parse(x.requests[0].raw);wrong.operation.arguments.expected_version="different";
 ck("wrong version refused",refuses(()=>f.api.validate(f.get(),"operation_start",wrong,JSON.stringify(wrong)+"\n")));
 for(let i=0;i<10;i++){
  const ff=factory();auth(ff);ff.get().oracleReportBodyRanges=Array(i).fill({sourceOnlyFake:true});ff.get().oracleReportBodyStarted=i;ff.get().completedObservers=before.completedObservers.concat(Array(i).fill({completedInactive:true,sourceOnlyFake:true}));
  ff.api.validate(ff.get(),"operation_start",x.requests[i].q,x.requests[i].raw);ck("exact next range "+i+" admitted by pure guard",true);
 }
 const fp=factory();auth(fp);await fp.api.prepare({callKey:"oracle-r2-body-fake-admit",kind:"operation_start",requestRaw:x.requests[0].raw});
 ck("actual prepare admission arm uses BODY GO",fp.archives.length===1&&JSON.parse(fp.archives[0].texts["armed.json"]).rootGo.blob===goPin.blob&&JSON.parse(fp.archives[0].texts["intent.json"]).rootGo.blob===goPin.blob);
 ck("actual prepare preserves old INFO calls",Object.keys(before.calls).every(k=>same(fp.get().calls[k],before.calls[k])));
 for(const kind of ["operation_status","operation_result"]){
  const ff=factory();auth(ff);const id="f".repeat(64);ff.get().activeObserver={id,tool:"binary_read",futureClosed:kind==="operation_result",nextPageOffset:0,pages:[],eof:false};
  const req=kind==="operation_status"?{operation_id:id}:{operation_id:id,offset:0,limit:16384};
  await ff.api.prepare({callKey:"oracle-r2-body-fake-"+(kind==="operation_status"?"status":"page"),kind,requestRaw:JSON.stringify(req)+"\n"});
  ck("actual "+kind+" arm uses BODY GO",ff.archives.length===1&&JSON.parse(ff.archives[0].texts["armed.json"]).rootGo.blob===goPin.blob);
 }
 const fs=factory();auth(fs);const id="e".repeat(64);fs.get().activeObserver={id,tool:"binary_read",futureClosed:false,nextPageOffset:0,pages:[],eof:false};for(let i=0;i<8;i++)fs.get().calls["fake-status-"+i]={kind:"operation_status",called:true,requestRaw:JSON.stringify({operation_id:id})};
 ck("ninth status refused",refuses(()=>fs.api.validate(fs.get(),"operation_status",{operation_id:id},JSON.stringify({operation_id:id}))));
 fs.get().activeObserver.futureClosed=true;fs.get().activeObserver.pages=Array(128).fill({sourceOnlyFake:true});
 ck("129th immutable page refused",refuses(()=>fs.api.validate(fs.get(),"operation_result",{operation_id:id,offset:0,limit:16384},"{}")));
 const end=factory();auth(end);end.get().oracleReportBodyRanges=Array(10).fill({sourceOnlyFake:true});end.get().oracleReportBodyStarted=10;end.get().completedObservers=before.completedObservers.concat(Array(10).fill({completedInactive:true}));
 ck("eleventh binary admission refused",refuses(()=>end.api.validate(end.get(),"operation_start",x.requests[9].q,x.requests[9].raw)));
 return {schema:"heptabao.official271.r2.ten-range-body-source-checks.r1",pass:true,check_count:checks.length,checks,ranges:10,wholeBytes:651803,binaryChunkCap:65536,newImmutablePageCap:16384,statusPerID:8,pagesPerID:128,payloadCap:1048576,NativeCalls:0,PythonRuns:0,bodyActualRead:false,sourceOnlyFakeArchives:true};
}
