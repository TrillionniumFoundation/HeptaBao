async function verifyMac4aStandaloneReportBody(files){
 const checks=[],same=(a,b)=>JSON.stringify(a)===JSON.stringify(b),raw=n=>{if(typeof files[n]!=="string")throw Error("missing "+n);return files[n];},j=n=>JSON.parse(raw(n));
 function ck(name,ok){checks.push({name,passed:!!ok});if(!ok)throw Error(name);}
 function fn(src,name){const all=[...src.matchAll(/^(?:async )?function (\w+)\(/gm)],i=all.findIndex(x=>x[1]===name);if(i<0)throw Error("fn "+name);return src.slice(all[i].index,i+1<all.length?all[i+1].index:src.length).trim();}
 const before=raw("journal.before.executed.js"),after=raw("journal.after.js"),plan=j("PLAN.public.json"),contract=j("GO.CONTRACT.public.json"),req=j("request.exact.json");
 ck("exact executed corrected donor",gitBlobMeta(before).blob==="86edcf2a0d2d5206025a6a702883e6b645e2cc87");
 ck("strict whole forward and reverse",applyStrict(before,raw("journal.forward.diff"))===after&&applyStrict(after,raw("journal.reverse.diff"))===before);
 ck("exact seven strict hunks",(raw("journal.forward.diff").match(/^@@/gm)||[]).length===7);
 ck("journal and request whole pins",same(gitBlobMeta(after),plan.journal)&&same(gitBlobMeta(raw("request.exact.json")),plan.exactRequest));
 for(const name of ["gfNeed","gfMetaEquals","gfSave","gfIntegerText","gfPrepareOne","gfAcceptArchivedSDK","gfReconcileSameGitArchiveReadOnly"])ck("retained complete function "+name,fn(before,name)===fn(after,name));
 ck("one exact actual range",req.operation.tool==="binary_read"&&req.operation.arguments.host==="mac"&&req.operation.arguments.path===plan.fixedReport.path&&req.operation.arguments.offset===0&&req.operation.arguments.limit===7685&&req.operation.arguments.expected_version==="16777244:72771947:7685:1794013039551370413:1794013039551379746");
 ck("actual metadata whole input",same(gitBlobMeta(raw("INFO-native.original.json")),plan.fixedReport.infoNative)&&same(gitBlobMeta(raw("OLD-STATE.paused.original.json")),plan.originalPausedState)&&same(gitBlobMeta(raw("RETRIEVAL-STATE.closed.original.json")),plan.completedRetrievalState));
 const payload=j("INFO-payload.original.json"),native=parseLosslessIntegers(raw("INFO-native.original.json")),md=native.metadata,p=native.version.split(":");
 ck("payload exact metadata",payload.resultType==="complete"&&payload.isError===false&&payload.content.length===1&&payload.content[0].text===raw("INFO-native.original.json")&&native.size===7685&&native.sha256===plan.fixedReport.sha256&&native.version===plan.fixedReport.version);
 ck("full9 lossless actual darwin uid gid mode",md.metadata_platform==="darwin"&&md.uid===501&&md.gid===20&&md.mode===384&&native.mode===384&&md.link_count===1&&same([p[0],p[1],"501","20","33152","1","7685",p[3],p[4]],plan.fixedReport.full9Strings));
 ck("no new job and old slots immutable",plan.newJob===null&&plan.originalPausedStateNeverWritten===true&&plan.retrievalStateNeverWritten===true&&plan.handback===false&&!after.includes("store(GF_OLD_SLOT")&&!after.includes("store(GF_RETRIEVAL_SLOT"));
 ck("binary16K both prepare and accept, old8K preserved",after.includes('q.limit===(s.activeObserver.tool==="binary_read"?GF_ORACLE_REPORT_BODY_PAGE_BYTES:8192)')&&after.includes('b.length<=(a.tool==="binary_read"?GF_ORACLE_REPORT_BODY_PAGE_BYTES:8192)')&&after.includes("const GF_ORACLE_REPORT_BODY_PAGE_BYTES = 16384;"));
 ck("finite original observer limits",after.includes(').length<8,"original_status_budget_eight"')&&after.includes(').length<128,"original_page_budget_128"')&&after.includes("v.total_bytes<=1048576"));
 const archiveArguments=[...after.matchAll(/archiveFlatPublicTextsOnce\(\{(?:\s*)key:([^\n,]+)/g)].map(x=>x[1].trim());
 ck("all five archive calls enumerated",archiveArguments.length===5);
 ck("all keys dynamic call or original operation",same(archiveArguments,['"gfa-"+callKey','"gfx-"+callKey','"gfs-"+callKey','archiveKey','"gfr-"+a.id'])&&after.includes('const archiveKey="gfc-"+a.id;')&&!after.includes('key:"successor')&&!after.includes('key:"official'));
 ck("whole payload before body and no semantics",fn(after,"gfCloseOriginalObserver").indexOf('texts:{"payload.original.json":raw}')<fn(after,"gfCloseOriginalObserver").indexOf("const p=parseLosslessIntegers(raw);")&&after.includes('texts:{"report.original.json":bodyRaw}')&&!after.includes("JSON.parse(bodyRaw)"));
 const goRaw=JSON.stringify({...contract,schema:"private-pure-GO-fixture-only"},null,2)+"\n",goPin=gitBlobMeta(goRaw),newSlot=plan.newSlot;
 let fakeArchiveCalls=0;
 function environment(source=after){
  const map=new Map([[plan.originalPausedSlot,j("OLD-STATE.paused.original.json")],[plan.completedRetrievalSlot,j("RETRIEVAL-STATE.closed.original.json")],[plan.completedRetrievalSlot+":payload-original",raw("INFO-payload.original.json")]]);
  const archives=[];
  async function archiveFlatPublicTextsOnce(x){fakeArchiveCalls++;archives.push(x);return {whole:true,tree:"a".repeat(40),entries:Object.entries(x.texts).map(([path,t])=>({path,...gitBlobMeta(t),whole:true}))};}
  const api=new Function("store","load","tools","archiveFlatPublicTextsOnce",raw("pure_helpers.original.js")+"\n"+source+"\nreturn{gfInitializeOnlyAfterRootGO,gfValidateRequest,gfPrepareOne,gfAcceptArchivedSDK,gfRun};")((k,v)=>map.set(k,v),k=>map.get(k),Object.freeze({}),archiveFlatPublicTextsOnce);
  return {map,archives,api,init(){return api.gfInitializeOnlyAfterRootGO({goRaw,goPin,goWholeReadback:true});}};
 }
 function denied(f){try{f();return false;}catch{return true;}}
 let e=environment();e.init();const initial=e.map.get(newSlot);
 ck("fresh BODY state without manufactured old job",initial.job===null&&initial.startCalled===false&&initial.completedObservers.length===0&&Object.keys(initial.calls).length===0&&initial.onlyOracleReportBody===true&&initial.oracleReportBodyStarted===false);
 ck("second initialize rejected",denied(()=>e.init()));
 ck("real new arm binds BODY GO",((await e.api.gfPrepareOne({callKey:"fake-body-admit",kind:"operation_start",requestRaw:raw("request.exact.json")})),same(JSON.parse(e.archives[0].texts["armed.json"]).rootGo,goPin)&&same(JSON.parse(e.archives[0].texts["intent.json"]).rootGo,goPin)));
 ck("old two contexts unchanged after prepare",same(e.map.get(plan.originalPausedSlot),j("OLD-STATE.paused.original.json"))&&same(e.map.get(plan.completedRetrievalSlot),j("RETRIEVAL-STATE.closed.original.json")));
 e=environment();e.init();
 ck("process start denied",denied(()=>e.api.gfValidateRequest(e.map.get(newSlot),"process_start",{},"{}")));
 const badInfo={idempotency_key:"fake-info",operation:{tool:"file_info",arguments:{host:"mac",path:plan.fixedReport.path}}};
 ck("file_info denied",denied(()=>e.api.gfValidateRequest(e.map.get(newSlot),"operation_start",badInfo,JSON.stringify(badInfo))));
 const bad={...req,operation:{tool:"binary_read",arguments:{...req.operation.arguments,expected_version:"wrong"}}};
 ck("wrong version denied",denied(()=>e.api.gfValidateRequest(e.map.get(newSlot),"operation_start",bad,JSON.stringify(bad))));
 e.map.get(newSlot).oracleReportBodyStarted=true;
 ck("second body admission denied",denied(()=>e.api.gfValidateRequest(e.map.get(newSlot),"operation_start",req,raw("request.exact.json"))));
 e=environment();e.map.get(plan.originalPausedSlot).pending="changed";
 ck("changed original paused state denied",denied(()=>e.init()));
 e=environment();e.map.get(plan.completedRetrievalSlot).closed=false;
 ck("changed completed retrieval denied",denied(()=>e.init()));
 for(const kind of ["operation_status","operation_result"]){
  e=environment();e.init();const s=e.map.get(newSlot),id="b".repeat(64);
  s.activeObserver={id,tool:"binary_read",futureClosed:kind==="operation_result",nextPageOffset:0,eof:false,pages:[],total:null,digest:null};
  s.oracleReportBodyStarted=true;
  const q=kind==="operation_status"?{operation_id:id}:{operation_id:id,offset:0,limit:16384};
  await e.api.gfPrepareOne({callKey:"fake-"+kind.replaceAll("_","-"),kind,requestRaw:JSON.stringify(q,null,2)+"\n"});
  ck("new "+kind+" arm exact BODY GO",same(JSON.parse(e.archives[0].texts["armed.json"]).rootGo,goPin));
 }
 const pageSDKRaw=raw("known-original-16384-page.sdk.json"),pageSDK=JSON.parse(pageSDKRaw),page=parseLosslessIntegers(pageSDK.content[0].text);
 ck("known original16384 page source",gitBlobMeta(pageSDKRaw).blob==="5ceec5345171ff27f8bd0265c94f0f8e6a0cef7c"&&unb64(page.data_base64).length===16384);
 function pageEnvironment(tool,source=after){
  const e=environment(source);e.init();const s=e.map.get(newSlot),key="fake-known-original-page0";
  s.activeObserver={id:page.operation_id,tool,futureClosed:true,nextPageOffset:0,eof:false,pages:[],total:null,digest:null};
  s.pending=key;s.calls[key]={kind:"operation_result",phase:"sdk_whole_uninterpreted",sdkArchive:{whole:true},sdkPin:gitBlobMeta(pageSDKRaw),requestRaw:JSON.stringify({operation_id:page.operation_id,offset:0,limit:tool==="binary_read"?16384:8192})};
  e.map.set(newSlot+":original_sdk_raw:"+key,pageSDKRaw);return {e,key};
 }
 let pe=pageEnvironment("binary_read");pe.e.api.gfAcceptArchivedSDK(pe.key);
 ck("actual original16K binary page accepted",pe.e.map.get(newSlot).activeObserver.nextPageOffset===16384&&pe.e.map.get(newSlot).activeObserver.pages.length===1);
 pe=pageEnvironment("file_info");
 ck("same actual16K still rejected by INFO8K guard",denied(()=>pe.e.api.gfAcceptArchivedSDK(pe.key)));
 const oldAccept=raw("prior-8192-accept.original.js");
 const downgraded=after.replace(fn(after,"gfAcceptArchivedSDK"),oldAccept.trim());
 pe=pageEnvironment("binary_read",downgraded);
 ck("same original16K rejected by retained pre-fix8192 expression",denied(()=>pe.e.api.gfAcceptArchivedSDK(pe.key)));
 ck("private harness no Native and only three fake archive preparations",fakeArchiveCalls===3);
 return {schema:"heptabao.mac4a.standalone-body-source-checks.r1",passed:true,check_count:checks.length,checks,NativeCalls:0,GitCalls:0,realContextsModified:false,fakeArchiveCalls,actualMetadataOnly:true,reportBodyRead:false,GOIssued:false};
}