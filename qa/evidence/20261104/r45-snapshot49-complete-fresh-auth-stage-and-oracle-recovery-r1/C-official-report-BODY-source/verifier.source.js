async function verifyOracleReportBodySource(files) {
 const checks=[];function ck(name,v){checks.push({name,passed:!!v});if(!v)throw Error(name);}
 const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b),meta=gitBlobMeta;
 const plan=JSON.parse(files["PLAN.public.json"]),before=files["journal.before.js"],after=files["journal.after.js"];
 const current=JSON.parse(files["STATE.info-closed.original.json"]),oldRaw=files["ORIGINAL.paused-state.json"],infoRaw=files["INFO.native.original.json"];
 const requestRaw=files["REQUEST.exact.json"],q=JSON.parse(requestRaw),info=parseLosslessIntegers(infoRaw);
 ck("strict forward",applyStrict(before,files["journal.strict.diff"],false)===after);
 ck("strict reverse",applyStrict(after,files["journal.strict.diff"],true)===before);
 ck("exact after source",same(meta(after),plan.source));
 ck("exact fixed request",same(meta(requestRaw),plan.request));
 ck("actual closed state exact",same(meta(files["STATE.info-closed.original.json"]),plan.closedInfoState));
 ck("actual independent INFO exact",same(meta(infoRaw),plan.infoNative));
 ck("old paused state exact",same(meta(oldRaw),plan.originalPausedState));
 ck("original 223583 bytes preserved",meta(oldRaw).bytes===223583);
 ck("closed new context two accepted calls",Object.keys(current.calls).length===2&&Object.values(current.calls).every(c=>c.phase==="accepted"&&c.sdkArchive.whole));
 ck("original one completed INFO",current.completedObservers.length===1&&current.completedObservers[0].completedInactive&&current.activeObserver===null&&current.pending===null&&!current.paused&&!current.nativeCallInFlight);
 ck("original unknown not reset",JSON.parse(oldRaw).paused&&JSON.parse(oldRaw).pending==="official271-x230-acl23-report-info-status0-r1");
 ck("one actual body offset length",q.operation.tool==="binary_read"&&q.operation.arguments.offset===0&&q.operation.arguments.limit===36658);
 ck("same actual path host version",q.operation.arguments.host==="x230"&&q.operation.arguments.path===info.path&&q.operation.arguments.expected_version===info.version);
 ck("same whole SHA size",info.size===36658&&info.sha256===plan.target.sha256&&current.oracleReportInfo.sha256===info.sha256);
 const regenerated=new Function(files["pure.original.js"]+"\n"+files["strict-diff.original.js"]+"\n"+files["deriver.source.js"]+"\nreturn deriveOracleReportBodyFromReconciledInfo;")()({after:before},files["STATE.info-closed.original.json"],infoRaw);
 ck("actual deriver byteexact",regenerated.after===after&&regenerated.requestRaw===requestRaw);
 ck("payload body fixed SHA and EOF",after.includes('v.version===n.version && v.chunk_sha256===n.sha256')&&after.includes("v.next_offset===n.bytes && v.eof===true"));
 ck("body archive before stored semantic value",after.indexOf('texts:{"report.original.json":bodyRaw,"native.original.json":nativeRaw}')<after.indexOf("s.oracleReportBody={body:bodyPin"));
 ck("original slot check remains every step",after.includes('gfMetaEquals(JSON.stringify(load(GF_ORIGINAL_SLOT),null,2)+"\\n",GF_ORIGINAL_PAUSED_STATE)'));
 ck("no process_start tool dispatch",!after.includes("tools.mcp__codex_apps__heptaruntime_mac_controller_process_start"));
 for(const name of ["gfState","gfInitializeOnlyAfterRootGO","gfReconcileSameGitArchiveReadOnly"]) {
  const get=s=>{const at=s.indexOf("function "+name+"(");return s.slice(at,s.indexOf("\n}",at)+2);};
  ck("unchanged "+name,get(before)===get(after));
 }
 const go={authorization:"GO",scope:"official271_oracle_result_binary_read_only",original_job:"1a1b17f9eff-fc05-7932",
  maximum_binary_read_operations:1,maximum_file_info_operations:0,maximum_process_start_calls:0,
  maximum_operation_status_calls:8,maximum_operation_result_calls:128,maximum_payload_bytes:1048576,
  immutable_body_page_bytes:16384,info_operation:current.oracleReportInfo.originalOperation,exact_request:meta(requestRaw)};
 const goRaw=JSON.stringify(go,null,2)+"\n",goPin=meta(goRaw),slot=plan.slot,oldSlot="official271_x230_acl23_oracle_gitfirst_r1";
 function harness() {
  const values=new Map([[slot,JSON.parse(files["STATE.info-closed.original.json"])],[oldSlot,JSON.parse(oldRaw)],[slot+":closed_native:"+current.oracleReportInfo.originalOperation,infoRaw]]);
  const archives=[];const archive=async args=>{archives.push(args);return {tree:"a".repeat(40),whole:true,entries:Object.entries(args.texts).map(([path,raw])=>({path,...meta(raw),whole:true}))};};
  const api=new Function("tools","store","load","archiveFlatPublicTextsOnce",files["pure.original.js"]+"\n"+after+"\nreturn {run:gfRun,validate:gfValidateRequest};")({},(k,v)=>values.set(k,v),k=>values.get(k),archive);
  return {api,values,archives};
 }
 async function auth(h){return h.api.run("authorize_oracle_report_body",{goRaw,goPin,goWholeReadback:true,priorStateRaw:files["STATE.info-closed.original.json"]});}
 let h=harness(),r=await auth(h);ck("actual authorization succeeds",r.ok);
 ck("authorization preserves original history",same(h.values.get(slot).calls,current.calls)&&JSON.stringify(h.values.get(oldSlot),null,2)+"\n"===oldRaw);
 ck("exact body has distinct GO",same(h.values.get(slot).oracleReportBodyGO.pin,goPin)&&goPin.blob!==current.goPin.blob);
 const fakeID="d".repeat(64);
 for(const kind of ["operation_start","operation_status","operation_result"]) {
  h=harness();r=await auth(h);if(!r.ok)throw Error("auth fixture");
  const s=h.values.get(slot);
  if(kind!=="operation_start"){s.oracleReportBodyStarted=true;s.activeObserver={id:fakeID,tool:"binary_read",futureClosed:kind==="operation_result",eof:false,nextPageOffset:0,pages:[]};}
  const raw=kind==="operation_start"?requestRaw:JSON.stringify(kind==="operation_status"?{operation_id:fakeID}:{operation_id:fakeID,offset:0,limit:16384},null,2)+"\n";
  r=await h.api.run("prepare",{callKey:"fake-body-"+kind.replaceAll("_","-"),kind,requestRaw:raw});
  ck("actual prepare succeeds "+kind,r.ok&&h.archives.length===1);
  ck("three leaf arm uses BODY GO "+kind,Object.keys(h.archives[0].texts).length===3&&same(JSON.parse(h.archives[0].texts["intent.json"]).rootGo,goPin)&&same(JSON.parse(h.archives[0].texts["armed.json"]).rootGo,goPin));
  ck("prior INFO calls unchanged "+kind,same(h.values.get(slot).calls[Object.keys(current.calls)[0]],current.calls[Object.keys(current.calls)[0]])&&same(h.values.get(slot).calls[Object.keys(current.calls)[1]],current.calls[Object.keys(current.calls)[1]])&&JSON.stringify(h.values.get(oldSlot),null,2)+"\n"===oldRaw);
 }
 function rejected(label,edit,kind,req){const h=harness();const s=h.values.get(slot);s.oracleReportBodyGO={pin:goPin,whole:true};s.onlyOracleReportBody=true;s.oracleReportBodyStarted=false;s.oracleReportBody=null;edit(s);let rejected=false;try{h.api.validate(s,kind,req,JSON.stringify(req,null,2)+"\n");}catch{rejected=true;}ck(label,rejected);}
 rejected("refuses process",()=>{},"process_start",{});
 rejected("refuses new INFO",()=>{},"operation_start",{idempotency_key:"forbidden",operation:{tool:"file_info",arguments:{host:"x230",path:info.path}}});
 rejected("refuses version drift",()=>{},"operation_start",{...q,operation:{...q.operation,arguments:{...q.operation.arguments,expected_version:"wrong"}}});
 rejected("refuses duplicate binary marker",s=>s.oracleReportBodyStarted=true,"operation_start",q);
 rejected("refuses old INFO status",s=>{s.oracleReportBodyStarted=true;s.activeObserver={id:fakeID,tool:"binary_read",futureClosed:false};},"operation_status",{operation_id:info.originalOperation??current.oracleReportInfo.originalOperation});
 rejected("refuses ninth body status",s=>{s.oracleReportBodyStarted=true;s.activeObserver={id:fakeID,tool:"binary_read",futureClosed:false};for(let i=0;i<8;i++)s.calls["fake-status-"+i]={kind:"operation_status",requestRaw:JSON.stringify({operation_id:fakeID})};},"operation_status",{operation_id:fakeID});
 rejected("refuses page before closed",s=>{s.oracleReportBodyStarted=true;s.activeObserver={id:fakeID,tool:"binary_read",futureClosed:false,eof:false,pages:[],nextPageOffset:0};},"operation_result",{operation_id:fakeID,offset:0,limit:16384});
 rejected("refuses wrong page offset",s=>{s.oracleReportBodyStarted=true;s.activeObserver={id:fakeID,tool:"binary_read",futureClosed:true,eof:false,pages:[],nextPageOffset:0};},"operation_result",{operation_id:fakeID,offset:16384,limit:16384});
 h=harness();r=await h.api.run("prepare",{callKey:"fake-no-body-go",kind:"operation_start",requestRaw});ck("prepare before BODY authority refuses",!r.ok&&h.archives.length===0);
 ck("no fake native tool available",true);
 return {schema:"heptabao.oracle-report-body-source-check.r1",passed:true,check_count:checks.length,checks,native_calls:0,python_runs:0,product_cases:0,actual_body_observed:false};
}