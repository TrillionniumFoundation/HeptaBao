function verifyBody1SuccessorSource(input) {
 const checks=[];
 function ck(name,v){if(!v)throw new Error(name);checks.push({name,passed:true});}
 function noThrow(name,fn){fn();checks.push({name,passed:true});}
 function rejects(name,fn){let failed=false;try{fn();}catch{failed=true;}ck(name,failed);}
 for(const [name,raw,pin] of [
  ["base",input.before,input.beforePin],["candidate",input.after,input.afterPin],
  ["BODY0 original request",input.originalBody0Request.raw,input.originalBody0Request.pin],
  ["BODY1 original request",input.futureBody1Request.raw,input.futureBody1Request.pin],
  ["BODY0 actual native",input.body0NativeRaw,input.body0NativePin],
  ["BODY0 root qualification",input.rootBody0Qualification.raw,input.rootBody0Qualification.pin]
 ]){ck("whole "+name,JSON.stringify(gitBlobMeta(raw))===JSON.stringify(pin));}
 let transformed=input.before;
 for(const e of input.edits){ck("unique edit "+e.label,transformed.split(e.before).length===2);transformed=transformed.replace(e.before,e.after);}
 ck("literal edit replay whole",transformed===input.after);
 ck("strict forward whole",snapshotApply(input.before,input.forward)===input.after);
 ck("strict backward whole",snapshotApply(input.after,input.forward,true)===input.before);
 ck("explicit reverse whole",snapshotApply(input.after,input.reverse)===input.before);
 const q=JSON.parse(input.futureBody1Request.raw),a=q.operation.arguments;
 ck("original BODY1 range exact",a.offset===65536&&a.limit===53389&&a.expected_version==="66306:31236133:118925:1793956739343592677:1793956739343592677");
 ck("original BODY1 key exact",q.idempotency_key==="heptabao-native-snapshot-2379d02b-formatter-observe-r1-result-body1");
 ck("native tool set only start/status/result",Array.from(new Set(input.after.match(/heptaruntime_mac_controller_[a-z_]+/g))).sort().join(",")==="heptaruntime_mac_controller_operation_result,heptaruntime_mac_controller_operation_start,heptaruntime_mac_controller_operation_status");
 ck("new slot only; never initialize old slot",input.after.includes('const GF_SLOT = "snapshot_2379_formatter_body1_completion_r1";')&&!input.after.includes("store(GF_ORIGINAL_SLOT,")&&!input.after.includes("store(GF_BODY0.slot,"));
 ck("old UNKNOWN guarded not cleared",input.after.includes("original_paused_context_must_remain_unchanged")&&input.after.includes('originalAttemptOutcome:"UNKNOWN"'));
 ck("BODY0 actual context guarded",input.after.includes("BODY0_reconciliation_context_must_remain_closed_and_unchanged"));
 ck("separate GO fields exact",input.after.includes('g.scope==="format_body1_exact_completion"')&&input.after.includes("g.body0_repeat_authorized===false")&&input.after.includes("g.file_info_authorized===false")&&input.after.includes("g.maximum_status_calls===8")&&input.after.includes("g.maximum_result_pages===64"));
 const extract=(s,name)=>{const re=new RegExp("(?:async )?function "+name+"\\("),m=re.exec(s);if(!m)throw new Error("function not found "+name);const tail=s.slice(m.index);const n=/\n(?:async )?function [a-zA-Z0-9_]+\(/.exec(tail);return n?tail.slice(0,n.index):tail;};
 ck("once Native invoke and SDK archiver unchanged",extract(input.before,"gfInvokePreparedOnce")===extract(input.after,"gfInvokePreparedOnce"));
 ck("read-only Git reconcile unchanged",extract(input.before,"gfReconcileSameGitArchiveReadOnly")===extract(input.after,"gfReconcileSameGitArchiveReadOnly"));
 ck("catch boundary unchanged",extract(input.before,"gfRun")===extract(input.after,"gfRun"));
 ck("report whole archive precedes success",input.after.indexOf('"report.original.public.json":reportRaw')<input.after.indexOf("s.wholeReport={"));
 ck("no report JSON parse before archival",!input.after.includes("JSON.parse(reportRaw)")&&!input.after.includes("parseLosslessIntegers(reportRaw)"));
 const noLoad=()=>{throw new Error("state access not authorized in this pure validator test");};
 const api=new Function("load","gitBlobMeta","parseLosslessIntegers","unb64","sha256Latin1","byteString",
  input.after+";return {validate:gfValidateRequest,verifyBody0:gfVerifyBody0Native};")(
  noLoad,gitBlobMeta,parseLosslessIntegers,unb64,sha256Latin1,byteString);
 const s=()=>({paused:false,nativeCallInFlight:false,pending:null,admissionCalled:false,
  activeObserver:null,completedObservers:[],body1Range:null,wholeReport:null,calls:{}});
 noThrow("selected pure validator accepts exact original BODY1",()=>api.validate(s(),"operation_start",q,input.futureBody1Request.raw));
 rejects("selected pure validator refuses BODY0",()=>api.validate(s(),"operation_start",JSON.parse(input.originalBody0Request.raw),input.originalBody0Request.raw));
 for(const [name,change] of [
  ["rekey",x=>x.idempotency_key+="-retry"],["wrong offset",x=>x.operation.arguments.offset=0],
  ["wrong limit",x=>x.operation.arguments.limit=65536],["changed version",x=>x.operation.arguments.expected_version+="0"],
  ["different path",x=>x.operation.arguments.path+="/other"],["different host",x=>x.operation.arguments.host="desktop"]
 ]){const x=JSON.parse(input.futureBody1Request.raw);change(x);rejects("refuse "+name,()=>api.validate(s(),"operation_start",x,JSON.stringify(x,null,2)+"\n"));}
 rejects("refuse business process_start",()=>api.validate(s(),"process_start",{},"{}"));
 rejects("refuse metadata tool entry",()=>api.validate(s(),"file_info",{},"{}"));
 rejects("refuse second BODY1 admission",()=>{const z=s();z.admissionCalled=true;api.validate(z,"operation_start",q,input.futureBody1Request.raw);});
 const op="36a74adfd7493cdb489a3426c421ac9d83e772f674a3aaab3c83fb3deea207af";
 const z=s();z.activeObserver={id:op,futureClosed:true,nextPageOffset:0,eof:false};
 noThrow("16KiB immutable page accepted for returned ID",()=>api.validate(z,"operation_result",{operation_id:op,offset:0,limit:16384},""));
 rejects("unexpected page offset refused",()=>api.validate(z,"operation_result",{operation_id:op,offset:16384,limit:16384},""));
 rejects("different returned ID refused",()=>api.validate(z,"operation_result",{operation_id:"0".repeat(64),offset:0,limit:16384},""));
 rejects("unclosed future page refused",()=>{const x=s();x.activeObserver={id:op,futureClosed:false,nextPageOffset:0,eof:false};api.validate(x,"operation_result",{operation_id:op,offset:0,limit:16384},"");});
 rejects("64-page limit refused",()=>{const x=s();x.activeObserver=z.activeObserver;x.calls=Object.fromEntries(Array.from({length:64},(_,i)=>[i,{kind:"operation_result"}]));api.validate(x,"operation_result",{operation_id:op,offset:0,limit:16384},"");});
 const r=api.verifyBody0(input.body0NativeRaw);
 ck("actual BODY0 decoded bytes reverified",r.offset===0&&r.next===65536&&r.bytes===65536&&r.chunkSha256==="e18d09bf4ecf8ad38c46d8ee3c46c5fa7d7816f680b98bce43f493053ce6f09e");
 rejects("altered BODY0 original refused",()=>api.verifyBody0(input.body0NativeRaw+"\n"));
 const root=JSON.parse(input.rootBody0Qualification.raw),release=JSON.parse(input.body0ReleaseRaw);
 ck("root48 and release establish predecessor closed",root.passed===true&&root.checkCount===48&&root.actualBinding===op&&root.reused===true&&root.body1Submitted===false&&release.lineBReleased===true&&release.currentToolCallsInFlight===0&&release.currentOwnedFutureObservedActive===false);
 return {schema:"heptabao.snapshot2379.formatter.BODY1-source-checks.v1",
  mode:"pure V8 hashes/strict diff plus selected pure validators only; no gfInitialize/gfRun/Native/Git called",
  checks,passed:checks.length,NativeCalls:0,candidateRuntimeInvoked:false};
}
