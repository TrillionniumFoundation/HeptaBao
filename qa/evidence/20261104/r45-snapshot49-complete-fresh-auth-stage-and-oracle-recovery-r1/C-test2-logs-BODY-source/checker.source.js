function checkFailedTestBodiesSource(input) {
 const rows=[];function c(k,v){rows.push({check:k,pass:!!v});if(!v)throw Error(k);}
 const eq=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
 const {before,after,expected,requestRaws,requestPins}=input;
 c("strict-forward",applyStrict(before,input.diff)===after);
 c("strict-reverse",applyStrict(after,input.diff,true)===before);
 c("two-ranges-566",expected.length===2&&expected[0].bytes===191&&expected[1].bytes===375&&expected.reduce((a,x)=>a+x.bytes,0)===566);
 for(let i=0;i<2;i++){
  const q=JSON.parse(requestRaws[i]),a=q.operation.arguments;
  c("request-pin-"+i,eq(gitBlobMeta(requestRaws[i]),requestPins[i]));
  c("exact-versioned-range-"+i,q.operation.tool==="binary_read"&&a.host==="rog"&&a.path===expected[i].path&&a.offset===0&&a.limit===expected[i].bytes&&a.expected_version===expected[i].version);
 }
 function functionText(source,name) {
  const at=source.search(new RegExp("^(?:async )?function "+name+"\\(","m"));if(at<0)throw Error(name);
  const next=source.slice(at+1).search(/^(?:async )?function /m);
  return next<0?source.slice(at):source.slice(at,at+1+next);
 }
 for(const name of ["gfNeed","gfMetaEquals","gfState","gfSave","gfIntegerText","gfInitializeOnlyAfterRootGO","gfReconcileSameGitArchiveReadOnly"]){
  c("whole-function-"+name,functionText(before,name)===functionText(after,name));
 }
 const go={authorization:"GO",scope:"build_failed_test2_logs_binary_read_only",original_job:"1a1b10cad9b-fc05-7560",maximum_binary_read_starts:2,maximum_file_info_starts:0,maximum_process_start_calls:0,immutable_body_page_bytes:16384,exact_requests:requestPins,info_operations:expected.map(x=>x.infoOperation)};
 function fixture() {
  const map=new Map([[input.slot,JSON.parse(input.stateRaw)],[input.priorSlot,JSON.parse(input.priorStateRaw)]]);
  for(let i=0;i<2;i++)map.set(input.slot+":closed_native:"+expected[i].infoOperation,input.nativeRaws[i]);
  const f=new Function("tools","store","load",input.pure+"\n"+input.archive+"\n"+after+"\nreturn {authorize:gfAuthorizeFailedTestLogBodiesOnly,validate:gfValidateRequest};")({},(k,v)=>map.set(k,v),k=>map.get(k));
  return {map,f};
 }
 const fx=fixture(),goRaw=JSON.stringify(go,null,2)+"\n";
 const result=fx.f.authorize({goRaw,goPin:gitBlobMeta(goRaw),goWholeReadback:true});
 const st=fx.map.get(input.slot);
 c("actual-two-infos-authorized",result.maximumBinaryReads===2&&result.bytes===566&&st.failedTestLogBodiesGO.whole===true);
 c("old-callmap-preserved",eq(st.calls,JSON.parse(input.stateRaw).calls)&&eq(st.completedObservers,JSON.parse(input.stateRaw).completedObservers));
 c("prior-build-context-preserved",JSON.stringify(fx.map.get(input.priorSlot),null,2)+"\n"===input.priorStateRaw);
 function rejected(label,fn){let err=null;try{fn();}catch(e){err=e;}c(label,err!==null);}
 const q0=JSON.parse(requestRaws[0]),q1=JSON.parse(requestRaws[1]);
 fx.f.validate(st,"operation_start",q0,requestRaws[0]);c("first-fixed-body-allowed",true);
 rejected("process-start-rejected",()=>fx.f.validate(st,"process_start",{}, "{}"));
 rejected("new-INFO-rejected",()=>fx.f.validate(st,"operation_start",{operation:{tool:"file_info",arguments:{host:"rog",path:expected[0].path}}},"{}"));
 rejected("second-before-first-closed-rejected",()=>fx.f.validate(st,"operation_start",q1,requestRaws[1]));
 const drift=JSON.parse(requestRaws[0]);drift.operation.arguments.expected_version+="0";
 rejected("version-drift-rejected",()=>fx.f.validate(st,"operation_start",drift,JSON.stringify(drift)));
 const wrong=JSON.parse(requestRaws[0]);wrong.operation.arguments.path=expected[1].path;
 rejected("path-drift-rejected",()=>fx.f.validate(st,"operation_start",wrong,JSON.stringify(wrong)));
 st.failedTestLogBodyStarted[0]=true;
 rejected("repeated-first-body-rejected",()=>fx.f.validate(st,"operation_start",q0,requestRaws[0]));
 st.failedTestLogBodies.push({pureFixture:true});st.completedObservers.push({pureFixture:true});st.calls.pureFixture={kind:"operation_start"};
 fx.f.validate(st,"operation_start",q1,requestRaws[1]);c("second-after-first-closed-allowed",true);
 st.failedTestLogBodyStarted[1]=true;st.failedTestLogBodies.push({pureFixture:true});st.completedObservers.push({pureFixture:true});st.calls.pureFixture2={kind:"operation_start"};
 rejected("no-third-body",()=>fx.f.validate(st,"operation_start",q1,requestRaws[1]));
 c("whole-payload-before-parse",after.indexOf('texts:{"payload.original.json":raw}')<after.indexOf("const p=parseLosslessIntegers(raw);"));
 c("whole-body-before-store",after.indexOf('key:"gcc-testlog-"+a.id')<after.indexOf('store(GF_SLOT+":test_log_original:"+i,bodyRaw);'));
 c("exact-body-SHA-and-EOF",after.includes('v.next_offset===need.bytes && v.eof===true')&&after.includes('bodyPin.sha256===need.sha256'));
 c("old8K-new16K",after.includes('q.limit===(s.activeObserver.tool==="binary_read"?16384:8192)')&&after.includes('gfNeed(b.length<=(a.tool==="binary_read"?16384:8192)'));
 c("oneMiB-payload-preserved",after.includes("v.total_bytes<=1048576"));
 return {schema:"heptabao.failed-test2-two-body-source-checks.r1",pass:true,check_count:rows.length,checks:rows,Native_calls:0,Git_mutations:0,product_cases:0};
}
