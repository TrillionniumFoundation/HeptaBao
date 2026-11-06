function verifyFormatterReceiptInfo(d,pure) {
 const P=new Function(pure+"\nreturn {gitBlobMeta};")(),checks=[],ck=(name,ok)=>{checks.push({name,pass:!!ok});if(!ok)throw Error(name);},clone=x=>JSON.parse(JSON.stringify(x));
 function defs(t){const found=[...t.matchAll(/^(?:async )?function ([A-Za-z0-9_]+)\(/gm)],out={};for(let i=0;i<found.length;i++)out[found[i][1]]=t.slice(found[i].index,i+1<found.length?found[i+1].index:t.length);return out;}
 const before=defs(d.beforeFormatter),after=defs(d.after);
 ck("one new explicit authorization function",Object.keys(after).length===Object.keys(before).length+1&&typeof after.gfAuthorizeFormatterReceiptInfoOnly==="string");
 const changed=["gfValidateRequest","gfPrepareOne","gfInvokePreparedOnce","gfCloseOriginalObserver","gfRun"];
 for(const n of Object.keys(before))if(!changed.includes(n))ck("whole original definition "+n,before[n]===after[n]);
 let rebuilt=d.beforeStageInfo;
 for(const r of d.replacements){ck("exact replacement count "+r.label,rebuilt.split(r.before).length-1===r.count);rebuilt=rebuilt.split(r.before).join(r.after);}
 ck("predecessor exact forward",rebuilt===d.after);
 for(const r of [...d.replacements].reverse()){if(r.label==="separate actual metadata state"){const re=/\bformatterReceiptInfo\b/g;ck("exact identifier inverse count "+r.label,(rebuilt.match(re)||[]).length===r.count);rebuilt=rebuilt.replace(re,r.before);}else{ck("exact inverse count "+r.label,rebuilt.split(r.after).length-1===r.count);rebuilt=rebuilt.split(r.after).join(r.before);}}
 ck("predecessor exact inverse",rebuilt===d.beforeStageInfo);
 const constants=d.after.slice(d.after.indexOf("const GF_SLOT"),d.after.indexOf("\nfunction gfAuthorizeFormatterReceiptInfoOnly"));
 const selected=pure+"\n"+constants+"\n"+after.gfNeed+after.gfMetaEquals+after.gfAuthorizeFormatterReceiptInfoOnly+after.gfValidateRequest;
 function fixture(mutator){const st=clone(d.state);let saves=0;const texts={...d.priorRaw};if(mutator)mutator(st,texts);
 const A=new Function("load","gfState","gfSave",selected+"\nreturn {authorize:gfAuthorizeFormatterReceiptInfoOnly,validate:gfValidateRequest};")(
 k=>texts[k],()=>st,()=>{saves++;});return {A,st,saves:()=>saves};}
 function go(change){const obj={authorization:"GO",scope:"formatter_receipt_file_info_only",original_job:d.state.job,maximum_file_info_starts:1,binary_read_authorized:false,exact_request:P.gitBlobMeta(d.requestRaw),fixtureOnly:true};if(change)change(obj);const raw=JSON.stringify(obj)+"\n";return{goRaw:raw,goPin:P.gitBlobMeta(raw),goWholeReadback:true};}
 function reject(label,f){let rejected=false;try{f();}catch(e){rejected=true;}ck("reject "+label,rejected);}
 const positive=fixture(),g=go();positive.A.authorize(g);ck("actual prior closed pins accepted",positive.st.formatterReceiptInfoGO?.whole===true&&positive.saves()===1);
 const q=JSON.parse(d.requestRaw);positive.A.validate(positive.st,"operation_start",q,d.requestRaw);ck("exact receipt-info accepted",true);
 reject("re-authorize same context",()=>positive.A.authorize(g));
 for(const [name,mut]of [
 ["wrong actual job",s=>s.job="wrong"],["active original observer",s=>s.activeObserver={}],["pending call",s=>s.pending="pending"],
 ["paused context",s=>s.paused=true],["native in flight",s=>s.nativeCallInFlight=true],["once started",s=>s.formatterReceiptInfoStarted=true],
 ["not original start",s=>s.startCalled=false],["missing prior closure",s=>s.completedObservers=[]],
 ["prior inactive false",s=>s.completedObservers[0].completedInactive=false]
 ]){const f=fixture(mut);reject(name,()=>f.A.authorize(go()));ck("no save after rejected "+name,f.saves()===0);}
 for(const [name,change]of [
 ["old stage scope",g=>g.scope="stage_result_file_info_only"],["binary permission",g=>g.binary_read_authorized=true],
 ["two metadata starts",g=>g.maximum_file_info_starts=2],["wrong request pin",g=>g.exact_request.sha256="0".repeat(64)]
 ]){const f=fixture();reject(name,()=>f.A.authorize(go(change)));}
 const fNoWhole=fixture(),noWhole=go();noWhole.goWholeReadback=false;reject("not whole GO",()=>fNoWhole.A.authorize(noWhole));
 const fCorrupt=fixture((s,texts)=>{const key=Object.keys(texts)[0];texts[key]+="\n";});reject("changed original native bytes",()=>fCorrupt.A.authorize(go()));
 const once=clone(positive.st);once.formatterReceiptInfoStarted=true;reject("metadata second admission",()=>positive.A.validate(once,"operation_start",q,d.requestRaw));
 const noGo=clone(d.state);reject("original formatter GO only",()=>positive.A.validate(noGo,"operation_start",q,d.requestRaw));
 for(const [name,mut]of [
 ["wrong path",q=>q.operation.arguments.path+="/other"],["wrong host",q=>q.operation.arguments.host="desktop"],
 ["extra argument",q=>q.operation.arguments.limit=1],["wrong key",q=>q.idempotency_key+="x"],
 ["binary_read",q=>q.operation.tool="binary_read"]
 ]){const bad=clone(q);mut(bad);reject(name,()=>positive.A.validate(positive.st,"operation_start",bad,JSON.stringify(bad)+"\n"));}
 const close=after.gfCloseOriginalObserver,begin=close.indexOf("   const md=v.metadata"),end=close.indexOf('\n  } else gfNeed(v.job_id',begin);
 const metadataBody=close.slice(begin,end),checkMeta=new Function("v","s","a",pure+"\n"+constants+"\n"+after.gfNeed+"\nconst nativeRaw=JSON.stringify(v);\n"+metadataBody+"\nreturn s.formatterReceiptInfo;");
 const valid={path:q.operation.arguments.path,size:12345,sha256:"a".repeat(64),mode:384,metadata:{metadata_platform:"linux",mode:384,uid:1000,gid:1000,link_count:1},version:"66306:123:12345:1793937480631234567:1793937480631234568"};
 const actual=checkMeta(clone(valid),{},{id:"fixture"});ck("metadata full mode uses OR",actual.full9Strings[4]==="33152");ck("decimal nanoseconds unchanged",actual.full9Strings[7]==="1793937480631234567"&&actual.full9Strings[8]==="1793937480631234568");
 for(const [name,mut]of [["over receipt cap",v=>{v.size=65537;v.version="66306:123:65537:1:2";}],["native full mode confused",v=>v.mode=33152],["wrong uid",v=>v.metadata.uid=0],["multiple links",v=>v.metadata.link_count=2],["wrong version size",v=>v.version="66306:123:999:1:2"],["rounded exponent ns",v=>v.version="66306:123:12345:1.7939374806312346e18:2"]]){
 const v=clone(valid);mut(v);reject(name,()=>checkMeta(v,{},{id:"fixture"}));}
 ck("once flag before original Native dispatch",after.gfInvokePreparedOnce.indexOf("s.formatterReceiptInfoStarted=true")<after.gfInvokePreparedOnce.indexOf("sdk=await tools."));
 ck("info cap is original planned receipt cap",d.after.includes("const GF_FORMATTER_RECEIPT_MAX_BYTES = 65536;"));
 ck("old immutable page cap unchanged",after.gfValidateRequest.includes("q.limit===8192"));
 ck("explicit action only",after.gfRun.includes('action==="authorize_formatter_receipt_info"'));
 return {schema:"heptabao.formatter-receipt-info.selected-source-checks.v1",checks,passed:checks.length,failed:0,execution:"only selected pure authorization/request/metadata guards with mocked state; no full journal, IO, Runtime, Python or Rust",newRuntimeCalls:0};
}