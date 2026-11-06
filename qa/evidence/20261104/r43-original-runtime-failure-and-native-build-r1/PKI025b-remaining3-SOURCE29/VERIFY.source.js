function verifyRemainingThreeSource(input) {
 const rows=[]; const check=(name,ok)=>{rows.push({name,pass:!!ok});if(!ok)throw Error("check:"+name);};
 const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
 const {before,source,diff,replacements,plan}=input;
 check("base exact whole",same(gitBlobMeta(before),plan.base));
 check("candidate exact whole",same(gitBlobMeta(source),plan.candidate));
 const f=applyStrictUnified(before,diff),r=applyStrictUnified(source,diff,true);
 check("strict forward five hunks",f.hunks===5&&f.text===source);
 check("strict reverse five hunks",r.hunks===5&&r.text===before);
 let rebuilt=before;
 for(const x of replacements){check("unique "+x.label,rebuilt.split(x.before).length-1===x.count);rebuilt=rebuilt.split(x.before).join(x.after);}
 check("six declared replacement groups only",replacements.length===6&&rebuilt===source);
 const defs=s=>{const m=[...s.matchAll(/^(?:async )?function ([A-Za-z0-9_]+)\(/gm)];return Object.fromEntries(m.map((v,i)=>[v[1],s.slice(v.index,m[i+1]?.index??s.length)]));};
 const bd=defs(before),ad=defs(source),changed=["gfState","gfInitializeOnlyAfterRootGO","gfValidateRequest","gfInvokePreparedOnce","gfRun"];
 check("same definition set",same(Object.keys(bd),Object.keys(ad)));
 for(const n of Object.keys(bd))check("definition "+n,changed.includes(n)?bd[n]!==ad[n]:bd[n]===ad[n]);
 check("whole per-file close unchanged",bd.gfCloseOriginalObserver===ad.gfCloseOriginalObserver);
 check("whole SDK accept unchanged",bd.gfAcceptArchivedSDK===ad.gfAcceptArchivedSDK);
 check("no native process call",!source.includes("tools.mcp__codex_apps__heptaruntime_mac_controller_process_start("));
 check("only three Runtime dispatch kinds",[...source.matchAll(/tools\.mcp__codex_apps__heptaruntime_mac_controller_([a-z_]+)\(/g)].map(m=>m[1]).join(",")==="operation_start,operation_status,operation_result");
 check("no historical store",!source.includes("store(GF_HISTORICAL_CONTEXTS"));
 const fakeQualificationRaw=JSON.stringify({schema:"PURE_TEST_ONLY_NOT_ROOT_AUTHORITY"})+"\n";
 let toolCalls=0,initializations=0,guardChecks=0;
 function make(overrides={}) {
  const data=new Map(),old=JSON.parse(input.oldStateRaw),rec=JSON.parse(input.recStateRaw);
  data.set(input.goShape.original_slot,old);data.set(input.goShape.predecessor_slot,rec);
  for(let i=0;i<4;i++)data.set(input.goShape.original_slot+":closed_native:"+old.publishedInfos[i].originalOperation,input.infoNativeRaws[i]);
  const fakeStore=(k,v)=>data.set(k,v),fakeLoad=k=>data.get(k);
  const noTools=new Proxy({}, {get(){return ()=>{toolCalls++;throw Error("NO_TOOLS_IN_PURE_GUARD");};}});
  const fn=new Function("tools","store","load",input.pure+"\n"+input.archive+"\n"+source+
   "\nreturn {init:gfInitializeOnlyAfterRootGO,state:gfState,validate:gfValidateRequest};")(noTools,fakeStore,fakeLoad);
  const g={...input.goShape,authorization:"GO",predecessor_root_qualification:gitBlobMeta(fakeQualificationRaw),...overrides};
  const raw=JSON.stringify(g,null,2)+"\n";
  const args={goRaw:raw,goPin:gitBlobMeta(raw),goWholeReadback:true,
   body0Raw:input.body0Raw,body0NativeRaw:input.body0NativeRaw,body0ReleaseRaw:input.body0ReleaseRaw,
   predecessorQualificationRaw:fakeQualificationRaw};
  return {data,fn,args,g};
 }
 function expectReject(name,work){let rejected=false;try{work();}catch(_){rejected=true;}guardChecks++;check("reject "+name,rejected);}
 function initOne(overrides){const e=make(overrides);const oldBefore=JSON.stringify(e.data.get(input.goShape.original_slot)),recBefore=JSON.stringify(e.data.get(input.goShape.predecessor_slot));e.fn.init(e.args);initializations++;check("private init historical context unchanged "+initializations,JSON.stringify(e.data.get(input.goShape.original_slot))===oldBefore&&JSON.stringify(e.data.get(input.goShape.predecessor_slot))===recBefore);return e;}
 expectReject("unauthorized GO template",()=>{const e=make({authorization:"NOT_AUTHORIZED_SOURCE_TEMPLATE"});e.fn.init(e.args);});
 expectReject("wrong remaining budget",()=>{const e=make({maximum_remaining_body_bytes:60209});e.fn.init(e.args);});
 expectReject("process permission",()=>{const e=make({process_start_authorized:true});e.fn.init(e.args);});
 expectReject("missing root qualification",()=>{const e=make({predecessor_root_qualification:null});e.fn.init(e.args);});
 expectReject("root qualification bytes mismatch",()=>{const e=make();e.args.predecessorQualificationRaw+=" ";e.fn.init(e.args);});
 expectReject("old UNKNOWN state mutation",()=>{const e=make();e.data.get(e.g.original_slot).paused=false;e.fn.init(e.args);});
 expectReject("closed predecessor state mutation",()=>{const e=make();e.data.get(e.g.predecessor_slot).pending="fabricated";e.fn.init(e.args);});
 expectReject("body0 actual bytes mismatch",()=>{const e=make();e.args.body0Raw+=" ";e.fn.init(e.args);});
 expectReject("body0 native bytes mismatch",()=>{const e=make();e.args.body0NativeRaw+=" ";e.fn.init(e.args);});
 expectReject("independent metadata bytes mismatch",()=>{const e=make();const old=e.data.get(e.g.original_slot);e.data.set(e.g.original_slot+":closed_native:"+old.publishedInfos[1].originalOperation,input.infoNativeRaws[1]+" ");e.fn.init(e.args);});
 const e=initOne(),s=e.fn.state(),args=(i)=>JSON.parse(input.requestRaws[i]);
 check("fresh context has no fabricated call",Object.keys(s.calls).length===0&&s.completedObservers.length===0&&s.inheritedClosedObservers.length===1);
 check("real body0 provenance inherited",s.publishedBodies.length===1&&s.publishedBodies[0].inherited===true&&s.publishedBodies[0].index===0&&s.publishedBodies[0].originalOperation===plan.body0Inherited.operation);
 check("four actual metadata full9 retained",same(s.publishedInfos,JSON.parse(input.oldStateRaw).publishedInfos));
 e.fn.validate(s,"operation_start",args(1),input.requestRaws[1]);guardChecks++;check("exact original body1 admitted by pure guard",true);
 expectReject("body0 repeat",()=>e.fn.validate(s,"operation_start",args(0),input.requestRaws[0]));
 expectReject("body2 before body1",()=>e.fn.validate(s,"operation_start",args(2),input.requestRaws[2]));
 expectReject("body3 before body1",()=>e.fn.validate(s,"operation_start",args(3),input.requestRaws[3]));
 expectReject("process START",()=>e.fn.validate(s,"process_start",{host:"rog"},"{}"));
 expectReject("file_info",()=>{const q=args(1);q.operation={tool:"file_info",arguments:{host:"rog",path:q.operation.arguments.path}};e.fn.validate(s,"operation_start",q,JSON.stringify(q));});
 for(const prop of ["host","path","expected_version","offset","limit"]){
  expectReject("changed "+prop,()=>{const q=args(1);q.operation.arguments[prop]=typeof q.operation.arguments[prop]==="number"?q.operation.arguments[prop]+1:q.operation.arguments[prop]+"x";e.fn.validate(s,"operation_start",q,JSON.stringify(q,null,2)+"\n");});
 }
 expectReject("changed private key",()=>{const q=args(1);q.idempotency_key+="x";e.fn.validate(s,"operation_start",q,JSON.stringify(q,null,2)+"\n");});
 s.publishedBodyStarted[1]=true;
 expectReject("repeated body1 admission",()=>e.fn.validate(s,"operation_start",args(1),input.requestRaws[1]));
 s.calls.one={kind:"operation_start",requestRaw:input.requestRaws[1]};
 s.publishedBodies.push({index:1});
 e.fn.validate(s,"operation_start",args(2),input.requestRaws[2]);guardChecks++;check("body2 guard only after body1 closure row",true);
 expectReject("body1 after body1 closure",()=>e.fn.validate(s,"operation_start",args(1),input.requestRaws[1]));
 s.publishedBodyStarted[2]=true;s.calls.two={kind:"operation_start",requestRaw:input.requestRaws[2]};s.publishedBodies.push({index:2});
 e.fn.validate(s,"operation_start",args(3),input.requestRaws[3]);guardChecks++;check("body3 guard only after body2 closure row",true);
 s.publishedBodyStarted[3]=true;s.calls.three={kind:"operation_start",requestRaw:input.requestRaws[3]};s.publishedBodies.push({index:3});
 expectReject("fourth admission after remaining three",()=>e.fn.validate(s,"operation_start",args(3),input.requestRaws[3]));
 const id="0".repeat(64);s.activeObserver={id,futureClosed:false,nextPageOffset:0,eof:false};
 e.fn.validate(s,"operation_status",{operation_id:id},"");guardChecks++;check("same original ID status accepted",true);
 expectReject("different status ID",()=>e.fn.validate(s,"operation_status",{operation_id:"1".repeat(64)},""));
 expectReject("page before native closed",()=>e.fn.validate(s,"operation_result",{operation_id:id,offset:0,limit:16384},""));
 for(let i=0;i<8;i++)s.calls["status"+i]={kind:"operation_status",requestRaw:JSON.stringify({operation_id:id})};
 expectReject("ninth status",()=>e.fn.validate(s,"operation_status",{operation_id:id},""));
 s.activeObserver.futureClosed=true;
 e.fn.validate(s,"operation_result",{operation_id:id,offset:0,limit:16384},"");guardChecks++;check("closed next original page accepted",true);
 expectReject("skipped page",()=>e.fn.validate(s,"operation_result",{operation_id:id,offset:16384,limit:16384},""));
 expectReject("larger page",()=>e.fn.validate(s,"operation_result",{operation_id:id,offset:0,limit:32768},""));
 for(let i=0;i<64;i++)s.calls["page"+i]={kind:"operation_result",requestRaw:JSON.stringify({operation_id:id})};
 expectReject("65th page",()=>e.fn.validate(s,"operation_result",{operation_id:id,offset:0,limit:16384},""));
 expectReject("second initialize",()=>e.fn.init(e.args));
 e.data.get(e.g.original_slot).paused=false;
 expectReject("historical mutation after initialization",()=>e.fn.state());
 check("pure tests made zero tool calls",toolCalls===0);
 return {status:"PASS_SOURCE_AND_PRIVATE_MEMORY_GUARDS_ONLY",checks:rows.length,guardCases:guardChecks,rows,privateInitializations:initializations,selectedFunctions:["gfInitializeOnlyAfterRootGO","gfState","gfValidateRequest"],realContextInitialized:false,NativeCalls:0,GitCalls:0,productCases:0,actualBodies1to3Submitted:0};
}
