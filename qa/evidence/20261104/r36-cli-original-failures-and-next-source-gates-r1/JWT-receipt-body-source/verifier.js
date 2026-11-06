function verifyBodyScope(d,pureSource) {
 const P=new Function(pureSource+"\nreturn {gitBlobMeta,parseLosslessIntegers,unb64,utf8Text};")();
 const checks=[];function ck(name,v){checks.push({name,pass:!!v});if(!v)throw Error(name);}
 function clone(v){return JSON.parse(JSON.stringify(v));}
 function def(t,name){const r=new RegExp("^(?:async )?function "+name+"\\(","m"),m=r.exec(t);if(!m)throw Error("no def");const e=t.indexOf("\n",m.index),line=t.slice(m.index,e);if(line.endsWith("}"))return line+"\n";const end=t.indexOf("\n}\n",e);if(end<0)throw Error("def close");return t.slice(m.index,end+3);}
 let patched=d.before;for(const r of d.replacements){ck("one_before_"+r.label,patched.split(r.before).length===2);patched=patched.replace(r.before,r.after);}ck("forward_whole",patched===d.after);
 for(const r of [...d.replacements].reverse()){ck("one_after_"+r.label,patched.split(r.after).length===2);patched=patched.replace(r.after,r.before);}ck("reverse_whole",patched===d.before);
 ck("eight_diff_hunks",(d.diff.match(/^@@/gm)||[]).length===8);
 const names=[...d.before.matchAll(/^(?:async )?function ([A-Za-z0-9_]+)\(/gm)].map(m=>m[1]),newNames=[...d.after.matchAll(/^(?:async )?function ([A-Za-z0-9_]+)\(/gm)].map(m=>m[1]);
 ck("one_new_15th_definition",names.length===14&&newNames.length===15);
 const changed=["gfValidateRequest","gfPrepareOne","gfInvokePreparedOnce","gfAcceptArchivedSDK","gfCloseOriginalObserver","gfRun"];
 for(const name of names)if(!changed.includes(name))ck("whole_original_definition_"+name,def(d.before,name)===def(d.after,name));
 const constants=d.after.slice(d.after.indexOf("const GF_SLOT"),d.after.indexOf("\nfunction gfAuthorizeFormatterReceiptInfoOnly"))+"\n"+
   d.after.slice(d.after.indexOf("const GF_FORMATTER_RECEIPT_BODY_REQUEST"),d.after.indexOf("\nfunction gfAuthorizeFormatterReceiptBodyOnly"));
 let current;
 const selected=constants+"\n"+def(d.after,"gfNeed")+def(d.after,"gfMetaEquals")+def(d.after,"gfAuthorizeFormatterReceiptBodyOnly")+def(d.after,"gfValidateRequest");
 const api=new Function("gitBlobMeta","parseLosslessIntegers","gfState","gfSave","load",selected+"\nreturn{authorize:gfAuthorizeFormatterReceiptBodyOnly,validate:gfValidateRequest};")
   (P.gitBlobMeta,P.parseLosslessIntegers,()=>current,s=>{current=s;},k=>k==="jwt_e3af_rog_formatter_gitfirst_r1:closed_native:"+d.binding.infoOperation?d.infoNative:undefined);
 const q=JSON.parse(d.requestRaw),rp=P.gitBlobMeta(d.requestRaw);
 const g={authorization:"GO",scope:"formatter_receipt_binary_read_only",original_job:d.baseState.job,info_operation:d.binding.infoOperation,maximum_binary_read_starts:1,immutable_page_bytes:16384,exact_request:rp},goRaw=JSON.stringify(g);
 const auth={goRaw,goPin:P.gitBlobMeta(goRaw),goWholeReadback:true};
 function reset(){current=clone(d.baseState);}
 function refuses(name,fn){let threw=false;try{fn();}catch(e){threw=true;}ck(name,threw);}
 reset();refuses("no_body_under_info_GO",()=>api.validate(current,"operation_start",q,d.requestRaw));
 api.authorize(auth);api.validate(current,"operation_start",q,d.requestRaw);ck("new_exact_body_GO_and_request_accept",true);
 refuses("no_second_body_capability",()=>api.authorize(auth));current.formatterReceiptBodyStarted=true;refuses("no_second_body_START",()=>api.validate(current,"operation_start",q,d.requestRaw));
 reset();refuses("old_info_GO_cannot_grant_body",()=>api.authorize({goRaw:d.oldInfoGO,goPin:P.gitBlobMeta(d.oldInfoGO),goWholeReadback:true}));
 reset();current.activeObserver={id:"unclosed"};refuses("unfinished_previous_observer",()=>api.authorize(auth));
 reset();current.formatterReceiptInfo.version+="0";refuses("changed_actual_metadata_version",()=>api.authorize(auth));
 reset();current.completedObservers.find(x=>x.id===d.binding.infoOperation).completedInactive=false;refuses("unclosed_actual_info",()=>api.authorize(auth));
 reset();refuses("GO_not_whole",()=>api.authorize({...auth,goWholeReadback:false}));
 const variants=[
  ["wrong_host",v=>v.operation.arguments.host="desktop"],
  ["wrong_path",v=>v.operation.arguments.path+="/another"],
  ["wrong_version",v=>v.operation.arguments.expected_version+="0"],
  ["wrong_offset",v=>v.operation.arguments.offset=1],
  ["larger_limit",v=>v.operation.arguments.limit=65536],
  ["new_key",v=>v.idempotency_key+="-retry"],
  ["extra_argument",v=>v.operation.arguments.extra=true]
 ];
 for(const[name,mutate]of variants){reset();api.authorize(auth);const v=clone(q);mutate(v);refuses(name,()=>api.validate(current,"operation_start",v,JSON.stringify(v,null,2)+"\n"));}
 const close=def(d.after,"gfCloseOriginalObserver"),start=close.indexOf('  if(a.tool==="binary_read") {'),end=close.indexOf(' else if(a.tool==="file_info")',start);
 ck("selected_binary_branch_exact",start>=0&&end>start);
 // Test the exact branch against a previously archived public whole binary
 // response. Only the fixture expected data parameter changes; no current
 // report content is fabricated, and the actual candidate constants are fixed.
 const old=JSON.parse(d.historicalBinaryNative),fixtureExpected={path:old.path,version:old.version,bytes:old.size,sha256:old.chunk_sha256,infoOperation:"historical-fixture"};
 let captured;
 const body=new Function("gitBlobMeta","unb64","utf8Text","store","GF_FORMATTER_RECEIPT_BODY_EXPECTED",
   'const GF_SLOT="private-fake";\n'+def(d.after,"gfNeed")+
   '\nreturn function(v){const s={},a={tool:"binary_read",id:"synthetic-operation"},pin={fixture:true};'+
   close.slice(start,end)+'\nreturn s.formatterReceiptBody;};')
   (P.gitBlobMeta,P.unb64,P.utf8Text,(k,v)=>{captured={k,v};},fixtureExpected);
 const ok=body(old);ck("historical_whole_exact_branch_accepts",ok.body.sha256===old.chunk_sha256&&ok.body.bytes===old.size&&captured.v.length>0&&ok.semanticQualification===false);
 const bad=[
  ["chunk_bad_version",v=>v.version+="0"],["chunk_bad_path",v=>v.path+="/bad"],
  ["chunk_bad_extent",v=>v.next_offset--],["chunk_missing_EOF",v=>v.eof=false],
  ["chunk_wrong_hash",v=>v.chunk_sha256="0".repeat(64)],
  ["chunk_corrupt_bytes",v=>v.data_base64="AAAA"],
  ["chunk_wrong_size",v=>v.size++]
 ];
 for(const[name,mutate]of bad){const v=clone(old);mutate(v);refuses(name,()=>body(v));}
 ck("one_native_marker_before_dispatch",d.after.indexOf('s.formatterReceiptBodyStarted=true;')<d.after.indexOf('sdk=await tools.mcp__codex_apps__heptaruntime_mac_controller_operation_start(q)'));
 ck("SDK acceptance differs only by new binary page cap",def(d.before,"gfAcceptArchivedSDK").replace("gfNeed(b.length<=8192 && v.next_offset===q.offset+b.length",'gfNeed(b.length<=(a.tool==="binary_read" ? GF_FORMATTER_RECEIPT_BODY_PAGE_BYTES : 8192)\n     && v.next_offset===q.offset+b.length')===def(d.after,"gfAcceptArchivedSDK"));
 ck("current_exact22202",q.operation.arguments.offset===0&&q.operation.arguments.limit===22202&&q.operation.arguments.expected_version===d.binding.version&&d.binding.bytes===22202);

 reset();const smallGo={...g,immutable_page_bytes:8192},smallRaw=JSON.stringify(smallGo);
 refuses("old 8192 permission is not implicit new16K approval",()=>api.authorize({goRaw:smallRaw,goPin:P.gitBlobMeta(smallRaw),goWholeReadback:true}));
 reset();api.authorize(auth);current.activeObserver={id:"fixture-original-op",tool:"binary_read",futureClosed:true,nextPageOffset:0,eof:false};
 const page={operation_id:"fixture-original-op",offset:0,limit:16384};
 api.validate(current,"operation_result",page,JSON.stringify(page));ck("new binary next16K page accepted",true);
 for(const [label,limit]of [["old size not the frozen new page",8192],["page above new cap",32768]]){
  refuses(label,()=>api.validate(current,"operation_result",{...page,limit},JSON.stringify({...page,limit})));
 }
 for(const tool of ["file_info","process_status","process_read"]){
  current.activeObserver.tool=tool;const oldPage={...page,limit:8192};
  api.validate(current,"operation_result",oldPage,JSON.stringify(oldPage));ck("prior "+tool+" remains8192",true);
  refuses("prior "+tool+" not silently16K",()=>api.validate(current,"operation_result",page,JSON.stringify(page)));
 }
 return{schema:"heptabao.native-jwt.formatter-receipt-body.selected-checks.v1",checks,passed:checks.length,
  RuntimeCalls:0,GitMutations:0,actualStateMutated:false,fullCandidateModuleExecuted:false,
  bodyPositiveFixture:"Previously archived original e3af stage report binary response; formatter receipt body remains unread.",
  currentBodyObserved:false};
}