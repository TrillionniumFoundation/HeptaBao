function verifyCompilerLogsOriginalChain(files) {
 const checks=[];const check=(name,ok)=>{checks.push({name,pass:!!ok});if(!ok)throw Error(name);};
 const parse=(p)=>parseLosslessIntegers(files[p]);
 const nativeFromSDK=(s)=>{check("SDK_not_error_"+checks.length,s.isError!==true);const ts=s.content.filter(x=>x.type==="text").map(x=>x.text);check("one_native_text_"+checks.length,ts.length===1);return parseLosslessIntegers(ts[0]);};
 const eq=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
 const idx=parse("CALL-INDEX.public.json"),state=parse("STATE.public.json");
 check("ten_original_calls",idx.calls.length===10);
 check("three_returned_observers",idx.observers.length===3);
 check("all_closed_context",state.pending===null&&state.activeObserver===null&&state.nativeCallInFlight===false&&state.paused===false);
 for(const c of idx.calls){
  const p="call-"+String(c.ordinal).padStart(2,"0");
  for(const [s,pin] of [["request.json",c.request],["sdk.original.json",c.sdk],["native.original.json",c.native]]){
   const m=gitBlobMeta(files[p+"-"+s]);check(p+"_"+s+"_whole",m.blob===pin.blob&&m.bytes===pin.bytes&&m.sha256===pin.sha256);
  }
  check(p+"_accepted_once",c.called===true&&c.phase==="accepted");
  check(p+"_native_from_original_sdk",eq(nativeFromSDK(parse(p+"-sdk.original.json")),parse(p+"-native.original.json")));
 }
 for(let i=0;i<idx.observers.length;i++){
  const o=idx.observers[i],cs=idx.calls.filter(c=>parse("call-"+String(c.ordinal).padStart(2,"0")+"-native.original.json").operation_id===o.id);
  const kind=c=>c.kind,one=(k)=>cs.filter(c=>kind(c)===k);
  check("observer_"+i+"_one_admission_status",one("operation_start").length===1&&one("operation_status").length===1);
  const st=parse("call-"+String(one("operation_status")[0].ordinal).padStart(2,"0")+"-native.original.json");
  check("observer_"+i+"_stored_inactive",st.async_state==="completed"&&st.result_state==="stored_observed"&&st.owned_future_active===false&&st.payload_available===true);
  const pages=one("operation_result");check("observer_"+i+"_page_count",pages.length===o.pages);
  let offset=0,chunks=[];
  for(const p of pages){
   const prefix="call-"+String(p.ordinal).padStart(2,"0"),req=parse(prefix+"-request.json"),v=parse(prefix+"-native.original.json"),b=unb64(v.data_base64);
   check(prefix+"_same_id_range",req.operation_id===o.id&&req.offset===offset&&v.offset===offset&&v.next_offset===offset+b.length&&b.length<=req.limit);
   check(prefix+"_immutable_payload_identity",v.immutable_snapshot===true&&v.result_sha256===o.payload.sha256&&v.total_bytes===o.payload.bytes);
   offset=v.next_offset;chunks.push(b);check(prefix+"_exact_eof",v.eof===(offset===o.payload.bytes));
  }
  const all=new Uint8Array(offset);let at=0;for(const b of chunks){all.set(b,at);at+=b.length;}
  const payload=utf8Text(all),stored=files["observer-"+i+"-payload.original.json"];
  check("observer_"+i+"_reconstructed_whole",payload===stored&&gitBlobMeta(stored).blob===o.payload.blob&&gitBlobMeta(stored).sha256===o.payload.sha256);
  check("observer_"+i+"_native_from_payload",eq(nativeFromSDK(parseLosslessIntegers(stored)),parse("observer-"+i+"-native.original.json")));
 }
 const body=parse("observer-2-native.original.json"),info=parse("observer-0-native.original.json"),req=parse("call-06-request.json").operation;
 const stderr=files["compiler.stderr.original.txt"],m=gitBlobMeta(stderr);
 check("body_exact_pinned_original",req.tool==="binary_read"&&req.arguments.offset===0&&req.arguments.limit===14696&&req.arguments.path===body.path&&req.arguments.expected_version===body.version);
 check("body_matches_info",body.path===info.path&&body.version===info.version&&body.size===info.size&&body.chunk_sha256===info.sha256);
 check("body_complete_actual_bytes",body.offset===0&&body.next_offset===14696&&body.eof===true&&utf8Text(unb64(body.data_base64))===stderr&&m.bytes===14696&&m.sha256===body.chunk_sha256);
 check("no_stdout_body_or_process",idx.calls.filter(c=>c.kind==="operation_start").map(c=>parse("call-"+String(c.ordinal).padStart(2,"0")+"-request.json").operation.tool).join(",")==="file_info,file_info,binary_read");
 check("two_compiler_E0061",stderr.split("error[E0061]:").length-1===2);
 check("PKI_diagnostic",stderr.includes("crates/heptabao-server/src/service_native_pki.rs:270:17"));
 check("SSH_diagnostic",stderr.includes("crates/heptabao-server/src/service_native_ssh.rs:326:17"));
 return {schema:"heptabao.native-jwt-pki.compiler-logs.original-chain-checks.v1",pass:true,checks,total:checks.length,scope:"pure original evidence; zero Native, no Rust compile or product tests",calls:10,observers:3,pages:4};
}
