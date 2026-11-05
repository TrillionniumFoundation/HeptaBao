function verifyMacSixPrerequisites(r,original,rootReview,h){
 const {parse,utf8,bs,sha,unb64}=h,checks=[],rows=[];
 function ck(n,v){if(!v)throw Error(n);checks.push(n);}
 function sort(v){if(Array.isArray(v))return v.map(sort);if(v&&typeof v==="object")return Object.fromEntries(Object.keys(v).sort().map(k=>[k,sort(v[k])]));return v;}
 const eq=(x,y)=>JSON.stringify(sort(x))===JSON.stringify(sort(y)),hash=t=>sha(bs(utf8(t))),is=v=>v&&typeof v==="object"?v.$exactInteger:String(v);
 function sdk(path){const s=parse(r[path]);ck(path+"_success",s.isError===false);const t=s.content.filter(x=>x.type==="text");ck(path+"_one_text",t.length===1);return {text:t[0].text,v:parse(t[0].text)};}
 const author=parse(r["review/six-verification.public.json"]);
 ck("unmodified_wrapper",r["reference/unmodified-wrapper.py"]===original["candidate/run_current_mac_full34_r1.py"]);
 ck("unbound_and_original_nlink_guard_retained",r["reference/unmodified-wrapper.py"].includes("BINDING_READY=False")&&r["reference/unmodified-wrapper.py"].includes("m['identity'][5]==1"));
 for(const expected of rootReview.requests){
  const role=expected.name,b="reads/"+role,q=parse(r["requests/"+role+".public.json"]),intent=parse(r[b+"/intent.public.json"]);
  ck(role+"_frozen_request_bytes",r["requests/"+role+".public.json"]===original["requests/readonly-"+role+".public.json"]);
  ck(role+"_frozen_intent",intent.original_request.blob===expected.blob&&eq(intent.exact_request,q));
  ck(role+"_typed_fixed_path",q.idempotency_key===expected.key&&q.operation.tool==="file_info"&&q.operation.arguments.host==="mac"&&q.operation.arguments.path===expected.path);
  const ack=sdk(b+"/admission.original.sdk.json"),st=sdk(b+"/status.original.sdk.json"),p=sdk(b+"/page-00000.original.sdk.json");
  ck(role+"_original_natives_exact",ack.text===r[b+"/admission.original.json"]&&st.text===r[b+"/status.original.json"]&&p.text===r[b+"/page-00000.original.json"]);
  ck(role+"_original_operation_closed",ack.v.operation_id===st.v.operation_id&&p.v.operation_id===ack.v.operation_id&&ack.v.tool_name==="file_info"&&ack.v.reused===false&&st.v.async_state==="completed"&&st.v.result_state==="stored_observed"&&st.v.owned_future_active===false&&st.v.payload_available===true);
  const pq=parse(r[b+"/page-00000.intent.public.json"]).exact_request,sq=parse(r[b+"/status.intent.public.json"]);
  ck(role+"_original_observers",pq.operation_id===ack.v.operation_id&&sq.operation_id===ack.v.operation_id&&pq.offset===0&&pq.limit===16384);
  const bytes=unb64(p.v.data_base64),payload=bs(bytes);
  ck(role+"_whole_single_immutable_page",p.v.offset===0&&p.v.next_offset===p.v.total_bytes&&p.v.total_bytes===bytes.length&&bytes.length<=pq.limit&&p.v.eof===true&&p.v.immutable_snapshot===true&&p.v.payload_kind==="native_result"&&p.v.format==="serialized_original_native_sdk_payload_before_operation_metadata_and_transport_normalization"&&sha(payload)===p.v.result_sha256&&payload===r[b+"/payload.original.sdk.json"]);
  const nativeSdk=sdk(b+"/payload.original.sdk.json"),n=nativeSdk.v;
  ck(role+"_native_info_original_text",nativeSdk.text===r[b+"/file-info.original.json"]);
  ck(role+"_expected_path_and_size",n.path===expected.path&&Number.isSafeInteger(n.size)&&n.size>0&&n.size<=512*1024*1024&&(expected.expected_bytes===null||n.size===expected.expected_bytes));
  ck(role+"_expected_hash",/^[0-9a-f]{64}$/.test(n.sha256)&&(expected.expected_sha256===null||n.sha256===expected.expected_sha256));
  ck(role+"_version_decimal_shape",/^[0-9]+:[0-9]+:[0-9]+:[0-9]+:[0-9]+$/.test(n.version)&&n.version.split(":")[2]===String(n.size));
  ck(role+"_posix_metadata",n.metadata.metadata_platform==="darwin"&&n.mode===n.metadata.mode&&Number.isSafeInteger(n.mode)&&n.mode>=0&&n.mode<=4095&&[n.metadata.uid,n.metadata.gid,n.metadata.link_count].every(x=>Number.isSafeInteger(x)&&x>=0));
  const t=n.version.split(":"),full9=[t[0],t[1],String(n.metadata.uid),String(n.metadata.gid),String(32768|n.mode),String(n.metadata.link_count),t[2],t[3],t[4]],projection=author.observed_full9_projection[role];
  ck(role+"_lossless_author_full9",eq(projection.identity.map(is),full9)&&projection.version===n.version&&projection.bytes===n.size&&projection.sha256===n.sha256&&projection.path===n.path);
  ck(role+"_explicit_link_admission",n.metadata.link_count===(role==="git"?78:1));
  rows.push({role,operation_id:ack.v.operation_id,payload_bytes:bytes.length,payload_sha256:p.v.result_sha256,path:n.path,bytes:n.size,sha256:n.sha256,version:n.version,full9_decimal_strings:full9,original_single_link_guard_satisfied:n.metadata.link_count===1});
 }
 ck("six_unique_operations",new Set(rows.map(x=>x.operation_id)).size===6);
 const g=rows.find(x=>x.role==="git");
 ck("exact_git_multi_link_observation",g.full9_decimal_strings[1]==="1152921500312571562"&&g.full9_decimal_strings[2]==="0"&&g.full9_decimal_strings[3]==="0"&&g.full9_decimal_strings[4]==="33261"&&g.full9_decimal_strings[5]==="78"&&g.bytes===118640&&g.sha256==="b8763cf250e607a778bb4603cecb5b90338814d0a3dfcba0d57b1de242f610e9");
 ck("known_refusal_preserved",parse(r["reads/git/binding-refusal.public.json"]).current_wrapper_admission_satisfied===false);
 ck("original_regex_error_and_narrow_correction_preserved",typeof r["review/initial-close-page-helper.js"]==="string"&&typeof r["review/corrected-close-page-helper.js"]==="string"&&typeof r["review/local-close-page-helper-correction.public.json"]==="string");
 return {schema:"heptabao.mac-full34-six-prerequisite-original-observations-root-review.r1",status:"SIX_READS_COMPLETE_FIVE_SINGLE_LINK_GIT78_REQUIRES_SPECIFIC_SOURCE_ADMISSION",packet:"7335151a16006015891c4fe62655d7907f8fedc1",source_packet:"bdb1dd296ac147ddcd355655814df099e59c571d",checks_passed:checks.length,checks,observations:rows,actual_runtime_product_calls:0,transport_errors:0,unsafe_integer_tokens_preserved:true,source_wrapper_unchanged:true,binding_ready:false,inert_go:false,prepare_go:false,live_go:false,git_specific_source_proposal_permitted:true,generic_guard_change_permitted:false,shim_or_alias_inventory_claimed:false,full_replacement_qualified:false};
}
