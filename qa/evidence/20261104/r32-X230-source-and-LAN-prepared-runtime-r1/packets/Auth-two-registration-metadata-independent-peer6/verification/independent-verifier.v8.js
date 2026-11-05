function verify(inputs, utf8, sha1, sha256, decode64) {
"use strict";
const files=inputs.files, tr=inputs.tree, checks=[];
const check=(name,ok,detail)=>{checks.push({name,passed:!!ok,...(detail===undefined?{}:{detail})});if(!ok)throw Error("check failed: "+name);};
const obj=p=>JSON.parse(files[p]);
const pin=p=>{const b=utf8(files[p]);return {blob:sha1("blob "+b.length+"\0"+b),bytes:b.length,sha256:sha256(b)};};
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const pinEq=(a,b)=>a.blob===b.blob&&a.bytes===b.bytes&&a.sha256===b.sha256;
const sdkNative=(base)=>{
 const sdk=obj(base+"/original.sdk.json");
 check(base+".SDK noerror",sdk.isError===false);
 check(base+".SDK one text",Array.isArray(sdk.content)&&sdk.content.length===1&&sdk.content[0].type==="text");
 check(base+".SDK exact native",sdk.content[0].text===files[base+"/original.native.txt"]);
 return JSON.parse(sdk.content[0].text);
};
check("fixed tree",tr.sha==="27c4b1be1736069cf4b9fdc6a1bf44acb819624f"&&tr.truncated===false);
const leafs=tr.tree.filter(e=>e.type==="blob"), dirs=tr.tree.filter(e=>e.type==="tree");
check("36 whole leaves",leafs.length===36&&Object.keys(files).length===36);
for(const e of leafs){const got=pin(e.path);check("whole "+e.path,e.mode==="100644"&&got.blob===e.sha&&got.bytes===e.size);}
const dirSet=new Set(["",...dirs.map(e=>e.path)]), mh=new Map();
for(const d of [...dirSet].sort((a,b)=>b.split("/").length-a.split("/").length||b.length-a.length)){
 const prefix=d?d+"/":"", entries=[];
 for(const e of tr.tree){if(!e.path.startsWith(prefix))continue;const name=e.path.slice(prefix.length);if(name.includes("/"))continue;entries.push({name,mode:e.type==="tree"?"40000":"100644",sha:e.type==="tree"?mh.get(e.path):e.sha,isTree:e.type==="tree"});}
 entries.sort((a,b)=>{const x=a.name+(a.isTree?"/":""),y=b.name+(b.isTree?"/":"");return x<y?-1:x>y?1:0;});
 const raw=entries.map(e=>utf8(e.mode+" "+e.name+"\0")+e.sha.match(/../g).map(h=>String.fromCharCode(parseInt(h,16))).join("")).join("");
 const actual=sha1("tree "+raw.length+"\0"+raw);mh.set(d,actual);
 check("Merkle "+(d||"/"),actual===(d?tr.tree.find(e=>e.path===d).sha:tr.sha));
}
const manifest=obj("manifest.public.json");
check("manifest 35 original members",manifest.files.length===35);
for(const m of manifest.files)check("manifest "+m.path,pinEq(m,pin(m.path)));
const go=obj("reference/root-GO.public.json"), summary=obj("SUMMARY.public.json"), release=obj("RELEASE.public.json");
check("exact metadata GO",pin("reference/root-GO.public.json").blob==="a99b9f7d507d357195cbdfc2ee76cf418ce04db1"&&go.requests.length===2&&go.metadata_only===true&&go.body_requests_authorized===0&&go.maximum_new_file_info_operations===2);
check("handoff pin",pinEq(go.handoff,pin("reference/lane-handoff.public.json")));
const records=[];
for(let i=1;i<=2;i++){
 const tag=String(i).padStart(2,"0"), base="observations/"+tag;
 const requestPath=base+"/intent/exact-request.public.json",request=obj(requestPath),intent=obj(base+"/intent/intent.public.json"), bound=obj(base+"/actual-binding.public.json"), s=summary.observed[i-1];
 check(tag+".request matches GO",same(request,go.requests[i-1].value)&&pinEq(go.requests[i-1].exact_request,pin(requestPath)));
 check(tag+".intent request",same(intent.exact_request,request)&&pinEq(intent.request,pin(requestPath))&&intent.sequence===i);
 check(tag+".intent GO/handoff",pinEq(intent.root_GO,pin("reference/root-GO.public.json"))&&pinEq(intent.handoff,pin("reference/lane-handoff.public.json")));
 check(tag+".intent limits",intent.submission_count_before===0&&intent.dispatch_once_after_this_external_call_completes===true&&intent.SDK_external_before_isError_and_parse===true&&intent.maximum_Runtime_calls===1&&intent.maximum_native_futures===1&&intent.immutable_page_limit===8192&&intent.body_authorized===0&&intent.SDK_authorized===0);
 check(tag+".previous closure",i===1?intent.previous_original_closed_and_whole===null:pinEq(intent.previous_original_closed_and_whole,pin("observations/01/actual-binding.public.json")));
 check(tag+".request only info",request.operation.tool==="file_info"&&same(Object.keys(request.operation.arguments).sort(),["host","path"])&&request.operation.arguments.host==="mac");
 const ack=sdkNative(base+"/admission"),st=sdkNative(base+"/status-0"),pg=sdkNative(base+"/result-0"),id=ack.operation_id;
 check(tag+".ACK identity",typeof id==="string"&&/^[0-9a-f]{64}$/.test(id)&&ack.tool_name==="file_info"&&ack.async_state==="queued"&&ack.reused===false&&ack.automatic_retry===false&&ack.admission_is_not_dispatch_completion===true);
 check(tag+".status same ID request",same(obj(base+"/status-0/request.json"),{operation_id:id}));
 check(tag+".status completed inactive",st.operation_id===id&&st.tool_name==="file_info"&&st.async_state==="completed"&&st.result_state==="stored_observed"&&st.owned_future_active===false&&st.payload_available===true);
 check(tag+".page request same ID bounded",same(obj(base+"/result-0/request.json"),{operation_id:id,offset:0,limit:8192}));
 check(tag+".immutable page",pg.operation_id===id&&pg.offset===0&&pg.immutable_snapshot===true&&pg.payload_kind==="native_result"&&pg.eof===true&&pg.next_offset===pg.total_bytes&&pg.total_bytes<=8192);
 const raw=decode64(pg.data_base64),payloadPath=base+"/payload.original.json";
 check(tag+".page full original bytes",raw===utf8(files[payloadPath])&&raw.length===pg.total_bytes&&sha256(raw)===pg.result_sha256);
 const payload=obj(payloadPath);
 check(tag+".native payload noerror complete",payload.isError===false&&payload.resultType==="complete"&&Array.isArray(payload.content)&&payload.content.length===1&&payload.content[0].type==="text");
 check(tag+".native byte exact",payload.content[0].text===files[base+"/native.original.json"]);
 const n=obj(base+"/native.original.json"),ver=n.version.split(":");
 check(tag+".native exact path",n.path===request.operation.arguments.path);
 check(tag+".metadata kind and permissions",n.mode===420&&n.metadata.mode===420&&n.metadata.metadata_platform==="darwin"&&n.metadata.uid===501&&n.metadata.gid===80&&n.metadata.link_count===1);
 check(tag+".version integers lossless",ver.length===5&&ver.every(v=>/^[0-9]+$/.test(v))&&ver[2]===String(n.size));
 check(tag+".whole SHA shape",/^[0-9a-f]{64}$/.test(n.sha256)&&Number.isSafeInteger(n.size)&&n.size>0);
 const full9=[ver[0],ver[1],String(n.metadata.uid),String(n.metadata.gid),String(32768|n.mode),String(n.metadata.link_count),ver[2],ver[3],ver[4]];
 check(tag+".bound raw full9",same(bound.observed,{...n,full9_decimal:full9})&&same(s.info,n)&&same(s.full9_decimal,full9));
 check(tag+".bound request status and content pins",pinEq(bound.request,pin(requestPath))&&bound.ACK_SDK===pin(base+"/admission/original.sdk.json").blob&&pinEq(bound.status,pin(base+"/status-0/original.native.txt"))&&bound.page_SDK===pin(base+"/result-0/original.sdk.json").blob&&pinEq(bound.payload,pin(payloadPath))&&pinEq(bound.native,pin(base+"/native.original.json")));
 check(tag+".bound closure identity",bound.operation_id===id&&bound.completed_stored_inactive===true&&bound.whole_original_payload===true&&bound.new_body_requests_submitted===0&&bound.SDK_execution===0&&bound.actual_selected_owner===null);
 check(tag+".summary pins",pinEq(s.request,pin(requestPath))&&pinEq(s.intent,pin(base+"/intent/intent.public.json"))&&s.ACK_SDK===pin(base+"/admission/original.sdk.json").blob&&s.ACK_native===pin(base+"/admission/original.native.txt").blob&&pinEq(s.status,pin(base+"/status-0/original.native.txt"))&&pinEq(s.native,pin(base+"/native.original.json"))&&pinEq(s.binding,pin(base+"/actual-binding.public.json")));
 check(tag+".summary closed sameID",s.operation_id===id&&s.async_state===st.async_state&&s.result_state===st.result_state&&s.owned_future_active===false&&s.payload_bytes===raw.length&&s.payload_sha256===pg.result_sha256);
 records.push({sequence:i,operation_id:id,path:n.path,bytes:n.size,sha256:n.sha256,version:n.version,full9_decimal:full9,payload_bytes:raw.length,native_pin:pin(base+"/native.original.json"),binding_pin:pin(base+"/actual-binding.public.json")});
}
check("two distinct operations",new Set(records.map(r=>r.operation_id)).size===2);
check("actual sizes",records[0].bytes===31444&&records[1].bytes===181581);
const plan=obj("body-proposal/REQUESTS.public.json");
check("four future proposal requests",plan.requests.length===4&&plan.status==="SOURCE_PROPOSAL_NO_BODY_GO"&&plan.body_operations_submitted===0&&plan.SDK_execution===0&&plan.metadata_operations_completed===2&&plan.original_pages_completed===2&&plan.metadata_native_futures===0);
const offsets=[0,0,65536,131072],limits=[31444,65536,65536,50509], keys=new Set();
for(let i=0;i<4;i++){
 const b=plan.requests[i],r=obj(b.request_path),a=r.operation.arguments,rec=records[i===0?0:1];
 check("body"+(i+1)+".exact original proposal",same(r,b.value)&&pinEq(b.request_pin,pin(b.request_path)));
 check("body"+(i+1)+".only exact binary fields",r.operation.tool==="binary_read"&&same(Object.keys(a).sort(),["expected_version","host","limit","offset","path"])&&a.host==="mac"&&a.path===rec.path&&a.expected_version===rec.version&&a.offset===offsets[i]&&a.limit===limits[i]);
 check("body"+(i+1)+".metadata original pins",pinEq(b.actual_metadata,rec.native_pin)&&pinEq(b.metadata_binding,rec.binding_pin));
 check("body"+(i+1)+".full info equality",same(b.expected_whole,{path:rec.path,bytes:rec.bytes,sha256:rec.sha256,version:rec.version,full9_decimal:rec.full9_decimal}));
 check("body"+(i+1)+".extent EOF and unsubmitted",b.sequence===i+1&&b.submitted===false&&b.expected_next_offset===a.offset+a.limit&&b.expected_next_offset<=rec.bytes&&b.expected_eof===(b.expected_next_offset===rec.bytes));
 check("body"+(i+1)+".key unique fixed hash",typeof r.idempotency_key==="string"&&!keys.has(r.idempotency_key)&&r.idempotency_key.includes(rec.sha256.slice(0,8)));keys.add(r.idempotency_key);
}
check("body limits contiguous unique extents",limits.reduce((a,b)=>a+b,0)===213025&&limits.slice(1).reduce((a,b)=>a+b,0)===records[1].bytes&&offsets[2]===offsets[1]+limits[1]&&offsets[3]===offsets[2]+limits[2]);
check("new accounting not inherited",same(plan.accounting.proposed_new,{files:2,chunks:4,bytes:213025,max_chunk:65536,immutable_result_page_limit:8192})&&same(plan.accounting.previous_completed,{files:6,chunks:7,bytes:140664})&&same(plan.accounting.cumulative_if_separately_authorized_and_completed,{files:8,chunks:11,bytes:353689})&&plan.accounting.old_body_authorization_reused_or_reset===false);
check("hash work distinct from body read",plan.accounting.metadata_hash_work_not_bounded_by_body_limits===true);
check("owner and production unqualified",plan.actual_selected_owner===null&&plan.manifest_filename===null&&plan.production_qualified===false);
check("summary counts and readonly scope",summary.original_operation_count===2&&summary.immutable_page_count===2&&summary.original_payload_bytes===1155&&summary.metadata_requested===2&&summary.metadata_complete===2&&summary.errors===0&&summary.reconciliations===0&&summary.body_operations_submitted===0&&summary.SDK_executed===0&&summary.actual_selected_owner===null);
check("summary proposal exact",pinEq(summary.proposed_body_plan,pin("body-proposal/REQUESTS.public.json"))&&summary.new_body_bytes_proposed===213025&&summary.prior_consumed_body_bytes===140664&&summary.cumulative_if_new_body_separately_approved_and_completed===353689);
check("release exact scope",pinEq(release.summary,pin("SUMMARY.public.json"))&&same(release.original_operation_ids,records.map(r=>r.operation_id))&&release.completed_stored_inactive===true&&release.whole_original_payloads===true&&release.inflight_Runtime_calls===0&&release.unclosed_current_native_futures===0&&release.new_body_requests_submitted===0&&release.new_body_GO_required===true&&release.SDK_execution===0&&release.production_changes===0&&release.actual_selected_owner===null);
return {schema:"heptabao.ha-independent-auth-metadata2-original-chain-peer.v1",status:"PASS_METADATA_ORIGINAL_CHAINS_AND_FUTURE_BODY_BINDINGS_ONLY",source_tree:tr.sha,whole_files:36,whole_bytes:Object.values(files).reduce((n,v)=>n+utf8(v).length,0),merkle_nodes:mh.size,checks_count:checks.length,checks,observations:records,proposed_chunks:limits,proposed_bytes:213025,prior_bytes:140664,cumulative_if_new_authorized:353689,Runtime_calls:0,author_checker_executed:false,public_source_bodies_read_by_this_peer:false,actual_owner_or_SDK_execution_qualified:false,fullmode_derivation:"Regular-file kind from purpose-built file_info contract plus returned permission mode; device/inode/size/mtime/ctime decimal strings from exact version; uid/gid/nlink from native metadata.",limitations:["Confirms immutable raw-chain consistency and closed original observer statuses; does not independently timestamp external call completion order.","Source bodies are not retrieved by this metadata packet; exact body proposals still require separate root authorization.","Known native metadata and whole SHA are historical observations, not a new host stat; no SDK factory/winner inference."]};
}
