function reviewMac47(raw,tree,audit,oldReleaseText){
const u=eval(load("root_utf8_bytes_r1_source")+";utf8Bytes"),bs=eval(load("root_byte_string_r1_source")+";byteString"),h=eval(load("root_sha256_latin1_r1_source")+";sha256Latin1"),unb64=eval(load("root_base64_bytes_source")+";unb64");
const checks=[];function need(ok,name){checks.push({name,pass:!!ok});if(!ok)throw Error(name);}
const j=p=>JSON.parse(raw[p]),sdk=p=>{const v=j(p);need(v.isError===false&&v.content.length===1&&v.content[0].type==="text","SDK success "+p);return JSON.parse(v.content[0].text);};
const idx=j("provenance/47-closed-operation-chunks.public.json"),prov=j("provenance/original-observation-trees.public.json"),manifest=j("manifest.public.json").files,assessment=j("assessment.public.json");
const byPath=new Map(audit.records.map(x=>[x.path,x])),byTreePath=new Map(tree.tree.filter(x=>x.type==="tree").map(x=>[x.path,x.sha]));
need(audit.files===560&&audit.bytes===4030291&&audit.merkle.trees_verified===281,"whole packet 560/4030291/281");
need(manifest.length===559&&new Set(manifest.map(x=>x.path)).size===559,"manifest 559 unique non-self files");
for(const x of manifest){const r=byPath.get(x.path);need(r&&r.bytes===x.bytes&&r.sha256===x.sha256&&r.blob===x.git_blob_sha,"manifest whole "+x.path);}
need(idx.length===47&&prov.length===47&&new Set(idx.map(x=>x.operation_id)).size===47,"47 unique operations");
const files=[{path:"/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261105-same-root-publication-normal-r2/normal-release-tests-r1/normal-release-build.stdout",size:440534,version:"16777244:72626337:440534:1793876825836663089:1793876825836663089",sha256:"8dc68d2435e0c431df2f153d7125ab841427265e987726cfbfa6280dc05dddd6",chunks:27,covered:440534},{path:"/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261105-same-root-publication-normal-r2/normal-release-tests-r1/build.stdout",size:438208,version:"16777244:72626769:438208:1793877277217169751:1793877277217169751",sha256:"9669ba9437855b9d0916367c86140911b83cbab9ac84721d14b463988d37eb95",chunks:20,covered:327680}];
const chunks=[[],[]],keys=new Set();let observationCount=0,pageCount=0,errorCount=0;
for(const x of idx){
const key="f"+x.file+"_o"+x.offset,base="operations/"+key+"/",f=files[x.file],p=prov.find(y=>y.key===key);
need(!!f&&x.path===f.path&&x.version===f.version&&x.file_size===f.size,"fixed file identity "+key);
need(p&&p.operation_id===x.operation_id,"original provenance identity "+key);
for(const o of p.raw_observations){need(o.files===2&&byTreePath.get(base+o.kind)===o.tree,"original observation Merkle "+key+"/"+o.kind);observationCount++;}
const req=j(base+"start/request.json"),ack=sdk(base+"start/original-sdk.json"),args=req.operation.arguments;
need(!keys.has(req.idempotency_key)&&typeof req.idempotency_key==="string","unique original key "+key);keys.add(req.idempotency_key);
need(req.operation.tool==="binary_read"&&args.host==="mac"&&args.path===x.path&&args.expected_version===x.version&&args.offset===x.offset&&args.limit===x.bytes,"typed original request "+key);
need(ack.operation_id===x.operation_id&&ack.reused===false&&ack.tool_name==="binary_read","original ACK "+key);
need(byTreePath.get(base+"start")===x.start_sdk_tree,"indexed ACK tree "+key);
const statusObs=p.raw_observations.find(o=>o.tree===x.closed_status_sdk_tree);
need(statusObs?.kind==="status0","indexed closed status "+key);
need(j(base+"status0/request.json").operation_id===x.operation_id,"same operation status request "+key);
const status=sdk(base+"status0/original-sdk.json");
need(status.operation_id===x.operation_id&&status.async_state==="completed"&&status.result_state==="stored_observed"&&status.owned_future_active===false&&status.payload_available===true&&status.tool_name==="binary_read","closed original read "+key);
let payload=[];for(const pg of x.result_pages){
const obs=p.raw_observations.find(o=>o.tree===pg.external_tree);need(!!obs,"indexed page provenance "+key+"@"+pg.offset);
const rp=base+obs.kind+"/",rq=j(rp+"request.json"),v=sdk(rp+"original-sdk.json"),b=unb64(v.data_base64);
need(rq.operation_id===x.operation_id&&rq.offset===pg.offset&&[8192,16384].includes(rq.limit),"same original operation page request "+key+"@"+pg.offset);
need(v.operation_id===x.operation_id&&v.offset===payload.length&&v.offset===pg.offset&&b.length===pg.bytes&&b.length<=rq.limit&&v.next_offset===v.offset+b.length,"contiguous original payload page "+key+"@"+pg.offset);
need(v.immutable_snapshot===true&&v.payload_kind==="native_result"&&v.total_bytes===x.original_payload_bytes&&v.result_sha256===x.original_payload_sha256&&v.eof===(v.next_offset===v.total_bytes),"immutable page closure "+key+"@"+pg.offset);
payload=payload.concat(b);pageCount++;
}
need(payload.length===x.original_payload_bytes&&h(bs(payload))===x.original_payload_sha256&&bs(payload)===raw[base+"payload.original.json"],"whole original payload "+key);
const result=JSON.parse(bs(payload));need(result.resultType==="complete"&&result.isError===false&&result.content.length===1&&result.content[0].type==="text"&&result.content[0].text===raw[base+"native.original.json"],"original native serialization "+key);
const native=JSON.parse(result.content[0].text),bytes=unb64(native.data_base64);
need(native.path===x.path&&native.version===x.version&&native.size===x.file_size&&native.offset===x.offset&&native.next_offset===x.offset+bytes.length&&native.eof===(native.next_offset===native.size),"binary read original cursor and version "+key);
need(bytes.length===x.bytes&&h(bs(bytes))===x.chunk_sha256&&native.chunk_sha256===x.chunk_sha256,"binary read whole chunk SHA "+key);
chunks[x.file].push({offset:x.offset,bytes});
for(const o of p.raw_observations){const original=j(base+o.kind+"/original-sdk.json");if(original.isError===true){need(key==="f0_o98304"&&o.kind==="result0"&&o.tree==="230c6859865648cf45d421fb2fc76632393232c7"&&original.content[0].text.includes("MCP request timed out"),"preserve original failed page");const er=j(base+o.kind+"/request.json");need(er.operation_id===x.operation_id&&er.offset===0,"failed page stayed on original op");errorCount++;}}
}
need(observationCount===230&&pageCount===135&&errorCount===1,"230 observations /135 successful pages /1 original failed page");
const coverage=[];for(let i=0;i<2;i++){let bytes=[];const ordered=chunks[i].sort((a,b)=>a.offset-b.offset);need(ordered.length===files[i].chunks,"chunk count file"+i);for(const ch of ordered){need(ch.offset===bytes.length,"contiguous file"+i+"@"+ch.offset);bytes=bytes.concat(ch.bytes);}need(bytes.length===files[i].covered,"covered byte count file"+i);if(i===0){need(h(bs(bytes))===files[i].sha256&&bs(bytes)===bs(u(oldReleaseText)),"full release log equals R24 whole original");}coverage.push({file:i,path:files[i].path,version:files[i].version,file_bytes:files[i].size,covered_bytes:bytes.length,chunks:ordered.length,covered_sha256:h(bs(bytes)),complete:bytes.length===files[i].size});}
const plan=assessment.remaining_plan;need(plan.length===7,"seven remaining build chunks");let next=327680;for(const p of plan){need(p.file===1&&p.path===files[1].path&&p.version===files[1].version&&p.offset===next&&p.limit===Math.min(16384,files[1].size-next),"fixed remaining chunk "+next);next+=p.limit;}need(next===438208,"remaining plan reaches exact EOF");
need(assessment.raw_host_calls===0&&assessment.new_binary_reads===0&&assessment.business_replays===0&&assessment.original_two_direct_rpc_unknown_preserved===true&&assessment.product_qualification_relabelled===false,"archive-only scope and historical unknown retained");
return {schema:"heptabao.mac47-original-operations-root-review.r1",status:"PASS_WHOLE_ARCHIVE_AND_ORIGINAL_READ_CHAINS_ONLY",source_tree:tree.sha,whole:{files:audit.files,bytes:audit.bytes,merkle:audit.merkle},checks:checks.length,passed:true,operations:47,original_observations:observationCount,successful_immutable_pages:pageCount,preserved_failed_pages:errorCount,coverage,remaining_plan:plan,historical_direct_rpc_unknowns_preserved:true,new_runtime_requests:0,new_business_requests:0,full_second_cargo_log:false,full_product_qualification:false,limitations:["This verifies immutable reads of public Cargo logs and their original SDK chain, not a new product execution.","Second Cargo log remains incomplete: 327680 of 438208 bytes; seven fixed reads are still unsubmitted.","Two earlier direct binary-read RPC unknowns and one failed immutable page remain historical observations."]};
}