function verifyLanReceipt(r, originalCore, helpers) {
 const {utf8,bs,sha,unb64,lossless}=helpers,checks=[];function ck(n,v){if(!v)throw Error(n);checks.push(n);}
 const hash=t=>sha(bs(utf8(t)));function sdk(t){const s=JSON.parse(t);ck("sdk_success_"+checks.length,s.isError===false);const a=s.content.filter(x=>x.type==="text");ck("sdk_native_"+checks.length,a.length===1);return{text:a[0].text,v:JSON.parse(a[0].text)};}
 function chain(base,offsets,tool,nativePath,payloadPath){const req=JSON.parse(r["sdk/"+base+"_start/request.json"]),a=sdk(r["sdk/"+base+"_start/original-sdk.json"]).v,st=sdk(r["sdk/"+base+"_status0/original-sdk.json"]).v;
 ck(base+"_tool_host",req.operation.tool===tool&&req.operation.arguments.host==="desktop");ck(base+"_closed",st.operation_id===a.operation_id&&st.async_state==="completed"&&st.owned_future_active===false&&st.payload_available===true);
 let raw="",cursor=0,total=null,digest=null;
 for(const offset of offsets){const key="sdk/"+base+"_result"+offset,q=JSON.parse(r[key+"/request.json"]),p=sdk(r[key+"/original-sdk.json"]).v,b=unb64(p.data_base64);if(total===null){total=p.total_bytes;digest=p.result_sha256;}
 ck(key+"_identity",q.operation_id===a.operation_id&&p.operation_id===a.operation_id&&q.offset===offset&&p.offset===offset&&cursor===offset);ck(key+"_binding",p.total_bytes===total&&p.result_sha256===digest&&p.immutable_snapshot===true);ck(key+"_bounds",p.next_offset===cursor+b.length&&b.length<=q.limit);raw+=bs(b);cursor+=b.length;ck(key+"_eof",p.eof===(cursor===total));}
 ck(base+"_payload",raw===r[payloadPath]&&utf8(raw).length===total&&hash(raw)===digest);const n=sdk(raw);ck(base+"_native",n.text===r[nativePath]);return{req,n:n.v};
 }
 const i=chain("receipt_info",[0],"file_info","receipt-info.native.json","native/receipt-info.payload.json"),b=chain("receipt_body",[0,8192],"binary_read","receipt-binary.native.json","native/receipt-body.payload.json");
 const body=bs(unb64(b.n.data_base64)),info=i.n;
 ck("fixed_receipt_path",i.req.operation.arguments.path===info.path&&b.req.operation.arguments.path===info.path&&b.n.path===info.path);
 ck("version_bound",b.req.operation.arguments.expected_version===info.version&&b.n.version===info.version&&info.version==="2050:7360981:7519:1793888506753279333:1793888506807390690");
 ck("whole7519",info.size===7519&&b.n.size===7519&&b.n.offset===0&&b.n.next_offset===7519&&b.n.eof===true&&utf8(body).length===7519);
 ck("body_exact",body===r["receipt.public.json"]);
 ck("whole_sha",hash(body)===info.sha256&&hash(body)===b.n.chunk_sha256&&info.sha256==="62e31bfb647267d245f063da95d1269c502abf88818d3c01e309ff517e563288");
 ck("metadata",info.mode===384&&info.metadata.mode===384&&info.metadata.uid===1000&&info.metadata.gid===1000&&info.metadata.link_count===1);
 function canon(v){if(Array.isArray(v))return v.map(canon);if(v&&typeof v==="object")return Object.fromEntries(Object.keys(v).sort().map(k=>[k,canon(v[k])]));return v;}
 ck("lossless_receipt_equals_original_stdout",JSON.stringify(canon(lossless(body)))===JSON.stringify(canon(originalCore)));
 return{schema:"heptabao.original-lan-receipt-root-review.r1",status:"INDEPENDENT_ORIGINAL_RECEIPT_CLOSED",packet:"e99062f02573e0300c1a8c64495411e86eb15667",checks_passed:checks.length,checks,receipt:{path:info.path,bytes:info.size,sha256:info.sha256,version:info.version},exact_int64_tokens_preserved:true,independent_nine_source_body_readbacks_complete:false,original_job_replayed:false,prepare_go:false,LAN_live_go:false,full_replacement_qualified:false};
}
