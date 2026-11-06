function verifyFormatted23Source(input) {
 const checks=[];
 const check=(name,ok)=>{checks.push({name,passed:!!ok});if(!ok)throw Error(name);};
 const reject=(name,fn)=>{let refused=false;try{fn();}catch(e){refused=true;}check(name,refused);};
 const select=eval(input.candidate+"\n;({rows:GF_OUTPUTS,next:gfNextFixedRequest,validate:gfValidateRequest,info:gfVerifyOutputInfo,chunk:gfVerifyOutputChunk,whole:gfVerifyWholeOutput})");
 const rows=select.rows,report=parseLosslessIntegers(input.report),go=JSON.parse(input.formatterGo);
 check("strict_forward_whole",snapshotApply(input.before,input.forward)===input.candidate);
 check("strict_reverse_whole",snapshotApply(input.candidate,input.reverse)===input.before);
 check("selected_twenty_three",rows.length===23);
 check("fixed_thirty_six_ranges",rows.reduce((n,x)=>n+x.ranges.length,0)===36);
 check("fixed_body_total",rows.reduce((n,x)=>n+x.bytes,0)===1346637);
 const changed=report.files.filter(x=>x.beforeBytes!==x.afterBytes||x.beforeSha256!==x.afterSha256);
 const unchanged=report.files.filter(x=>x.beforeBytes===x.afterBytes&&x.beforeSha256===x.afterSha256);
 check("actual_changed_set_exact",JSON.stringify(rows.map(x=>[x.name,x.bytes,x.sha256]))===
   JSON.stringify(changed.map(x=>[x.name,x.afterBytes,x.afterSha256])));
 check("unchanged26_whole_reference_count_and_bytes",unchanged.length===26&&unchanged.reduce((n,x)=>n+x.afterBytes,0)===686814);
 check("actual_formatter_output_path_expression",input.formatterSource.includes("write_new(ROOT/'formatted'/name,out)"));
 const keys=[];
 for(const row of rows) {
  const inputPin=go.input_files.find(x=>x.name===row.name);
  check("output"+row.index+"_canonical_source_pin",inputPin.path===row.canonicalPath &&
    inputPin.blob===row.source.blob&&inputPin.bytes===row.source.bytes&&inputPin.sha256===row.source.sha256);
  check("output"+row.index+"_fixed_actual_path",row.path===go.new_create_only_root+"/formatted/"+row.name);
  const iq=JSON.parse(row.infoRaw);
  check("output"+row.index+"_exact_info_request",gitBlobMeta(row.infoRaw).blob===row.info.blob&&
   iq.operation.tool==="file_info"&&iq.operation.arguments.host==="rog"&&iq.operation.arguments.path===row.path);
  keys.push(iq.idempotency_key);
  let next=0;
  for(const range of row.ranges) {
   const q=JSON.parse(range.templateRaw),a=q.operation.arguments;keys.push(q.idempotency_key);
   check("output"+row.index+"_range"+range.index+"_fixed_template",
    gitBlobMeta(range.templateRaw).blob===range.template.blob&&q.operation.tool==="binary_read"
    &&a.host==="rog"&&a.path===row.path&&a.offset===next&&a.offset===range.offset
    &&a.limit===range.limit&&range.limit>0&&range.limit<=65536&&a.expected_version===null);
   next+=range.limit;
  }
  check("output"+row.index+"_range_coverage",next===row.bytes);
 }
 check("all59_unique_bounded_keys",keys.length===59&&new Set(keys).size===59&&keys.every(x=>x.length<=128));
 for(const f of unchanged) {
  const x=go.input_files.find(x=>x.name===f.name);
  check("reuse_"+f.name,x.bytes===f.afterBytes&&x.sha256===f.afterSha256);
 }
 const fresh=()=>({paused:false,nativeCallInFlight:false,pending:null,activeObserver:null,
   admissionsCalled:0,outputFiles:[],outputInfos:Array(23).fill(null),
   outputRanges:rows.map(()=>[]),infoStarted:Array(23).fill(false),bodyStarted:rows.map(x=>x.ranges.map(()=>false))});
 let s=fresh(),n=select.next(s);
 check("first_info_selects_exact",n.raw===rows[0].infoRaw&&n.tool==="file_info");
 select.validate(s,"operation_start",JSON.parse(n.raw),n.raw);
 check("first_info_validator_accepts",true);
 const changedKey=JSON.parse(n.raw);changedKey.idempotency_key+="x";
 reject("rekey_refused",()=>select.validate(s,"operation_start",changedKey,JSON.stringify(changedKey,null,2)+"\n"));
 reject("process_start_refused",()=>select.validate(s,"process_start",{},n.raw));
 const premature=JSON.parse(rows[0].ranges[0].templateRaw);premature.operation.arguments.expected_version="1:2:3:4:5";
 reject("body_without_actual_metadata_refused",()=>select.validate(s,"operation_start",premature,JSON.stringify(premature,null,2)+"\n"));
 s.infoStarted[0]=true;reject("same_info_second_call_refused",()=>select.next(s));
 s=fresh();const row=rows[0],version="66306:9007199254740993:"+row.bytes+":1793956739343592677:1793956739343592679";
 const metadata={path:row.path,size:row.bytes,sha256:row.sha256,mode:384,version,
   metadata:{metadata_platform:"linux",mode:384,uid:1000,gid:1000,link_count:1}};
 const info=select.info(row,metadata,"0".repeat(64));
 check("large_inode_and_ns_lossless",info.full9Strings[1]==="9007199254740993"&&
   info.full9Strings[7]==="1793956739343592677"&&info.full9Strings[4]==="33152");
 check("no_source_identity_substitution",info.firstOutputIdentityObservation&&info.originalSourceInputIdentityReused===false);
 for(const [name,change] of [
  ["metadata_path",v=>v.path+="/other"],["metadata_size",v=>v.size++],
  ["metadata_sha",v=>v.sha256="0".repeat(64)],["metadata_mode",v=>v.mode=256],
  ["metadata_uid",v=>v.metadata.uid=0],["metadata_nlink",v=>v.metadata.link_count=2],
  ["metadata_version_size",v=>v.version="1:2:0:4:5"]]) {
  const v=JSON.parse(JSON.stringify(metadata));change(v);reject(name+"_drift_refused",()=>select.info(row,v,"0".repeat(64)));
 }
 s.outputInfos[0]=info;s.infoStarted[0]=true;
 n=select.next(s);const q=JSON.parse(n.raw);
 check("body_version_only_actual_derivation",q.operation.arguments.expected_version===version&&q.operation.arguments.offset===0&&q.operation.arguments.limit===65536);
 select.validate(s,"operation_start",q,n.raw);check("bound_first_body_accepts",true);
 s.bodyStarted[0][0]=true;reject("duplicate_body_refused",()=>select.next(s));
 s=fresh();s.paused=true;reject("paused_refuses_new_admission",()=>select.validate(s,"operation_start",JSON.parse(rows[0].infoRaw),rows[0].infoRaw));
 s=fresh();s.activeObserver={id:"a".repeat(64),futureClosed:false,statusCalled:8};
 reject("ninth_status_refused",()=>select.validate(s,"operation_status",{operation_id:s.activeObserver.id},""));
 s.activeObserver={id:"a".repeat(64),tool:"binary_read",futureClosed:true,statusCalled:1,pageCalled:0,nextPageOffset:16384,eof:false};
 select.validate(s,"operation_result",{operation_id:s.activeObserver.id,offset:16384,limit:16384},"");check("body16K_next_page_accepts",true);
 reject("old_page_or_wrong_width_refused",()=>select.validate(s,"operation_result",{operation_id:s.activeObserver.id,offset:0,limit:8192},""));
 s.activeObserver.tool="file_info";
 select.validate(s,"operation_result",{operation_id:s.activeObserver.id,offset:16384,limit:8192},"");check("metadata8K_preserved",true);
 reject("metadata16K_refused",()=>select.validate(s,"operation_result",{operation_id:s.activeObserver.id,offset:16384,limit:16384},""));
 const content="x".repeat(65535)+"é"+"終"+"z",data=utf8Bytes(content),wholePin=gitBlobMeta(content);
 const synthetic={index:0,path:"/synthetic/public.rs",bytes:data.length,sha256:wholePin.sha256,
  ranges:[{offset:0,limit:65536},{offset:65536,limit:data.length-65536}]};
 const si={version:"1:2:"+data.length+":9007199254740995:9007199254740997"};
 const observed=[];
 for(let i=0;i<2;i++) {
  const r=synthetic.ranges[i],b=data.slice(r.offset,r.offset+r.limit),h=sha256Latin1(byteString(b));
  const rq={operation:{tool:"binary_read",arguments:{host:"rog",path:synthetic.path,offset:r.offset,limit:r.limit,expected_version:si.version}}};
  const v={path:synthetic.path,version:si.version,size:data.length,offset:r.offset,next_offset:r.offset+r.limit,eof:i===1,data_base64:encodeBase64Bytes(b),chunk_sha256:h};
  observed.push(select.chunk(synthetic,si,observed,rq,v,String(i).repeat(64),{blob:"b".repeat(40),bytes:1,sha256:"c".repeat(64)}));
 }
 reject("first_UTF8_split_is_not_individually_decodable",()=>utf8Text(unb64(observed[0].base64)));
 check("cross_range_UTF8_whole_exact",select.whole(synthetic,observed).raw===content);
 reject("whole_truncation_refused",()=>select.whole(synthetic,observed.slice(0,1)));
 reject("whole_SHA_mismatch_refused",()=>select.whole({...synthetic,sha256:"0".repeat(64)},observed));
 const corrupted=JSON.parse(JSON.stringify(observed));corrupted[1].base64=encodeBase64Bytes(Array(synthetic.ranges[1].limit).fill(0));
 reject("retained_chunk_drift_refused",()=>select.whole(synthetic,corrupted));
 check("only_three_Native_methods",JSON.stringify([...new Set(input.candidate.match(/tools\.mcp__codex_apps__heptaruntime_mac_controller_\w+/g)||[])].sort())===
  JSON.stringify(["operation_result","operation_start","operation_status"].map(x=>"tools.mcp__codex_apps__heptaruntime_mac_controller_"+x).sort()));
 check("no_original_context_reset_or_reference",!input.candidate.includes('store("snapshot_2379_rog_formatter_gitfirst_r1"')&&
  !input.candidate.includes('store("snapshot_2379_formatter_body0_admission_reconcile_r1"')&&
  !input.candidate.includes('store("snapshot_2379_formatter_body1_completion_r1"'));
 check("SDK_whole_precedes_parse",input.candidate.indexOf('c.phase="sdk_whole_uninterpreted"')<input.candidate.indexOf("const sdk=JSON.parse(raw)"));
 check("precall_validation_precedes_called_marker",input.candidate.indexOf('gfNeed(fixedNext.raw===c.requestRaw')<input.candidate.indexOf('c.called=true;c.phase="native_call_entered"'));
 check("full_output_external_before_next_file",input.candidate.indexOf('fileArchive=await archiveFlatPublicTextsOnce')<input.candidate.indexOf("s.outputFiles.push(wholeFile)"));
 check("original_format_budgets_retained",report.internalSeconds===50&&report.newRemoteSupervisorSeconds===60&&report.children.every(x=>x.timeoutSeconds===10));
 return {schema:"heptabao.snapshot-formatted23-source-checks.v1",passed:true,checks:checks.length,
  rows:checks,NativeCalls:0,candidateInitializeOrDispatchCalls:0,
  scope:"strict source/data and selected pure request/metadata/byte guards; no host/IO/tool invocation"};
}
