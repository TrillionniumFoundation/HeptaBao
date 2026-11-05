function verifyColdProjectorActual(a,get,parse,u,req,metadata,core){
 const checks=[],ck=(n,v)=>{if(!v)throw Error(n);checks.push(n);},rec=p=>a.records.find(r=>r.path===p),raw=p=>get(rec(p).blob),j=p=>parse(raw(p));
 const auth=j("authority.original.json"),sdk=j("sdk/authority.envelope.json"),ack=j("submission/ack.original.json");
 ck("authority exact original SDK",!sdk.isError&&sdk.content[0].text===raw("authority.original.json"));
 ck("known successful exact job",auth.job_id==="1a1aaa6142c-fc05-4599"&&auth.exit_code===0&&auth.output_complete&&auth.output_durable&&!auth.timed_out&&auth.terminal_publication_confirmed);
 ck("once exact request ACK",!ack.reused&&ack.job.id===auth.job_id&&ack.job.launch_state==="launched"&&ack.job.host===req.host&&ack.job.executable===req.executable&&ack.job.cwd===req.cwd&&ack.job.idempotency_key===req.idempotency_key&&JSON.stringify(ack.job.args)===JSON.stringify(req.args));
 let combined="",offset=0;
 for(const at of [0,16384,32768,49152]){
   const p="sdk/terminal-"+at,e=j(p+".envelope.json"),v=j(p+".payload.json"),x=v.stdout;
   ck("native stream original "+at,!e.isError&&e.content[0].text===raw(p+".payload.json")&&v.job_id===auth.job_id);
   ck("contiguous whole stream "+at,x.offset===offset&&x.size===55402&&x.next_offset===at+u(x.text).length&&x.eof===(x.next_offset===55402)&&x.bytes_hex===Array.from(u(x.text),v=>v.toString(16).padStart(2,"0")).join(""));
   ck("empty stderr "+at,v.stderr.offset===0&&v.stderr.next_offset===0&&v.stderr.size===0&&v.stderr.eof&&v.stderr.text===""&&v.stderr.bytes_hex==="");combined+=x.text;offset=x.next_offset;
 }
 ck("whole55402",combined===raw("stdout.original.json")&&u(combined).length===55402&&offset===55402&&raw("stderr.original.txt")==="");
 for(const side of ["stdout","stderr"])ck("durable authority "+side,auth.log_bytes[side].seen===(side==="stdout"?55402:0)&&auth.log_bytes[side].stored===(side==="stdout"?55402:0)&&auth.log_synced[side]&&!auth.log_truncated[side]&&auth.log_errors[side]===null);
 ck("original bound publication",core.status==="observed"&&core.complete&&core.publication_within_original_deadline&&core.new_shared_seconds===15&&core.elapsed_seconds_before_publication<15&&core.max_input_bytes===2097152&&core.max_marker_count===128&&core.max_output_bytes===65536&&core.max_timing_line_bytes===65536&&core.markers.length===103);
 ck("readonly zero business",core.read_only&&core.product_requests===0&&core.children_started===0&&core.files_written===0&&!core.raw_log_values_emitted&&!core.unknown_lines_emitted&&!core.cross_request_correlation_proven);
 ck("six fd once closed",core.descriptors.length===6&&core.descriptors.every(x=>x.close_attempted&&x.closed&&!x.close_error)&&core.all_owned_descriptors_closed);
 const v=metadata.version.split(":"),expected={device:v[0],inode:v[1],uid:String(metadata.metadata.uid),gid:String(metadata.metadata.gid),mode:String(metadata.mode),type:"32768",nlink:String(metadata.metadata.link_count),bytes:v[2],mtime_ns:v[3],ctime_ns:v[4]},n=x=>typeof x==="object"?x.$exactInteger:String(x);
 for(const phase of ["input_before","input_after","input_named_after"])ck("full10 literal "+phase,Object.entries(expected).every(([k,x])=>n(core[phase][k])===x));
 ck("source fixture and whole input",core.input_sha256===metadata.sha256&&core.scanned_bytes===metadata.size&&core.same_metadata_input_binding_verified&&core.source_sha256_argument===req.args[5]&&core.candidate_commit==="df026fe323dd7cf0f0ec57d7d2d9c5a79897053c"&&core.cold_read_source_blob==="b09e57362d53ce207b255d713d7aa7c126215691"&&core.fixture_result_sha256==="532967541d5b611665b41286109c459565f24cc29eddef3d4a64b65466afcf8b");
 const last=core.markers.at(-1),cold=last.phases.filter(p=>p.scope==="cold_native_ha");
 ck("complete last bounded timing marker",last.line_number===184&&last.marker==="HBHA-REQUEST-TIMING-FAIL"&&last.status===503&&last.request_class==="ordinary"&&last.bucket_limit===64&&!last.bucket_bound_reached&&last.phases.length===12&&last.exit_remaining_ns==="3717085098");
 for(const name of ["committed_root","local_selection","local_root_binding","local_root_identity"])ck("completed "+name,cold.filter(x=>x.phase===name&&x.calls==="1"&&x.completed==="1"&&x.failed==="0").length===1);
 ck("current cursor actual failure",cold.some(x=>x.phase==="current_cursor"&&x.calls==="1"&&x.completed==="0"&&x.failed==="1"&&x.elapsed_us==="5"));
 ck("no install materialize in complete last scope",!cold.some(x=>["replica_source","replica_install","installed_local_selection","materialize_full","materialize_after_repair"].includes(x.phase)));
 return {checks,last_marker:last};
}
