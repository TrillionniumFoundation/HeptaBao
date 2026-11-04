function(raw,info){
 const h=eval("("+load("source_hash_sha256_js")+")"),e=eval("("+load("source_hash_utf8_js")+")");
 const src=load("phaseb_r3_old_logs_projection_runtime_source");
 const fixed=new Set([...src.matchAll(/"([a-z][a-z0-9_]{0,79})"/g)].map(m=>m[1]));
 const keys=["schema","request_class","forwarded","status","elapsed_us","entry_remaining_ns","exit_remaining_ns","bucket_limit","bucket_bound_reached","phases"];
 const bk=["scope","phase","calls","advanced","completed","failed","elapsed_us","maximum_elapsed_us","first_entry_remaining_ns","last_exit_remaining_ns","minimum_entry_remaining_ns","minimum_exit_remaining_ns"];
 const same=(a,b)=>a.length===b.length&&a.every(x=>b.includes(x));
 const out={path:info.path,bytes:info.size,sha256:info.sha256,version:info.version,line_count:raw?raw.split("\n").length-Number(raw.endsWith("\n")):0,events:[],unmatched_lines:0,rejected_prefix_lines:0};
 for(const[i,line]of raw.split("\n").entries()){
  if(!line)continue;const line_sha256=h(e(line));
  if(line.startsWith("HBHA-NATIVE-SYNC-FAIL ")){
   const m=/^HBHA-NATIVE-SYNC-FAIL step=([a-z0-9_]+) code=([a-z0-9_]+) reason_sha=([0-9a-f]{64}|-) elapsed_us=(\d+) step_elapsed_us=(\d+) original_deadline_expired=(true|false) original_remaining_ns=(\d+) panicking=(true|false)$/.exec(line);
   if(!m||!fixed.has(m[1])||!fixed.has(m[2])){out.rejected_prefix_lines++;continue;}
   out.events.push({line:i+1,line_sha256,prefix:"HBHA-NATIVE-SYNC-FAIL",step:m[1],code:m[2],reason_sha256:m[3],elapsed_us:m[4],step_elapsed_us:m[5],original_deadline_expired:m[6]==="true",original_remaining_ns:m[7],panicking:m[8]==="true"});continue;
  }
  if(line.startsWith("HBHA-REQUEST-TIMING-FAIL ")){
   let x;try{x=JSON.parse(line.slice(25));}catch{out.rejected_prefix_lines++;continue;}
   const ints=keys.filter(k=>!["schema","request_class","forwarded","bucket_bound_reached","phases"].includes(k));
   const valid=same(Object.keys(x),keys)&&x.schema==="heptabao.native-ha.request-failure-timing.v1"&&fixed.has(x.request_class)&&typeof x.forwarded==="boolean"&&typeof x.bucket_bound_reached==="boolean"&&ints.every(k=>Number.isSafeInteger(x[k])&&x[k]>=0)&&x.status>=500&&x.status<=599&&x.bucket_limit===64&&Array.isArray(x.phases)&&x.phases.length<=64&&x.phases.every(p=>same(Object.keys(p),bk)&&fixed.has(p.scope)&&fixed.has(p.phase)&&bk.filter(k=>!["scope","phase"].includes(k)).every(k=>Number.isSafeInteger(p[k])&&p[k]>=0));
   if(!valid){out.rejected_prefix_lines++;continue;}
   out.events.push({line:i+1,line_sha256,prefix:"HBHA-REQUEST-TIMING-FAIL",...x});continue;
  }
  if(line.startsWith("heptabao-r72-sync: ")){
   const a=/^heptabao-r72-sync: stage=sync_inner_error status=(\d{3}) loaded=(true|false) recovery=(true|false) record_root=(true|false)$/.exec(line);
   const c=/^heptabao-r72-sync: stage=materialized_completed_error status=(\d{3})$/.exec(line);
   if(a)out.events.push({line:i+1,line_sha256,prefix:"heptabao-r72-sync",stage:"sync_inner_error",status:Number(a[1]),loaded:a[2]==="true",recovery:a[3]==="true",record_root:a[4]==="true"});
   else if(c)out.events.push({line:i+1,line_sha256,prefix:"heptabao-r72-sync",stage:"materialized_completed_error",status:Number(c[1])});
   else out.rejected_prefix_lines++;continue;
  }out.unmatched_lines++;
 }return out;
}
