export function sha256String(str) {
 const raw=unescape(encodeURIComponent(str)), bytes=Array.from(raw,c=>c.charCodeAt(0));
 const len=bytes.length, bitLen=len*8;bytes.push(128);
 while(bytes.length%64!==56)bytes.push(0);
 const hi=Math.floor(bitLen/4294967296),lo=bitLen>>>0;
 for(let i=3;i>=0;i--)bytes.push((hi>>>(8*i))&255);
 for(let i=3;i>=0;i--)bytes.push((lo>>>(8*i))&255);
 const k=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
 const h=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19],rot=(x,n)=>(x>>>n)|(x<<(32-n));
 for(let offset=0;offset<bytes.length;offset+=64) {
  const w=new Array(64);
  for(let i=0;i<16;i++){const p=offset+i*4;w[i]=((bytes[p]<<24)|(bytes[p+1]<<16)|(bytes[p+2]<<8)|bytes[p+3])>>>0;}
  for(let i=16;i<64;i++){const a=w[i-15],b=w[i-2];w[i]=(w[i-16]+(rot(a,7)^rot(a,18)^(a>>>3))+w[i-7]+(rot(b,17)^rot(b,19)^(b>>>10)))>>>0;}
  let [a,b,c,d,e,f,g,hh]=h;
  for(let i=0;i<64;i++){const t1=(hh+(rot(e,6)^rot(e,11)^rot(e,25))+((e&f)^(~e&g))+k[i]+w[i])>>>0,t2=((rot(a,2)^rot(a,13)^rot(a,22))+((a&b)^(a&c)^(b&c)))>>>0;hh=g;g=f;f=e;e=(d+t1)>>>0;d=c;c=b;b=a;a=(t1+t2)>>>0;}
  for(const [i,x]of[a,b,c,d,e,f,g,hh].entries())h[i]=(h[i]+x)>>>0;
 }
 return h.map(x=>x.toString(16).padStart(8,"0")).join("");
}

export function reviewMacCargoLockEvidence(files,sha) {
 const p1="qa/evidence/20261104/mac-cargo-lock-probe-r1/",p2="qa/evidence/20261104/mac-cargo-lock-probe-r2/";
 const checks=[],ck=(name,ok)=>{checks.push({name,passed:!!ok});if(!ok)throw new Error(name);};
 const J=p=>JSON.parse(files[p]),S=p=>JSON.parse(J(p).content.find(c=>c.type==="text").text);
 const q1=J(p1+"original-request.public.json"),q2=J(p2+"original-request.public.json");
 const s1=S(p1+"status.original-sdk.json"),s2=S(p2+"status.original-sdk.json");
 const a1=S(p1+"start.original-sdk.json"),a2=S(p2+"start.original-sdk.json");
 const r1=S(p1+"read.original-sdk.json"),r2=S(p2+"read.original-sdk.json");
 const st=J(p2+"stage.public.json"),r=J(p2+"result.public.json");
 for(const f of S(p2+"files.original-sdk.json").files)ck("remote_file_"+f.path.split("/").at(-1),files[p2+f.path.split("/").at(-1)]===f.text&&sha(f.text)===f.sha256&&unescape(encodeURIComponent(f.text)).length===f.size&&f.eof===true);
 ck("original_request_bytes",sha(files[p1+"original-request.public.json"])==="bda920dc7284041d64279c6bdaa85a51a2b83f16417679a016016b018ae7b21d");
 ck("probe_pin",sha(q2.stdin)==="aaec18ac2ac5a610629b3eaa6d0e8e0de7ef0d45716cd5e3ea24b11145136271"&&q1.stdin===q2.stdin&&files[p2+"probe_actual_cargo_release_lock_r2.py"]===q2.stdin);
 ck("wrapper_pins",sha(q1.args.at(-1))==="a1564315bd8095e41d801fc70f23123c401e1cc1a90b331f9e3d0532823b53a3"&&sha(q2.args.at(-1))==="36764b174fae8037fc2020aed9334d2f399342ea3f2dabe69126be95fdd4faa0"&&files["tools/production/run_mac_cargo_lock_probe.py"]===q2.args.at(-1));
 for(const [q,a]of[[q1,a1],[q2,a2]])ck("request_"+a.job.id,a.job.host===q.host&&a.job.executable===q.executable&&a.job.cwd===q.cwd&&a.job.idempotency_key===q.idempotency_key&&JSON.stringify(a.job.args)===JSON.stringify(q.args));
 ck("first_red_before_probe",s1.job_id==="1a1a77f3353-fc05-2b9a"&&s1.state==="failed"&&s1.exit_code===1&&r1.stdout.size===0&&r1.stderr.size===261&&r1.stderr.text.includes("assert info.st_dev == device and info.st_uid == 501")&&q1.args.at(-1).indexOf("assert info.st_dev == device and info.st_uid == 501")<q1.args.at(-1).indexOf("CONTROL.mkdir"));
 for(const s of[s1,s2])ck("durable_terminal_"+s.job_id,s.output_complete===true&&s.output_durable===true&&s.terminal_publication_confirmed===true&&s.automatic_retry===false&&s.timed_out===false&&s.log_truncated.stdout===false&&s.log_truncated.stderr===false);
 ck("volume_interpreter",st.ok===true&&st.mount_uid===0&&st.work_base_uid===501&&st.volume_uuid==="FB804D1B-24CB-4D6E-AEA7-A9E180807758"&&st.python_sha256==="7ecc1ecbf9daa9303c4bf502ff62ffdd9010ed5c08729d470ae9380c10ce1211"&&st.probe_source_sha256===sha(q2.stdin)&&st.probe_source_bytes===9003);
 ck("success_job",s2.job_id==="1a1a7848b96-fc05-2ba5"&&a2.job.id===s2.job_id&&s2.state==="succeeded"&&s2.exit_code===0&&r2.job_id===s2.job_id&&r2.stderr.size===0&&r2.stdout.eof&&r2.stderr.eof);
 const outputs=r2.stdout.text.trimEnd().split("\n").map(JSON.parse);
 ck("stdout_pins",outputs.length===2&&outputs[0].stage_receipt_sha256===sha(files[p2+"stage.public.json"])&&outputs[1].result_sha256===sha(files[p2+"result.public.json"])&&outputs[1].status==="passed");
 ck("toolchain",r.cargo_version===files[p2+"cargo-version.stdout"]&&r.cargo_version.startsWith("cargo 1.98.0 ")&&r.cargo.sha256==="1de2e84c15443b70444eecfa959ff9099dd8c1a5606b6d9ef5bc0ea9c25bc7f9"&&r.rustc.sha256==="a11618eca0956a8aa4372c2bc898690b513cbdfa2cb9125b2a5301e360ed5b49");
 ck("actual_lock_wait",r.blocked_same_child.primitive==="flock LOCK_EX|LOCK_NB"&&r.blocked_same_child.existing_descriptor_mode==="O_RDONLY|O_NOFOLLOW"&&r.blocked_same_child.artifact_absent===true&&r.blocked_same_child.diagnostic==="Blocking waiting for file lock on artifact directory"&&files[p2+"cargo.stderr"].trimStart().startsWith(r.blocked_same_child.diagnostic+"\n"));
 ck("same_child_sequence",r.same_child_pid===r.blocked_same_child.pid&&r.same_child_pid===r.owned_child_cleanup.pid&&r.blocked_same_child.held_since_monotonic_ns<r.blocked_same_child.observed_at_monotonic_ns&&r.blocked_same_child.observed_at_monotonic_ns<=r.released_at_monotonic_ns&&r.released_at_monotonic_ns<r.completed_at_monotonic_ns);
 ck("log_pins",sha(files[p2+"cargo.stdout"])===r.cargo_stdout_sha256&&sha(files[p2+"cargo.stderr"])===r.cargo_stderr_sha256);
 const es=files[p2+"cargo.stdout"].trimEnd().split("\n").map(JSON.parse);
 ck("real_non_test_artifact",es.some(e=>e.reason==="build-finished"&&e.success===true)&&es.filter(e=>e.reason==="compiler-artifact"&&e.executable===r.actual_cargo_artifact.executable).length===1&&r.actual_cargo_artifact.fresh===false&&r.actual_cargo_artifact.profile.test===false&&r.actual_cargo_artifact.profile.opt_level==="3");
 ck("original_budget_cleanup",r.status==="passed"&&r.budget_seconds===30&&r.elapsed_seconds<=30&&r.owned_child_cleanup.reaped===true&&r.owned_child_cleanup.wait_returncode===0&&r.owned_child_cleanup.remaining.length===0);
 ck("scope",r.source_cache_touched===false&&r.product_compiled_or_started===false&&r.exact_tag_handler_source_claimed===false&&st.product_source_or_cache_touched===false&&st.production_service_or_client_changed===false);
 return {schema:"heptabao.mac-cargo-release-lock-root-review.v1",evidence_consistent:true,checks_passed:checks.length,checks_total:checks.length,checks,job_id:s2.job_id,result_sha256:sha(files[p2+"result.public.json"]),probe_elapsed_seconds:r.elapsed_seconds,qualified_scope:"Actual pinned Cargo 1.98.0 on Darwin waits for O_RDONLY flock on its owned release build directory and the same child builds after unlock.",limitations:{product_build_qualified:false,normal_product_profile_qualified:false,global_cargo_home_reserved:false,whole_host_reserved:false,source_cache_clone_executed:false,ha_or_storage_behavior_qualified:false,production_cutover:false,full_replacement:false},prior_red:{job_id:s1.job_id,reason:"Wrapper incorrectly required user ownership of the root-owned APFS mount; failed before any directory creation or probe execution."},control_plane_note:"The initial r2 response was not retained as a parseable receipt. Reconciliation used the identical request and key; only the authoritative job and complete raw receipts above are accepted."};
}
