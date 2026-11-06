function verifyReadyControlsSource(f,h,d,correctBinding) {
 const checks=[];function ck(k,v){checks.push({check:k,pass:!!v});if(!v)throw Error(k);}
 const bind=JSON.parse(f["BINDINGS.public.json"]),qual=h.parseLosslessIntegers(f["root-stage-qualification.original.json"]),stage=h.parseLosslessIntegers(f["stage-result.original.json"]);
 ck("actual_root_source_stage_qualified",h.gitBlobMeta(f["root-stage-qualification.original.json"]).blob==="7cdf99e46ba40fe09ab156a09608ee131e28400d"&&qual.evidence_qualified===true&&qual.source_prepared===true&&qual.report.blob===h.gitBlobMeta(f["stage-result.original.json"]).blob);
 ck("current33b_source_and_report",stage.source_commit==="33b814c7034ec853151b1ff13e7529c83f65ea70"&&stage.source_tree==="b7f276f70e0da1a33306564f385ab7bc12fd44f6"&&stage.status==="prepared"&&h.gitBlobMeta(f["stage-result.original.json"]).sha256==="2137f9962784c451d11a2aaae0741189fec8ab511c0b3e6b226031f908331da0");
 function defs(s){const lines=s.split("\n"),out=[];for(let i=0;i<lines.length;i++){if(!/^def \w+\(/.test(lines[i]))continue;let j=i+1;while(j<lines.length&&(!lines[j]||/^\s|^#/.test(lines[j])))j++;out.push(lines.slice(i,j).join("\n"));i=j-1;}return out;}
 let count=0,hunks=0;
 for(const role of["runner","launcher","publisher"]){const a=f[role+".before.py"],b=f[role+".after.py"],diff=f[role+".strict.diff"];let x=a;
 ck("before_pin:"+role,h.gitBlobMeta(a).blob===bind.beforePins[role].blob);
 for(const[p,q]of bind.replacements[role]){ck("single_explicit_literal:"+role+":"+p.slice(0,25),x.split(p).length===2);x=x.replace(p,q);}ck("all_other_bytes_same:"+role,x===b);
 for(const[p,q]of bind.replacements[role].slice().reverse()){if(x.split(q).length!==2)throw Error("inverse_once");x=x.replace(q,p);}ck("inverse_whole:"+role,x===a);
 const fw=d.applyStrictUnified(a,diff),rv=d.applyStrictUnified(b,diff,true);ck("strict_both_directions:"+role,fw.text===b&&rv.text===a);hunks+=fw.hunks;
 ck("exactly_ready_flag:"+role,b.includes("BINDING_READY = True")&&!b.includes("BINDING_READY = False"));
 ck("all_functions_whole:"+role,JSON.stringify(defs(a))===JSON.stringify(defs(b)));count+=defs(b).length;
 }
 ck("25_original_functions_4_hunks",count===25&&hunks===4);
 const groupRaw=f["jwt-test-groups.public.json"],gm=h.gitBlobMeta(groupRaw),groups=JSON.parse(groupRaw);
 ck("unchanged_groups35153",gm.blob==="5d563b1c7a1b7070395f6d8a03b512ddb019fae0"&&gm.sha256==="35153ff5e90b582f83e4fbbb66ff5c9fb295e95153f08df152cefedecdb50869");
 ck("actual149_unique166_profiles",new Set(groups.flatMap(x=>x.tests)).size===149&&groups.reduce((n,x)=>n+x.tests.length,0)===166);
 ck("four_original_budgets_and_shape",JSON.stringify(groups.map(x=>[x.label,x.libtest_profile,x.tests.length,x.runtime_seconds]))===JSON.stringify([["native-jwt-pki-file17","file",17,600],["native-jwt-pki-default17","default",17,600],["legacy-jwt-default63","default",63,600],["native-auth-identity-default69","default",69,600]]));
 ck("runner_launcher_same_groups",f["runner.after.py"].includes("assert args.groups_sha256 == '"+gm.sha256+"'")&&f["launcher.after.py"].includes("GROUPS_SHA256 = '"+gm.sha256+"'"));
 const pins=JSON.parse(/^PINS = (\{[\s\S]*?\n\})\n/m.exec(f["publisher.after.py"])[1]),payload=JSON.parse(f["payload.exact.json"]);
 ck("carrier_schema_exact_3_files",payload.schema==="heptabao.native-jwt-pki-build-control-inputs.v1"&&Object.keys(payload.files).sort().join(",")==="jwt-test-groups.public.json,launch_native_jwt_build.py,native_jwt_build.py");
 for(const[name,raw]of Object.entries({"native_jwt_build.py":f["runner.after.py"],"launch_native_jwt_build.py":f["launcher.after.py"],"jwt-test-groups.public.json":groupRaw})){const p=h.gitBlobMeta(raw),decoded=h.utf8Text(h.unb64(payload.files[name]));ck("publisher_pin_and_whole_payload:"+name,decoded===raw&&pins[name][0]===p.bytes&&pins[name][1]===p.sha256);}
 const q=JSON.parse(f["INERT.PROPOSED.request.json"]),qp=h.gitBlobMeta(f["INERT.PROPOSED.request.json"]);
 ck("one_unchanged_publisher_interface",q.host==="rog"&&q.executable==="/usr/bin/python3"&&q.cwd==="/home/qian-qi"&&q.timeout_seconds===60&&JSON.stringify(q.args.slice(0,4))===JSON.stringify(["-I","-S","-B","-c"])&&q.args.length===5&&q.args[4]===f["publisher.after.py"]&&q.stdin===f["payload.exact.json"]);
 ck("original_stdin_cap_actual",h.gitBlobMeta(q.stdin).bytes===118531&&h.gitBlobMeta(q.stdin).bytes<=262144&&f["publisher.after.py"].includes("incoming = sys.stdin.buffer.read(262145)"));
 ck("bounded_new_inert_key",q.idempotency_key==="heptabao-native-jwt-pki-33b814c7-controls-inert-r1-8724a95b"&&q.idempotency_key.length<=128);
 ck("actual_typed_digest_positive_control",correctBinding(JSON.parse(f["positive-control.request.original.json"])).sha256==="043dd4147f135f879d2ad30d1d31bec7ee692a940eac9b8a31a892ce6da7e732");
 const typed=correctBinding(q);ck("exact_proposed_typed_digest",typed.sha256===bind.typedBinding.sha256&&typed.native_fingerprint===bind.typedBinding.native_fingerprint);
 let j=f["journal.before.js"];for(const[p,z]of bind.journalReplacements){ck("single_journal_binding:"+p.slice(0,30),j.split(p).length===2);j=j.replace(p,z);}ck("journal_only5_bindings",j===f["journal.after.js"]&&bind.journalReplacements.length===5);
 const jf=d.applyStrictUnified(f["journal.before.js"],f["journal.strict.diff"]),jr=d.applyStrictUnified(j,f["journal.strict.diff"],true);ck("journal2_hunks_strict_whole",jf.text===j&&jr.text===f["journal.before.js"]&&jf.hunks===2);
 ck("exact_request_and_fresh_slot_bound",j.includes(qp.blob)&&j.includes(String(qp.bytes))&&j.includes(qp.sha256)&&j.includes('const GF_SLOT = "jwt_pki_33b814c7_build_controls_inert_gitfirst_r1"'));
 ck("original_journal_caps_and_success_boundary",j.includes("q.limit===8192")&&j.includes("a.limit===16384")&&j.includes("v.total_bytes<=1048576")&&j.includes('return {ok:true,action,value:'));
 ck("no_new_runtime_or_Cargo_claim",bind.NativeCalls===0&&bind.Cargo===0&&bind.controlsPublication===null&&bind.buildRequest===null);
 return {schema:"heptabao.jwt-pki33b-build-controls-ready-source-checks.v1",pass:true,checks:checks.length,rows:checks,unchangedPythonFunctions:count,sourceHunks:hunks,journalHunks:jf.hunks,uniqueTests:149,profileInstances:166,Native:0,Cargo:0,candidateExecuted:false};
}
