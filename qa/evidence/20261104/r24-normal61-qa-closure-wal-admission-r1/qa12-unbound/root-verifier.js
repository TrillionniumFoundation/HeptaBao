function verifyQA12Unbound(input,utf8,latin1,sha256,unb64,apply){
 const raw=input.raw,a=input.audit,checks=[],ck=(n,v)=>{if(!v)throw Error(n);checks.push(n);},hash=s=>sha256(latin1(utf8(s))),obj=p=>JSON.parse(raw[p]),same=(a,b)=>JSON.stringify(a)===JSON.stringify(b),si=obj("verification/static-input.json"),ci=obj("verification/carrier-input.json"),b=obj("binding/files.unbound.public.json"),dispatch=obj("dispatch/templates.unbound.public.json"),oldreq=obj("references/normal5-actual-inert.request.json"),oldpayload=JSON.parse(oldreq.stdin);
 const map=new Map(a.records.map(r=>[r.path,r])),bindings=raw["references/qa-binding-215d6db9.py"];
 ck("original_normal5_carrier_recovered_exact",oldreq.args.at(-1)===raw["before/inert_carrier.py"]&&Object.keys(oldpayload.files).length===3);
 function defs(s){
  const lines=s.split("\n"),out={};
  for(let i=0;i<lines.length;i++){const m=lines[i].match(/^(?:def|class) ([A-Za-z_]\w*)/);if(!m)continue;let j=i+1;while(j<lines.length&&(lines[j]===""||/^\s/.test(lines[j])))j++;out[m[1]]=lines.slice(i,j).join("\n").trimEnd()+"\n";}
  return out;
 }
 let unchangedCount=0,totalHunks=0;
 for(const [name,hunks]of[["sender.py",2],["receiver.py",6],["relay.py",3]]){
  const before=raw["before/"+name],after=raw["candidate/"+name],patch=apply(before,raw["diffs/"+name+".diff"]);
  ck(name+".actual_before_payload",latin1(unb64(oldpayload.files[name]))===latin1(utf8(before)));
  ck(name+".actual_static_inputs",si.old[name]===before&&si.candidate[name]===after);
  ck(name+".strict_whole_diff",patch.text===after&&patch.hunks===hunks);totalHunks+=hunks;
  ck(name+".guard_before_setup",after.includes("ACTUAL_INPUTS_READY=False\nif not ACTUAL_INPUTS_READY:\n raise RuntimeError('unresolved exact H2 QA artifact transport input metadata')\nos.umask(0o077)")&&after.indexOf("ACTUAL_INPUTS_READY=False")<after.indexOf("START=time.monotonic()"));
  ck(name+".instrument_identity_fixed",after.includes("HEAD='df026fe323dd7cf0f0ec57d7d2d9c5a79897053c'")&&after.includes("TREE='424463ccd2310ddc1e7b2bbcd7b7af29ae58c825'"));
  const beforeDefs=defs(before),afterDefs=defs(after);
  for(const [n,body]of Object.entries(beforeDefs)){if(n==="receive")continue;ck(name+"."+n+".whole_definition_unchanged",body===afterDefs[n]);unchangedCount++;}
  const tableText=after.slice(after.indexOf("FILES=")+6,after.indexOf("\n]",after.indexOf("FILES="))+2),table=JSON.parse(tableText.replace(/\bNone\b/g,"null"));
  ck(name+".exact12_unbound_roles",same(table,b.files)&&same(table,si.table)&&table.length===12&&table.every(r=>r.bytes===null&&r.sha256===null&&r.version===null&&(r.role==="executable"?r.source_mode===320&&r.target_mode===320:r.source_mode===384&&r.target_mode===256)));
 }
 ck("36_prior_transport_definitions_preserved",unchangedCount===36&&totalHunks===11);
 ck("source_role_paths_known_exact",same(si.path_manifest,obj("references/qa12-paths.unbound.public.json"))&&b.files.every((f,i)=>f.role===si.path_manifest.files[i].role&&f.path===si.path_manifest.files[i].source&&f.name===si.path_manifest.files[i].basename)&&new Set(b.files.map(x=>x.role)).size===12&&new Set(b.files.map(x=>x.name)).size===12);
 ck("binder_reference_exact_reviewed",map.get("references/qa-binding-215d6db9.py").blob==="215d6db91333b5a74e4814c3fe66051e858d5e0e"&&si.binder===bindings);
 const r=raw["candidate/receiver.py"],rd=defs(r),bd=defs(bindings);
 for(const n of ["need","sha","duplicate_free","parse","lock_subset"])ck("binder_data_helper_exact."+n,rd[n]===bd[n]);
 const bl=bindings.split("\n"),at=bl.findIndex(l=>l.startsWith("    def verify_h2_qa(")),end=bl.findIndex((l,i)=>i>at&&l.startsWith("    def "));
 let method=bl.slice(at,end).map(l=>l.startsWith("    ")?l.slice(4):l).join("\n").trimEnd()+"\n";
 method=method.replace("def verify_h2_qa(self, until: int) -> dict:\n","def verify_h2_qa(raw: dict) -> dict:\n    pins = {item['role']: item for item in FILES}\n").replaceAll("self.h2_client","pins");
 const readBlock='    raw = {}\n    for role in ("cargo_lock", "canonical_lock", "build_receipt", "build_binding",\n                 "component_stdout", "component_record", "component_list_stdout"):\n        raw[role], _ = pin_file(pins[role], until, retain=True)\n';
 ck("exact_old_additional_file_read_block",method.includes(readBlock));
 method=method.replace(readBlock,"").replaceAll('self.artifacts["combined_tests"]["sha256"]',"NORMAL_DF026_COMBINED_SHA").replace(/\bCOMMIT\b/g,"HEAD").replace("    remaining(until)\n","    remaining()\n");
 ck("instrument_verifier_only_data_adaptation",method===rd.verify_h2_qa&&method===si.expected_method.trimEnd()+"\n"&&!method.includes("pin_file(")&&!method.includes("self."));
 ck("historic_normal60_provenance_fixed",r.includes('NORMAL_DF026_COMBINED_SHA = "84d763e6ff948df27964f373e834f869d7b22eeb0d7efb929fbd5c299c528f1b"')&&method.includes('"1a3fdc3a7cf6504447feb7d7dadf2f365b292512f6d0cf8cdfb4a2ea63d33d40"')&&method.includes("heptabao.native-h2-qa.build.v3"));
 ck("same_FD_source_byte_validation_before_QA",rd.receive.includes("read_file(fd,item['bytes'],item['sha256'],item['role']!='executable')")&&rd.receive.includes("identity(before)==identity(os.fstat(fd))==identity(path.lstat())")&&rd.receive.includes("assert os.read(0,1)==b''")&&rd.receive.split("verify_h2_qa(qa_bytes)").length===2&&rd.receive.includes("qa_build_provenance_verified=True")&&!r.includes("normal_release_provenance_verified"));
 ck("fresh_exact_destination",r.includes("ROOT=Path('/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-native-h2-qa-shared-artifacts-r1')")&&rd.receive.includes("assert not DESTINATION.exists() and not DESTINATION.is_symlink()")&&rd.receive.includes("os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW")&&rd.receive.includes("finally:os.close(fd)"));
 const carrier=raw["candidate/inert_carrier.py"],oldcarrier=raw["before/inert_carrier.py"],patch=apply(oldcarrier,raw["diffs/inert_carrier.py.diff"]),payload=JSON.parse(raw["payload/three-controls.unbound.json"]);
 ck("inert_only3_hunks",patch.text===carrier&&patch.hunks===3&&ci.before===oldcarrier&&ci.after===carrier&&ci.payload===raw["payload/three-controls.unbound.json"]);
 const cdefs=defs(carrier),olddefs=defs(oldcarrier);ck("all5_inert_definitions_whole",Object.keys(cdefs).length===5&&same(cdefs,olddefs));
 ck("exact_inert_payload3_unchanged_cap",payload.schema==="heptabao.df026-shared-h2qa12-inputs.v1"&&Object.keys(payload.files).length===3&&utf8(raw["payload/three-controls.unbound.json"]).length===61860&&carrier.includes("incoming = sys.stdin.buffer.read(262145)")&&carrier.includes("len(incoming) <= 262144"));
 for(const n of ["sender.py","receiver.py","relay.py"])ck(n+".inert_payload_exact",latin1(unb64(payload.files[n]))===latin1(utf8(raw["candidate/"+n]))&&ci.sources[n]===raw["candidate/"+n]);
 const se=obj("verification/static-executor.json"),sr=obj("verification/static-result.public.json"),ce=obj("verification/carrier-executor.json"),cr=obj("verification/carrier-result.public.json");
 ck("46_actual_selected_AST_checks",se.exit_code===0&&same(JSON.parse(se.output),sr)&&sr.status==="passed"&&sr.checks.length===46&&sr.checks.every(c=>c.passed===true)&&sr.selected_guard_executions===3&&sr.full_module_executions===0&&sr.host_actions===0&&sr.children===0&&sr.transport_execution===false);
 ck("actual_inert_static_result",ce.exit_code===0&&same(JSON.parse(ce.output),cr)&&cr.status==="passed"&&cr.whole_compile_only===1&&cr.decoded_sources===3&&cr.module_execution===false&&cr.host_actions===0&&cr.transport_execution===false);
 ck("original_transport_caps",same(dispatch.limits,{relay_seconds:300,child_seconds:90,endpoint_seconds:90,connect_seconds:10,term_seconds:5,kill_seconds:5})&&dispatch.inert.timeout_seconds===60&&dispatch.relay.timeout_seconds===360);
 ck("no_request_or_go",dispatch.ready===false&&dispatch.inert.request===null&&dispatch.inert.idempotency_key===null&&dispatch.relay.request===null&&dispatch.relay.idempotency_key===null&&dispatch.host_action_authorized===false&&b.ready===false&&b.current_product_not_transported===true);
 return{schema:"heptabao.root.qa12-transport-unbound-source.v1",status:"PASS_UNBOUND_TOOL_TRANSPORT_SOURCE_ONLY",packet:a.tree,files:a.files,bytes:a.bytes,merkle_trees:a.merkle.trees_verified,check_count:checks.length,checks,source_artifact_slots_unbound:12,whole_unchanged_transport_definitions:36,whole_unchanged_inert_definitions:5,actual_selected_AST_checks:46,strict_hunks:{sender:2,receiver:6,relay:3,carrier:3},instrument_commit:"df026fe323dd7cf0f0ec57d7d2d9c5a79897053c",current_product_qualification_inherited:false,original_limits:dispatch.limits,metadata_bindings_ready:false,inert_go:false,relay_go:false,current_product_H2_go:false,full_replacement:false,host_calls_by_verifier:0};
}