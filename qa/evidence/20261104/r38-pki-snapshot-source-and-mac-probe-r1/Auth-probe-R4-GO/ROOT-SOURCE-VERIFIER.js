function reviewR4Root(p,r3,peer,selfq){
 const f=p.raw,o=r3.raw,checks=[];function ck(name,v){checks.push({name,passed:!!v});if(!v)throw Error(name);}
 const eq=(a,b)=>JSON.stringify(a)===JSON.stringify(b), pin=(s,v)=>{const q=gitBlobMeta(s);return q.blob===v.blob&&q.bytes===v.bytes&&q.sha256===v.sha256;};
 function once(s,a,b){if(s.split(a).length!==2)throw Error("not one:"+a.slice(0,64));return s.replace(a,b);}
 ck("whole_SOURCE28_exact",p.audit.tree==="690747178bd9d66eedca0e704719727bd4cd5a3a"&&p.pins.length===28&&p.pins.reduce((n,x)=>n+x.bytes,0)===536636);
 ck("whole_original_R3_SOURCE31",r3.audit.tree==="c680477cae4fc6dd01077b01de6c349e9fea3055"&&r3.pins.length===31);
 const refs=JSON.parse(f["REFERENCES.public.json"]),newc=f["constants.r4.py"],oldc=f["constants.r3.original.py"],newm=f["common.r4.py"],oldm=f["common.r3.original.py"];
 for(const n of ["constants","common","journal"]){const before=f[n+".r3.original."+ (n==="journal"?"js":"py")],after=f[n+".r4."+(n==="journal"?"js":"py")];const fw=strictApply(before,f[n+".forward.diff"]),rv=strictApply(after,f[n+".forward.diff"],true);ck(n+"_strict_both_directions",fw.text===after&&rv.text===before&&fw.hunks===(n==="journal"?2:1));ck(n+"_explicit_reverse_diff",strictApply(after,f[n+".reverse.diff"]).text===before);}
 const image=/^KERNEL_PYTHON_IMAGE = ("[^"]+")$/m.exec(newc);ck("one_exact_kernel_constant",!!image&&once(newc,image[0]+"\n","")===oldc);
 const kernel=JSON.parse(image[1]),launcher=/^PYTHON = '([^']+)'$/m.exec(newc)[1];
 ck("only_executable_rhs_changed",once(newm,"== KERNEL_PYTHON_IMAGE","== PYTHON")===oldm);
 const child=f["managed-probe.r4.py"],controller=f["controller.r4.py"],originalChild=o["managed-probe.r3.py"],originalController=o["controller.r3.py"];
 ck("child_whole_inverse_original",once(once(child,newc,oldc),newm,oldm)===originalChild&&pin(originalChild,refs.before.child));
 ck("original_common_matches_prior_review",o["fixed-io.r3.py"]===oldm);
 const b64=/^CHILD_BASE64 = '([^']+)'$/m.exec(controller)[1],oldb64=/^CHILD_BASE64 = '([^']+)'$/m.exec(originalController)[1];
 ck("embedded_child_exact",utf8Text(unb64(b64))===child&&utf8Text(unb64(oldb64))===originalChild);
 let back=once(once(controller,newc,oldc),newm,oldm);
 back=once(back,b64,oldb64);back=once(back,"CHILD_BYTES = "+refs.after.child.bytes,"CHILD_BYTES = "+refs.before.child.bytes);back=once(back,"CHILD_SHA = '"+refs.after.child.sha256+"'","CHILD_SHA = '"+refs.before.child.sha256+"'");
 ck("whole_controller_inverse_original",back===originalController&&pin(back,refs.before.controller));
 ck("whole_original_parent_core_unchanged","\n"+controller.slice(controller.indexOf("PARENT_START_NS = "))===o["controller-core.r3.py"]);
 ck("kernel_occurrences_only_constant_and_operand",controller.split("KERNEL_PYTHON_IMAGE").length===3&&child.split("KERNEL_PYTHON_IMAGE").length===3);
 for(const [name,path]of Object.entries({constants:"constants.r4.py",common:"common.r4.py",controller:"controller.r4.py",child:"managed-probe.r4.py",request:"request.r4.json",journal:"journal.r4.js",contract:"CONTRACT.r4.json"}))ck("exact_after_pin_"+name,pin(f[path],refs.after[name]));
 const q=JSON.parse(f["request.r4.json"]),oldq=JSON.parse(o["request.r3.json"]);ck("request_changes_only_stdin_and_key",eq({...q,stdin:oldq.stdin,idempotency_key:oldq.idempotency_key},oldq)&&q.stdin===controller&&q.idempotency_key==="heptabao-mac-owned-home-t5-probe-87ddc495-20261106-r4");
 ck("typed_STDIN_envelope",eq(Object.keys(q).sort(),["args","cwd","executable","host","idempotency_key","stdin","timeout_seconds"])&&q.host==="mac"&&q.executable===launcher&&eq(q.args,["-I","-S","-B","-"])&&q.cwd==="/Users/qianqi"&&q.timeout_seconds===60);
 let j=f["journal.r4.js"];for(const[a,b]of[["owner_launchd_home_t5_probe_gitfirst_r4","owner_launchd_home_t5_probe_gitfirst_r3"],[refs.after.request.blob,refs.before.request.blob],[String(refs.after.request.bytes),String(refs.before.request.bytes)],[refs.after.request.sha256,refs.before.request.sha256],["heptabao-mac-owned-home-t5-probe-87ddc495-","heptabao-mac-owned-home-t5-probe-8cfa410c-"]])j=once(j,a,b);
 ck("original_journal_all_bytes_restored",j===o["journal.r3.js"]&&j===f["journal.r3.original.js"]);
 const c=JSON.parse(f["CONTRACT.r4.json"]),oc=JSON.parse(f["CONTRACT.r3.original.json"]);
 ck("original_contract_exact_prior",pin(f["CONTRACT.r3.original.json"],refs.before.contract)&&f["CONTRACT.r3.original.json"]===o["CONTRACT.r3.json"]);
 for(const k of["roots","effects","chronology","ownership","budget","closureConstructionCorrection"])ck("contract_unchanged_"+k,eq(c[k],oc[k]));
 ck("fresh_qualified_self_reference",selfq.blob==="110d8f083a05e5cb478fdb60917d0406b54bc276"&&selfq.value.evidence_qualified&&pin(f["self.stdout.original.json"],selfq.value.stdout)&&pin(f["self.authority.original.json"],selfq.value.authority));
 const s=JSON.parse(f["self.stdout.original.json"]);ck("fresh_two_actual_paths_match_literal",s.first.publicExecutablePath===kernel&&s.second.publicExecutablePath===kernel&&s.sameIdentityAndBirthAcrossReads&&s.sysExecutableEqualsFixedLauncher&&s.declaredLauncher===launcher&&kernel!==launcher);
 ck("fresh_all_five_numeric_predicates_true",["first","second"].every(k=>Object.entries(s[k].originalPredicates).every(([n,v])=>v===(n!=="executable_eq_fixed_python"))));
 const m=controller.slice(controller.indexOf("def main():")),firstMkdir=m.indexOf("io.mkdir(HOME)");
 ck("fresh_both_absence_before_mkdir",["io.absent(HOME)","io.absent(WORK)","need(temporary.query(expect_binding=False) is None, 'fresh_label_initially_absent')"].every(x=>m.indexOf(x)>=0&&m.indexOf(x)<firstMkdir));
 ck("fixed_launcher_whole_identity_and_PYTHON_argv_preserved",m.includes("io.read(Path(PYTHON), expected=PYTHON_ID)")&&m.includes("sha(raw) == PYTHON_SHA")&&m.includes("argv = [PYTHON,'-I','-S','-B',str(CHILD),'--plan',str(PLAN),'--plan-sha256',sha(plan_raw)]"));
 ck("sys_executable_original_launcher",m.includes("sys.executable == PYTHON")&&child.includes("sys.executable == PYTHON"));
 ck("unchanged_absolute_45_25_35",["PARENT_UNTIL_NS = PARENT_START_NS + 45000000000","CHILD_UNTIL_NS = PARENT_START_NS + 25000000000","HELPER_ADMISSION_END_NS = PARENT_START_NS + 35000000000"].every(x=>controller.includes(x)));
 const pr=JSON.parse(peer.raw["result.actual.public.json"]);ck("whole_independent_peer6",peer.audit.tree==="8e6a89181cdbaacd58c7dce06af7a89ed4843e56"&&peer.pins.length===6&&peer.pins.reduce((n,x)=>n+x.bytes,0)===53687&&pr.status==="PASS_NARROW_SOURCE_ONLY"&&pr.NativeCalls===0&&pr.authorVerifierExecuted===false);
 return {schema:"heptabao.root-source-review.Mac-public-home-T5-probe-R4.v1",status:"PASS_MINIMAL_SOURCE_AND_BINDINGS",checks,check_count:checks.length,source_packet:p.audit.tree,original_R3_packet:r3.audit.tree,self_actual_qualification:selfq.blob,independent_peer:peer.audit.tree,source:refs.after.controller,child:refs.after.child,request:refs.after.request,journal:refs.after.journal,native_binding:((b)=>({sha256:b.sha256,native_fingerprint:b.native_fingerprint,typed_stdin:true}))(processStartBinding(q)),source_delta:"One exact kernel image constant and one executable comparison right operand; entire controller, managed child and journal independently reconstruct their original reviewed R3 bytes after reversing only documented binding changes.",scope:{kernel_image_path_observed:true,kernel_image_file_qualified:false,original_R3_missing_fields_reconstructed:false,runtime_qualified:false,AuthBus_credentials_qualified:false,full_replacement:false,production_cutover:false,legacy_cleanup:false},root_Runtime_calls:0};
}