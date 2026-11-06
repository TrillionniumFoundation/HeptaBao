function reviewR4(input, h) {
 const f=input.files, refs=JSON.parse(f["REFERENCES.public.json"]), checks=[];
 function ck(name, value, detail=null){checks.push({name,pass:!!value,detail});if(!value)throw Error(name);}
 function eq(a,b){return JSON.stringify(a)===JSON.stringify(b);}
 function pin(s,p){const m=h.gitBlobMeta(s);return m.blob===p.blob&&m.bytes===p.bytes&&m.sha256===p.sha256;}
 function one(s,a,b){ck("one_replacement:"+a.slice(0,52),s.split(a).length===2);return s.replace(a,b);}
 function apply(base,diff){
  const b=base.split("\n"),d=diff.split("\n");ck("strict_terminal_LF",b.pop()===""&&d.pop()==="");
  ck("strict_header",d[0].startsWith("--- ")&&d[1].startsWith("+++ "));
  let i=2,pos=0,n=0,out=[];
  while(i<d.length){let m=/^@@ -(\d+),(\d+) \+(\d+),(\d+) @@$/.exec(d[i++]);ck("strict_hunk_header",!!m);
   const st=+m[1]-1;ck("strict_order",st>=pos);out.push(...b.slice(pos,st));pos=st;
   ck("strict_new_offset",out.length===+m[3]-1);
   let old=0,neo=0;while(i<d.length&&!d[i].startsWith("@@ ")){const ln=d[i++],sign=ln[0],s=ln.slice(1);ck("strict_sign",[" ","+","-"].includes(sign));if(sign!=="+"){ck("strict_original_line",b[pos++]===s);old++;}if(sign!=="-"){out.push(s);neo++;}}
   ck("strict_counts",old===+m[2]&&neo===+m[4]);n++;
  }
  out.push(...b.slice(pos));return {raw:out.join("\n")+"\n",hunks:n};
 }
 for(const r of input.whole){ck("whole:"+r.path,pin(f[r.path],r));}
 for(const [n,c] of [["constants",1],["common",1],["journal",2]]){
  const before=f[n+".r3.original."+ (n==="journal"?"js":"py")],after=f[n+".r4."+(n==="journal"?"js":"py")];
  for(const [a,b,d]of[[before,after,f[n+".forward.diff"]],[after,before,f[n+".reverse.diff"]]]){
   const r=apply(a,d);ck("strict_whole:"+n,r.raw===b&&r.hunks===c);
  }
 }
 const beforeC=f["constants.r3.original.py"],afterC=f["constants.r4.py"];
 const imageLine=afterC.split("\n").find(x=>x.startsWith("KERNEL_PYTHON_IMAGE = "));
 const image=JSON.parse(imageLine.slice(imageLine.indexOf("=")+1).trim());
 const launcher=/^PYTHON = '([^']+)'$/m.exec(afterC)[1];
 ck("sole_constant_added",one(afterC,imageLine+"\n","")===beforeC);
 ck("kernel_image_fresh_exact",image!==launcher);
 ck("common_single_operand",one(f["common.r4.py"],"== KERNEL_PYTHON_IMAGE","== PYTHON")===f["common.r3.original.py"]);
 const child=f["managed-probe.r4.py"],controller=f["controller.r4.py"];
 const oldChild=one(one(child,afterC,beforeC),f["common.r4.py"],f["common.r3.original.py"]);
 ck("child_whole_rebuilt_R3",pin(oldChild,refs.before.child));
 let oldController=one(one(controller,afterC,beforeC),f["common.r4.py"],f["common.r3.original.py"]);
 const enc=/^CHILD_BASE64 = '([^']+)'$/m.exec(controller)[1];
 ck("embedded_child_whole",h.utf8Text(h.unb64(enc))===child);
 oldController=one(oldController,enc,h.encodeBase64Bytes(h.utf8Bytes(oldChild)));
 oldController=one(oldController,"CHILD_BYTES = "+refs.after.child.bytes,"CHILD_BYTES = "+refs.before.child.bytes);
 oldController=one(oldController,"CHILD_SHA = '"+refs.after.child.sha256+"'","CHILD_SHA = '"+refs.before.child.sha256+"'");
 ck("controller_whole_rebuilt_R3",pin(oldController,refs.before.controller));
 const manifest=JSON.parse(f["R3.manifest.original.json"]);
 const core="\n"+controller.slice(controller.indexOf("PARENT_START_NS = "));
 ck("parent_core_original_full_pin",pin(core,manifest.entries.find(x=>x.path==="controller-core.r3.py")));
 for(const [key,word]of[["constants","constants.r4.py"],["common","common.r4.py"],["controller","controller.r4.py"],["child","managed-probe.r4.py"],["request","request.r4.json"],["journal","journal.r4.js"]]) ck("after_pin:"+key,pin(f[word],refs.after[key]));
 const main=controller.slice(controller.indexOf("def main():"));
 ck("absence_home_work_before_mkdir",main.indexOf("io.absent(HOME)")<main.indexOf("io.mkdir(HOME)")&&main.indexOf("io.absent(WORK)")<main.indexOf("io.mkdir(HOME)"));
 ck("absence_label_before_mkdir",main.indexOf("need(temporary.query(expect_binding=False) is None, 'fresh_label_initially_absent')")<main.indexOf("io.mkdir(HOME)"));
 ck("fixed_file_identity_not_replaced",main.includes("io.read(Path(PYTHON), expected=PYTHON_ID)")&&main.includes("sha(raw) == PYTHON_SHA"));
 ck("launchd_original_python_9argv",main.includes("argv = [PYTHON,'-I','-S','-B',str(CHILD),'--plan',str(PLAN),'--plan-sha256',sha(plan_raw)]"));
 ck("original_system_executable",main.includes("sys.executable == PYTHON")&&child.includes("sys.executable == PYTHON"));
 ck("fixed_close_all_critical",f["common.r4.py"].includes("def close(self):\n        with self.signals.critical():\n            for row in reversed(self.rows):\n                self.close_one(row)"));
 ck("kernel_occurrences_only_constant_operand",controller.split("KERNEL_PYTHON_IMAGE").length===3&&child.split("KERNEL_PYTHON_IMAGE").length===3);
 for(const bound of ["PARENT_UNTIL_NS = PARENT_START_NS + 45000000000","CHILD_UNTIL_NS = PARENT_START_NS + 25000000000","HELPER_ADMISSION_END_NS = PARENT_START_NS + 35000000000"])ck("deadline:"+bound,controller.includes(bound));
 const q=JSON.parse(f["request.r4.json"]);
 ck("exact_native_envelope",eq(Object.keys(q).sort(),["args","cwd","executable","host","idempotency_key","stdin","timeout_seconds"])&&q.host==="mac"&&q.executable===launcher&&eq(q.args,["-I","-S","-B","-"])&&q.cwd==="/Users/qianqi"&&q.timeout_seconds===60&&q.stdin===controller);
 ck("source_bound_key",q.idempotency_key==="heptabao-mac-owned-home-t5-probe-87ddc495-20261106-r4");
 let journal=f["journal.r4.js"];
 for(const [a,b]of[["owner_launchd_home_t5_probe_gitfirst_r4","owner_launchd_home_t5_probe_gitfirst_r3"],[refs.after.request.blob,refs.before.request.blob],[String(refs.after.request.bytes),String(refs.before.request.bytes)],[refs.after.request.sha256,refs.before.request.sha256],["heptabao-mac-owned-home-t5-probe-87ddc495-","heptabao-mac-owned-home-t5-probe-8cfa410c-"]])journal=one(journal,a,b);
 ck("journal_only_bindings",journal===f["journal.r3.original.js"]);
 const contract=JSON.parse(f["CONTRACT.r4.json"]),oldContract=JSON.parse(f["CONTRACT.r3.original.json"]);
 ck("budgets_whole_same",eq(contract.budget,oldContract.budget));
 ck("roots_whole_same",eq(contract.roots,oldContract.roots));
 ck("contract_request_bind",pin(f["request.r4.json"],contract.exact.request));
 const self=JSON.parse(f["self.stdout.original.json"]);
 ck("freshself_reader_original",self.originalReaderSourceBlob==="6ca7a8debfe9d9a31d19d1237ca3e84176cc40f5");
 for(const row of [self.first,self.second]){ck("fresh_exact_kernel_path",row.publicExecutablePath===image);ck("fresh_five_numeric_predicates",Object.entries(row.originalPredicates).filter(([k])=>k!=="executable_eq_fixed_python").length===5&&Object.entries(row.originalPredicates).filter(([k])=>k!=="executable_eq_fixed_python").every(([,v])=>v===true));ck("fresh_original_eq_false",row.originalPredicates.executable_eq_fixed_python===false);}
 ck("fresh_same_numeric",eq(self.first.numeric,self.second.numeric));
 ck("fresh_launcher_separate",self.declaredLauncher===launcher&&self.sysExecutableEqualsFixedLauncher===true);
 ck("fresh_kernel_file_not_qualified",self.kernelExecutableFileIdentityOrContentQualified===false);
 return {schema:"heptabao.independent.public-home-t5-r4-source-peer.r1",status:"PASS_NARROW_SOURCE_ONLY",checks:checks.length,results:checks,tree:input.tree,sourceChanges:{constantsHunks:1,commonHunks:1,journalHunks:2},reconstructedOriginals:{controller:h.gitBlobMeta(oldController),child:h.gitBlobMeta(oldChild),parentCore:h.gitBlobMeta(core)},NativeCalls:0,PythonExecutions:0,authorVerifierExecuted:false,scope:"Exact R4 delta and binding; no runtime, old R3 cause, kernel-file identity, managed launch success, credentials or product qualification."};
}