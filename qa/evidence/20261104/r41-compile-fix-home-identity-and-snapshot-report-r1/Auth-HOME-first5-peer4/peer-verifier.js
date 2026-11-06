function verifyHomeOwnCreateFirst5(files,tree) {
 const checks=[],check=(name,ok)=>{checks.push({name,passed:!!ok});if(!ok)throw Error(name);};
 check("tree_exact",tree.sha==="7592e1176e1634cf4b8259f53860ec0bc35786e3");
 const merkle=gitTreeAudit(tree);check("sixteen_leaf_one_Merkle",merkle.leaf_count===16&&merkle.trees_verified===1);
 for(const row of tree.tree.filter(x=>x.type==="blob")) {
  const pin=gitBlobMeta(files[row.path]);
  check("whole_"+row.path,pin.blob===row.sha&&pin.bytes===row.size);
 }
 for(const name of ["home-control","manager","publisher"]) {
  const before=files[name+".before.py"],after=files[name+".after.py"],
    forward=files[name+".forward.diff"],reverse=files[name+".reverse.diff"];
  check(name+"_three_hunks_both_directions",(forward.match(/^@@ /gm)||[]).length===3&&(reverse.match(/^@@ /gm)||[]).length===3);
  check(name+"_strict_forward",snapshotApply(before,forward)===after);
  check(name+"_strict_reverse",snapshotApply(after,reverse)===before);
 }
 const before=files["home-control.before.py"],after=files["home-control.after.py"];
 for(const name of ["manager","publisher"]) {
  check(name+"_contains_exact_helper_before",files[name+".before.py"].includes(before));
  check(name+"_contains_exact_helper_after",files[name+".after.py"].includes(after));
  check(name+"_only_same_helper_replacement",files[name+".before.py"].replace(before,after)===files[name+".after.py"]);
 }
 function methods(raw) {
  const starts=[...raw.matchAll(/^    def (\w+)\(/gm)],out={};
  for(let i=0;i<starts.length;i++)out[starts[i][1]]=raw.slice(starts[i].index,i+1<starts.length?starts[i+1].index:raw.length);
  return out;
 }
 const bm=methods(before),am=methods(after);
 check("same_eighteen_methods",Object.keys(bm).length===18&&JSON.stringify(Object.keys(bm))===JSON.stringify(Object.keys(am)));
 for(const name of Object.keys(bm).filter(x=>!["__init__","write_new","public"].includes(x)))
  check("unchanged_method_"+name,bm[name]===am[name]);
 check("identity_order_first5_object",files["manager.before.py"].includes("return tuple(str(x) for x in (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,\n        s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns))"));
 check("preoperation_full9_unchanged",am.check.includes("file_identity(info)==file_identity(named)==self.root_identity"));
 check("owned_new_regular_single_link_preserved",am.write_new.includes("before.st_nlink==1")&&am.write_new.includes("stat.S_IMODE(before.st_mode)==0o600"));
 check("created_leaf_first6_plus_named_full9_preserved",am.write_new.includes("identity==file_identity(named) and identity[:6]==file_identity(before)[:6]"));
 check("new_root_guard_first5_and_held_named_full9",am.write_new.includes("need(current==named_root and current[:5]==before_root[:5],"));
 check("last_observation_initial_none",am.__init__.includes("self.last_own_create_root_observation=None"));
 const observation=am.write_new.indexOf("self.last_own_create_root_observation={"),
   guard=am.write_new.indexOf("need(current==named_root"),
   update=am.write_new.indexOf("self.root_identity=current"),
   clear=am.write_new.indexOf("self.effect_unknown=False");
 check("diagnostic_record_before_guard",observation>=0&&observation<guard);
 check("root_update_and_effect_known_only_after_guard",guard<update&&update<clear);
 check("all_three_full9_recorded",["'beforeFull9':list(before_root)","'currentFull9':list(current)","'namedFull9':list(named_root)"].every(x=>am.write_new.includes(x)));
 check("field_differences_and_two_predicates_recorded",["'heldNamedFull9Equal':current==named_root","'sameRootObjectFirst5':current[:5]==before_root[:5]","'fieldEqualToBefore':[x==y for x,y in zip(current,before_root)]"].every(x=>am.write_new.includes(x)));
 check("original_fixed_root_and_caps",before.slice(0,before.indexOf("class HomeControl:"))===after.slice(0,after.indexOf("class HomeControl:")));
 check("finally_once_close_remains",am.write_new.slice(am.write_new.indexOf("        finally:"))===bm.write_new.slice(bm.write_new.indexOf("        finally:")));
 check("public_observation_visible_without_erasing_unknown",am.public.includes("'lastOwnCreateRootObservation':self.last_own_create_root_observation")
   &&am.public.includes("'rootCreated':self.root_created,'effectUnknown':self.effect_unknown,"));
 const actual=parseLosslessIntegers(files["original-failure.stdout.public.json"]);
 check("original_failure_UNKNOWN_retained",actual.errorCode==="home_own_create_preserves_root_object"&&actual.outcomeUnknown===true&&actual.ok===false);
 const plan=JSON.parse(files["PLAN.public.json"]);
 check("component_only_no_dispatch_binding",plan.status==="COMPONENT_SOURCE_ONLY_NOT_DISPATCHABLE"&&plan.NativeCalls===0&&plan.actualRootTupleAtOriginalFailure===null);
 return {schema:"heptabao.peer-home-first5-source-checks.v1",passed:true,checks:checks.length,rows:checks,
  source_only:true,PythonCalls:0,NativeCalls:0,syntheticComponentRerun:false};
}
