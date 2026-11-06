function qualifyAuthPythonIdentityComponents(){
 const p=load("r34_packet_Auth-launcher-kernel-three-fixes-source22"),r=p.raw,plan=JSON.parse(r["PLAN.public.json"]),checks=[],ck=(name,v)=>{checks.push({name,passed:v===true});if(v!==true)throw Error(name)},eq=(s,p)=>{const m=gitBlobMeta(s);return m.blob===p.blob&&m.bytes===p.bytes&&m.sha256===p.sha256};
 const launcher="/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14",kernel="/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/Resources/Python.app/Contents/MacOS/Python";
 ck("whole22_294884",p.audit.whole===true&&p.audit.files===22&&p.audit.bytes===294884);
 const defs=t=>Array.from(t.matchAll(/^(?:def|class) [^\n]+/gm),m=>m[0]);
 const edits=[
  [["        need(actual_python==python_runtime,'same_actual_synthetic_python_for_wrappers')","        need(actual_python==python_runtime and actual_python['path']==PYTHON_LAUNCHER,\n             'same_actual_synthetic_python_for_wrappers')"],["                 and observed['executable']==self.python_runtime['path'],","                 and observed['executable']==PYTHON_KERNEL_IMAGE,"]],
  [["             and self_identity['executable']==str(Path(sys.executable).resolve()),","             and self_identity['executable']==PYTHON_KERNEL_IMAGE\n             and str(Path(sys.executable).resolve())==PYTHON_LAUNCHER,"]],
  [["        need(self_identity['uid']==501 and self_identity['executable']==str(Path(sys.executable).resolve()),","        need(self_identity['uid']==501 and self_identity['executable']==PYTHON_KERNEL_IMAGE\n             and str(Path(sys.executable).resolve())==PYTHON_LAUNCHER,"]]
 ];
 for(let i=0;i<3;i++){
  const c=plan.completedSource.kernelIdentityThreeFiles[i],b=r[c.file+".before"],a=r[c.file+".identity-candidate"],fd=r[c.file+".forward.diff"],rd=r[c.file+".reverse.diff"];
  ck(c.file+"_whole_before_after",eq(b,c.before)&&eq(a,c.after));
  const f= strictApply(b,fd), rev=strictApply(a,rd);
  ck(c.file+"_strict_forward_reverse",f.text===a&&rev.text===b&&f.hunks===c.hunks&&rev.hunks===c.hunks&&c.hunks===(i===0?3:2));
  ck(c.file+"_exact_two_constants",a.split("PYTHON_LAUNCHER = ").length===2&&a.split("PYTHON_KERNEL_IMAGE = ").length===2&&a.includes('PYTHON_LAUNCHER = "'+launcher+'"')&&a.includes('PYTHON_KERNEL_IMAGE = "'+kernel+'"'));
  let expected=b;
  for(const [old,next]of edits[i]){ck(c.file+"_unique_original_identity_"+old.slice(0,20),expected.split(old).length===2);expected=expected.replace(old,next);}
  const constant='PYTHON_LAUNCHER = "'+launcher+'"\nPYTHON_KERNEL_IMAGE = "'+kernel+'"\n';
  ck(c.file+"_only_declared_identity_edits",a.replace(constant,"")===expected);
  ck(c.file+"_definitions_unchanged",JSON.stringify(defs(a))===JSON.stringify(defs(b)));
 }
 const outer=r["reference.outer.complete.unchanged.py"],oldq=load("r40_auth_libproc_r3_actual_qualification");
 ck("whole_outer_unchanged_original",eq(outer,plan.completedSource.outerUntouched)&&plan.completedSource.outerUntouched.blob==="12a6fa7a0432281246b36915f1b4b5cd5cd5b400");
 ck("actual_R3_root_and_stdout_references_exact",eq(r["reference.r3.root-qualification.json"],oldq)&&eq(r["reference.actual-r3-observation.json"],load("r40_auth_libproc_r3_actual_report")));
 ck("reviewed_exit78_parser_pin",eq(r["reference.reviewed-exit78-parser.py"],plan.completedSource.fixedExit78Parser.pin)&&plan.completedSource.fixedExit78Parser.pin.blob==="67eebb1703023041fe375a6313bb5f1506c5c0b5");
 ck("component_only_not_dispatchable",plan.proposedFreshBinding.componentSourcesStillContainOriginalBinding===true&&plan.proposedFreshBinding.executionBindingReady===false&&plan.proposedFreshBinding.existsObserved===false&&plan.proposedFreshBinding.mandatoryCreateOnly===true&&plan.proposedFreshBinding.fallbackPathsAllowed===false);
 ck("no_claim_old_failure_cause_or_kernel_file",plan.actualLimits.kernelImageWholeFileQualification===false&&plan.actualLimits.kernelIdentityFixIsOriginalEXCONFIGCause===false&&plan.actualLimits.newProbeT5EntryObserved===false&&plan.actualLimits.newProbeAdmissionCompleted===false&&plan.actualLimits.historicalR4ManagedClosed===false&&plan.actualLimits.historical87650Reaped===false&&plan.actualLimits.oldAuthBusLabelClosed===false);
 const author=JSON.parse(r["source-checks.actual.public.json"]);
 ck("author25_SOURCE_not_compiled",author.passed===true&&author.check_count===25&&author.checks.length===25&&author.checks.every(x=>x.pass===true)&&author.nativeCalls===0&&author.pythonCandidateExecution===false&&author.fullWorkerCandidate===false&&author.stageOrExecutionGO===false);
 return {schema:"heptabao.root-source-review.Mac-python-launcher-kernel-components.v1",status:"PASS_NARROW_SOURCE_COMPONENTS_ONLY",checks,check_count:checks.length,packet:p.audit,component_pins:plan.completedSource.kernelIdentityThreeFiles,launcher_path:launcher,kernel_image_observed_string:kernel,outer_unchanged:plan.completedSource.outerUntouched,scope:"Three exact launcher-versus-kernel-image comparisons; retained independent launcher qualification and original birth/UID/PGID checks",limits:["Component sources still use the original T5 root and labels; this is not a dispatchable fresh HOME/T5 candidate.","Kernel image is an observed process pathname only; its file body was not qualified.","This correction is not established as the cause of the original EX_CONFIG78 failure.","No Python compile, AuthBus execution, credential validation or production cutover follows from source review."],complete_AuthBus_candidate:false,execution_authorized:false,AuthBus_credentials_qualified:false,full_replacement:false,production_cutover:false,legacy_cleanup:false,root_Runtime_calls:0};
}
