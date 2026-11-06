function verifyKernelImageR4({before,after,selfRaw,pin,strictApply,unbase64,decodeUtf8}) {
 const checks=[];const check=(name,value)=>{checks.push({name,passed:!!value});if(!value)throw new Error(name);};
 const one=(s,a,b)=>{if(s.split(a).length!==2)throw new Error('single_exact_block');return s.replace(a,b);};
 const line=(s,prefix)=>{const a=s.split('\n').filter(l=>l.startsWith(prefix));if(a.length!==1)throw new Error('single_line');return a[0];};
 const eq=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
 const obs=JSON.parse(selfRaw);
 check('exact_fresh_actual_self_stdout',pin(selfRaw).blob==='4e28d3301fa4409b06efe23bd9834779173aaa71');
 check('fresh_self_complete_and_stable',obs.ok&&obs.observationComplete&&!obs.outcomeUnknown&&obs.sameIdentityAndBirthAcrossReads&&obs.selfReadCallsStarted===2&&obs.selfReadCallsReturned===2&&eq(obs.first,obs.second));
 check('actual_only_old_executable_equality_false',Object.entries(obs.first.originalPredicates).every(([k,v])=>v===(k!=='executable_eq_fixed_python')));
 const image=obs.first.publicExecutablePath;
 check('one_actual_kernel_constant',line(after.constants,'KERNEL_PYTHON_IMAGE = ')==='KERNEL_PYTHON_IMAGE = '+JSON.stringify(image));
 check('constants_only_added_observed_literal',one(after.constants,'KERNEL_PYTHON_IMAGE = '+JSON.stringify(image)+'\n','')===before.constants);
 check('common_only_final_executable_operand',one(before.common,"and value['executable'] == PYTHON, 'process_identity_fixed_python')","and value['executable'] == KERNEL_PYTHON_IMAGE, 'process_identity_fixed_python')")===after.common);
 for(const k of ['constants','common']){
  check(k+'_forward_strict',strictApply(before[k],after[k+'Diff']).raw===after[k]);
  check(k+'_reverse_strict',strictApply(after[k],after[k+'Reverse']).raw===before[k]);
 }
 check('base_controller_exact',pin(before.controller).blob==='bf69252fe9a2431ccf09740d5e5bed7eb6231248');
 check('base_child_exact',pin(before.child).blob==='2649636d559f401a5068de2b92ed3bf7d6db7d72');
 check('child_only_constants_common',one(one(before.child,before.constants,after.constants),before.common,after.common)===after.child);
 let controller=one(one(before.controller,before.constants,after.constants),before.common,after.common);
 for(const p of ['CHILD_BASE64 = ','CHILD_BYTES = ','CHILD_SHA = '])
  controller=one(controller,line(before.controller,p),line(after.controller,p));
 check('controller_only_constants_common_derived_child',controller===after.controller);
 const b64=line(after.controller,'CHILD_BASE64 = ').match(/^CHILD_BASE64 = '([A-Za-z0-9+/=]+)'$/);
 check('embedded_child_exact_whole',b64&&decodeUtf8(unbase64(b64[1]))===after.child);
 check('embedded_child_exact_size_sha',line(after.controller,'CHILD_BYTES = ')==='CHILD_BYTES = '+pin(after.child).bytes&&line(after.controller,'CHILD_SHA = ')==="CHILD_SHA = '"+pin(after.child).sha256+"'");
 for(const p of ['MODULES = ','ANCHOR_BASE64 = ','ANCHOR_SHA = '])
  check('preserved_'+p.trim(),line(before.controller,p)===line(after.controller,p));
 const q0=JSON.parse(before.request),q=JSON.parse(after.request);
 check('request_only_stdin_key',eq({...q,stdin:q0.stdin,idempotency_key:q0.idempotency_key},q0));
 check('request_stdin_whole',q.stdin===after.controller&&!Object.hasOwn(q,'stdin_text'));
 check('request_new_source_key',q.idempotency_key==='heptabao-mac-owned-home-t5-probe-'+pin(after.controller).sha256.slice(0,8)+'-20261106-r4');
 check('journal_forward_strict',strictApply(before.journal,after.journalDiff).raw===after.journal);
 check('journal_reverse_strict',strictApply(after.journal,after.journalReverse).raw===before.journal);
 check('journal_functions_unchanged',before.journal.slice(before.journal.indexOf('function gfNeed')).replace('/^heptabao-mac-owned-home-t5-probe-8cfa410c-/','/^heptabao-mac-owned-home-t5-probe-'+pin(after.controller).sha256.slice(0,8)+'-/')===after.journal.slice(after.journal.indexOf('function gfNeed')));
 const oldContract=JSON.parse(before.contract),contract=JSON.parse(after.contract);
 for(const k of ['roots','effects','chronology','ownership','budget','publication','priorEvidence','validation','closureConstructionCorrection'])
  check('unchanged_contract_'+k,eq(oldContract[k],contract[k]));
 check('contract_modules_preserved',eq(oldContract.sourceReuse.modules,contract.sourceReuse.modules));
 check('all_new_exact_pins',eq(contract.exact.controller,pin(after.controller))&&eq(contract.exact.managedProbe,pin(after.child))&&eq(contract.exact.request,pin(after.request))&&eq(contract.exact.journal,pin(after.journal)));
 check('kernel_file_not_qualified_or_read',contract.kernelImageIdentityCorrection.actual.kernelImageFileIdentityOrContentQualified===false&&contract.kernelImageIdentityCorrection.noKernelImageFileRead===true);
 return {schema:'heptabao.public-home-t5-probe.r4-source-binding-checks.v1',passed:true,checkCount:checks.length,checks,PythonExecution:false,NativeCalls:0,oldR3NotReplayed:true,sourceAndExistingPublicDataOnly:true};
}