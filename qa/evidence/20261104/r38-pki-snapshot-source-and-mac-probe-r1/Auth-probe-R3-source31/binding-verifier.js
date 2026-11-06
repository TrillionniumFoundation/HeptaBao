function verifyProbeR3Binding({r2,r3,pin,strictApply,unbase64,decodeUtf8}) {
 const checks=[];
 const check=(name,value)=>{checks.push({name,passed:Boolean(value)});if(!value)throw new Error(name);};
 const one=(s,a,b)=>{if(s.split(a).length!==2)throw new Error('not_unique_reconstruction');return s.replace(a,b);};
 const f=(s,prefix)=>{const a=s.split('\n').filter(x=>x.startsWith(prefix));if(a.length!==1)throw new Error('one_literal_line');return a[0];};
 const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
 const bc=r2['fixed-io.r2.py'],ac=r3['fixed-io.r3.py'];
 const bp=r2['controller-core.r2.py'],ap=r3['controller-core.r3.py'];
 check('base_common_exact',pin(bc).blob==='19c9b321dd4c3e9b3e85dc8607bb2d1f3e997f11');
 check('base_parent_core_exact',pin(bp).blob==='1c9ebc874ac92c41cdc9de3bf27cb9e5e55bc7c1');
 check('common_forward_exact',strictApply(bc,r3['fixed-io.r2-r3.diff']).raw===ac);
 check('common_inverse_exact',strictApply(ac,r3['fixed-io.r3-r2.diff']).raw===bc);
 check('parent_forward_exact',strictApply(bp,r3['controller-core.r2-r3.diff']).raw===ap);
 check('parent_inverse_exact',strictApply(ap,r3['controller-core.r3-r2.diff']).raw===bp);
 check('entire_close_loop_critical_only',one(bc,
  "    def close(self):\n        for row in reversed(self.rows):\n            self.close_one(row)\n",
  "    def close(self):\n        with self.signals.critical():\n            for row in reversed(self.rows):\n                self.close_one(row)\n")===ac);
 const oldController=r2['controller.r2.py'],newController=r3['controller.r3.py'];
 const oldChild=r2['managed-probe.r2.py'],newChild=r3['managed-probe.r3.py'];
 check('base_controller_exact',pin(oldController).blob==='b50c5755c364ffdafed997e5f4f4362292d14b21');
 check('base_child_exact',pin(oldChild).blob==='27f07eda5bdec7d5581ee524d4fc157dad1e1cd7');
 check('child_only_shared_close_loop',one(oldChild,bc,ac)===newChild);
 let rebuilt=one(one(oldController,bc,ac),bp,ap);
 for(const prefix of ["CHILD_BASE64 = ","CHILD_BYTES = ","CHILD_SHA = "])
  rebuilt=one(rebuilt,f(oldController,prefix),f(newController,prefix));
 check('controller_only_core_common_child_pins',rebuilt===newController);
 const embedded=f(newController,"CHILD_BASE64 = ").match(/^CHILD_BASE64 = '([A-Za-z0-9+/=]+)'$/);
 check('embedded_child_full_byte_equal',embedded&&decodeUtf8(unbase64(embedded[1]))===newChild);
 check('embedded_child_size',f(newController,"CHILD_BYTES = ")==='CHILD_BYTES = '+pin(newChild).bytes);
 check('embedded_child_sha',f(newController,"CHILD_SHA = ")==="CHILD_SHA = '"+pin(newChild).sha256+"'");
 const oldRequest=JSON.parse(r2['request.r2.json']),q=JSON.parse(r3['request.r3.json']);
 check('request_stdin_exact',q.stdin===newController&&!Object.hasOwn(q,'stdin_text'));
 check('request_only_source_key',same({...q,stdin:oldRequest.stdin,idempotency_key:oldRequest.idempotency_key},oldRequest));
 check('key_exact_new_source',q.idempotency_key==='heptabao-mac-owned-home-t5-probe-'+pin(newController).sha256.slice(0,8)+'-20261106-r3');
 const bj=r2['journal.r2.js'],aj=r3['journal.r3.js'];
 check('journal_forward_exact',strictApply(bj,r3['journal.r2-r3.diff']).raw===aj);
 check('journal_inverse_exact',strictApply(aj,r3['journal.r3-r2.diff']).raw===bj);
 check('journal_function_bodies_exact',bj.slice(bj.indexOf('function gfNeed')).replace(
  '/^heptabao-mac-owned-home-t5-probe-7b73f40e-/',
  '/^heptabao-mac-owned-home-t5-probe-'+pin(newController).sha256.slice(0,8)+'-/')===aj.slice(aj.indexOf('function gfNeed')));
 const reqPin=pin(r3['request.r3.json']);
 check('journal_request_pin_exact',aj.includes('blob:"'+reqPin.blob+'"')&&aj.includes('bytes:'+reqPin.bytes+',sha256:"'+reqPin.sha256+'"'));
 const oldContract=JSON.parse(r2['CONTRACT.r2.json']),contract=JSON.parse(r3['CONTRACT.r3.json']);
 for(const k of ['roots','effects','chronology','ownership','budget','publication','priorEvidence','validation'])
  check('contract_preserved_'+k,same(contract[k],oldContract[k]));
 check('contract_source_helper_pins_unchanged',same(contract.sourceReuse.modules,oldContract.sourceReuse.modules));
 check('contract_exact_new_sources',same(contract.exact.controller,pin(newController))&&same(contract.exact.managedProbe,pin(newChild))&&same(contract.exact.request,reqPin)&&same(contract.exact.journal,pin(aj)));
 check('guard_started_before_new',ap.indexOf('guard_init_started = True')<ap.indexOf('guard = HeldT5.__new__'));
 check('guard_complete_after_init',ap.includes('                       remaining, signals.critical)\n        guard_init_complete = True\n'));
 check('incomplete_guard_cannot_close',ap.includes('volume_closed = (not guard_init_started or (guard_init_complete\n            and guard is not None'));
 check('unknown_formula_unchanged',f(ap,"        result['outcomeUnknown'] = ")===f(bp,"        result['outcomeUnknown'] = "));
 check('guard_close_original_scope',ap.slice(ap.indexOf("        if guard is not None and hasattr(guard,'rows'):"),
  ap.indexOf("        if io is not None:",ap.indexOf("        if guard is not None and hasattr(guard,'rows'):")) )===
  bp.slice(bp.indexOf("        if guard is not None and hasattr(guard,'rows'):"),
  bp.indexOf("        if io is not None:",bp.indexOf("        if guard is not None and hasattr(guard,'rows'):"))));
 return {schema:'heptabao.public-home-t5-probe.r3-source-binding-checks.v1',
  passed:checks.every(x=>x.passed),checkCount:checks.length,checks,
  PythonCompileOrCandidateExecution:false,NativeCalls:0,FDOrSignalFaultInjection:false,
  originalR1ChecksNotRerun:true,R2LedgerChecksNotRerun:true,
  scope:'Strict source reconstruction and literal binding only. No probe execution or ownership qualification.'};
}