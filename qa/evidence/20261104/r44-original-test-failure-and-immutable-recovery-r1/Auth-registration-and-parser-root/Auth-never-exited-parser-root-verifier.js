
function qualifyNeverExitedParser(p,originalManager){
 const checks=[],ck=(name,ok)=>checks.push({name,pass:ok===true}),b=p.raw["manager.before.original.py"],a=p.raw["manager.after.candidate.py"],d=p.raw["manager.forward.diff"],r=p.raw["manager.reverse.diff"];
 const bm=gitBlobMeta(b),am=gitBlobMeta(a),forward=strictApply(b,d),reverse=strictApply(a,r);
 ck("whole_SOURCE11",p.audit.tree==="5245358633c2cf458b56578e586840d34fc930d1"&&p.pins.length===11&&p.pins.reduce((s,x)=>s+x.bytes,0)===150649);
 ck("exact_original_manager",bm.blob==="03c8f2e6472a2b52dad789c28bacc28022c87dc0"&&bm.bytes===58452&&b===originalManager);
 ck("exact_after_manager",am.blob==="3f259a4b085394fba0658359575aa0d74b9757e2"&&am.bytes===58584);
 ck("one_hunk_forward_and_reverse",forward.hunks===1&&reverse.hunks===1);
 ck("strict_forward_exact",forward.text===a);ck("strict_reverse_exact",reverse.text===b);
 const extra="            if name=='last exit code' and typed_value=='(never exited)':\n                fields[name]=None\n                continue\n";
 ck("exact_three_line_delta",a.replace(extra,"")===b&&a.split(extra).length===2);
 ck("only_last_exit_literal_branch",extra.includes("name=='last exit code'")&&extra.includes("typed_value=='(never exited)'"));
 ck("not_success_zero_or_false",extra.includes("fields[name]=None")&&!extra.includes("=0")&&!extra.includes("=False"));
 ck("pid_runs_integer_validation_unchanged",a.includes("for name in ('pid','runs','last exit code'):")&&a.includes("need(re.fullmatch(r'-?[0-9]{1,10}',typed_value) is not None,'typed_launchctl_integer')"));
 ck("EX_CONFIG_78_unchanged",a.includes("if name=='last exit code' and typed_value=='78: EX_CONFIG':\n                typed_value='78'"));
 const success="need(state.get('last exit code')==0,'actual_launchd_phase_exit_zero')";
 ck("success_consumer_strict_zero_unchanged",a.split(success).length===2&&b.split(success).length===2);
 ck("all_outside_parser_unchanged",a.slice(a.indexOf("\nclass "))===b.slice(b.indexOf("\nclass "))||a.replace(extra,"")===b);
 const c=p.raw["selected-parser-regression.source.py"];
 ck("component_extracts_only_selected_AST",c.includes("names = {'ManagerRefused', 'need', 'parse_print'}")&&c.includes("predicates.append(copy.deepcopy(node.args[0]))"));
 ck("component_none_cannot_pass_consumer",c.includes("'original_consumer_does_not_accept_none'")&&c.includes("eval(new_final, {}, {'state': after['fields']}) is False"));
 ck("component_retains_numeric_and_rejected_literals",c.includes("('78: EX_CONFIG', 78)")&&c.includes("['(Never exited)', 'never exited', '0: UNKNOWN', '78: EX_CONFIG unexpected']")&&c.includes("'duplicate_exit'"));
 const use=JSON.parse(p.raw["exact22-usage-and-pins.public.json"]);
 ck("source_scan_scope_explicit",use.sourceCount===22&&Object.keys(use.pins).length===22&&use.hits.length===6&&use.hits.every(x=>x.source==="mac_owned_launchd_r3.py"));
 ck("only_original_success_literal_use",b.split("\n").filter(l=>l.includes("last exit code")).length===4&&a.split("\n").filter(l=>l.includes("last exit code")).length===5);
 const observation=JSON.parse(p.raw["fresh-diagnostic.stdout.original.txt"]);
 ck("fresh_observation_supports_literal",observation.prints.length===2&&observation.prints.every(x=>x.projection.fieldFacts["last exit code"].recognizedLiteral==="(never exited)"&&x.projection.fieldFacts.pid.typedInteger===32527));
 return {schema:"heptabao.root.never-exited-parser-SOURCE11-review.r44",passed:checks.every(x=>x.pass),checkCount:checks.length,checks,before:bm,after:am,scope:"mechanical source delta and unchanged strict-zero consumer; no Python or product runtime",pythonComponentExecuted:false,managedScope:"UNKNOWN",credentialCycleSuccess:false,newNativeCalls:0};
}
