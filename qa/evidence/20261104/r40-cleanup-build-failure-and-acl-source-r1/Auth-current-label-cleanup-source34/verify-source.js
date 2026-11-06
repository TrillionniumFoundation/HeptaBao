function verifyCleanupSource(input, H) {
  const checks=[];
  const stable=v=>JSON.stringify(v,(_,x)=>x&&typeof x==="object"&&!Array.isArray(x)?Object.fromEntries(Object.keys(x).sort().map(k=>[k,x[k]])):x);
  const ck=(name,value)=>{checks.push({name,pass:value===true});if(value!==true)throw Error("source_check:"+name);};
  const b=input.before,c=input.after;
  const pin=(raw,p)=>{const a=H.pin(raw);return a.blob===p.blob&&a.bytes===p.bytes&&a.sha256===p.sha256;};
  const line=(s,prefix)=>s.split("\n").find(x=>x.startsWith(prefix));
  const main=s=>s.slice(s.indexOf("def main():\n"));
  const topBlock=(s,name)=>{
    const re=new RegExp("^(?:class|def) "+name.replace(/[.*+?^$()|[\]\\]/g,"\\$&")+"(?:\\(|:)","m");
    const m=re.exec(s);if(!m)throw Error("missing_block:"+name);
    const tail=s.slice(m.index),next=/\n(?=(?:class|def) )/.exec(tail);
    return next?tail.slice(0,next.index+1):tail;
  };
  ck("source_pin",pin(c.source,c.sourcePin));
  ck("request_pin",pin(c.request,c.requestPin));
  ck("journal_pin",pin(c.journal,c.journalPin));
  ck("baseline_source_pin",pin(b.source,b.sourcePin));
  ck("baseline_request_pin",pin(b.request,b.requestPin));
  ck("baseline_journal_pin",pin(b.journal,b.journalPin));
  ck("seven_strict_source_hunks",c.diff.hunks===7&&H.apply(b.source,c.diff.raw).raw===c.source);
  ck("seven_strict_source_reverse",c.reverse.hunks===7&&H.apply(c.source,c.reverse.raw).raw===b.source);
  ck("two_strict_journal_hunks",c.jdiff.hunks===2&&H.apply(b.journal,c.jdiff.raw).raw===c.journal);
  ck("two_strict_journal_reverse",c.jreverse.hunks===2&&H.apply(c.journal,c.jreverse.raw).raw===b.journal);
  const afterPrefix=c.source.slice(0,-c.body.length),beforePrefix=b.source.slice(0,-b.body.length);
  const restoredPrefix=afterPrefix.replace(c.constText,"")
    .replace(line(c.source,"PUBLIC_ERROR_CODES = "),line(b.source,"PUBLIC_ERROR_CODES = "))
    .replace('"""One preflight-qualified existing public label; at most one bootout and exact rereads."""',
             '"""One fixed existing public launchd label observation; no registration mutation."""');
  ck("prefix_only_explicit_observed_constants_allowlist_description",restoredPrefix===beforePrefix);
  ck("parent_only_added_control_and_main_replacement",c.body.replace(c.control,"").replace(main(c.body),main(b.body))===b.body);
  for(const name of ["ProcessReader","FixedIO","ReadOnlyControl","parse_print","missing_service",
       "restore_handlers","remaining","load_readonly_helpers","fixed_field_projection",
       "check_leaf_metadata","read_pinned","observe_ready","observe_terminal","safe_commands_public"]) {
    ck("whole_unchanged_"+name,topBlock(c.source,name)===topBlock(b.source,name));
  }
  ck("original_child_validator_source_unchanged",c.source.includes(input.originalValidators)&&b.source.includes(input.originalValidators));
  const q=JSON.parse(c.request),oldq=JSON.parse(b.request);
  ck("request_source_equals_stdin",q.stdin===c.source&&!Object.hasOwn(q,"stdin_text"));
  ck("request_native_other_fields_unchanged",Object.keys(oldq).length===Object.keys(q).length&&
    Object.keys(q).filter(k=>!["stdin","idempotency_key"].includes(k)).every(k=>JSON.stringify(q[k])===JSON.stringify(oldq[k])));
  ck("fresh_key_source_bound",q.idempotency_key==="heptabao-mac-owned-home-t5-close-label-"+c.sourcePin.sha256.slice(0,8)+"-20261106-r1");
  ck("journal_fresh_uninitialized_slot",c.journal.includes('const GF_SLOT = "owner_launchd_home_t5_existing_close_label_gitfirst_r1";')&&input.slotInitialized===false);
  ck("journal_request_pin_exact",c.journal.includes('blob:"'+c.requestPin.blob+'"')&&
    c.journal.includes('bytes:'+c.requestPin.bytes+',sha256:"'+c.requestPin.sha256+'"'));
  ck("journal_prefix_source_exact",c.journal.includes("/^heptabao-mac-owned-home-t5-close-label-"+c.sourcePin.sha256.slice(0,8)+"-/"));
  const r=JSON.parse(input.actualStdout);
  ck("actual_stdout_whole",pin(input.actualStdout,c.observed.priorObservation));
  ck("root_qualification_whole",pin(input.rootQualification,c.observed.rootQualification));
  ck("actual_r3_success_only_scope",r.ok===true&&r.observationComplete===true&&r.outcomeUnknown===false&&
     r.registrationClosureClaimed===false&&r.originalR4ManagedScopeStillUnknown===true&&r.historicalReadonlyR2Helper87650ClosureStillUnknown===true);
  for(const [to,from] of [["readyIdentity",r.ready.identity],["readyFull9",r.ready.full9],
    ["markerFull9",r.ready.markerFull9],["terminalFull9",r.terminal.full9],
    ["stderrFull9",r.managedStderr.full9],["terminalError",r.terminal.public.error]])
    ck("actual_observed_"+to,stable(c.observed[to])===stable(from));
  ck("observation_const_json_exact",JSON.stringify(JSON.parse(c.constText.slice(c.constText.indexOf("r'''")+4,c.constText.lastIndexOf("'''"))))===JSON.stringify(c.observed));
  ck("marker_tuple_type_preserved",c.sequence.includes("result['ready']['markerFull9'] == tuple(CLEANUP_OBSERVED['markerFull9'])")&&
    topBlock(c.source,"FixedIO").includes("return identity(before)")&&
    topBlock(c.source,"FixedIO").includes("return bytes(raw), list(identity(after))"));
  ck("fixed_current_registration_preflight",c.sequence.includes("and all(first['projection']['registrationBinding'].values())")&&
    c.sequence.includes("first_value.get('pid') is None")&&c.sequence.includes("first_value.get('state') == 'not running'")&&
    c.sequence.includes("first_value.get('runs') == 1")&&c.sequence.includes("first_value.get('last exit code') == 1"));
  ck("expired_original_plan_deadlines_before_effect",c.sequence.indexOf("'cleanup_original_child_and_controller_deadlines_elapsed'")<c.sequence.indexOf("control.bootout_once()")&&
    c.sequence.includes("type(plan['childUntilNs']) is int")&&c.sequence.includes("type(plan['controllerUntilNs']) is int"));
  ck("same_closed_failed_terminal_preflight",c.sequence.includes("terminal['ok'] is False")&&
    c.sequence.includes("terminal['stage'] == 'home_admission'")&&c.sequence.includes("terminal['error'] == CLEANUP_OBSERVED['terminalError']")&&
    c.sequence.includes("terminal['outcomeUnknown'] is False")&&c.sequence.includes("terminal['allReturnedApplicationFdsClosed'] is True"));
  ck("exact_one_bootout_body_call",c.body.split("control.bootout_once()").length===2&&c.body.split("['/bin/launchctl','bootout',TARGET]").length===2);
  ck("attempt_flag_precedes_potential_effect",c.control.indexOf("self.bootout_attempted = True")<c.control.indexOf("row,out,err = self.call(")&&
    c.control.includes("not self.bootout_attempted and not self.unknown"));
  ck("known_empty_bootout_required",c.control.includes("row['exitCode'] == 0 and not out and not err")&&
    c.control.indexOf("self.bootout_returned_known = True")>c.control.indexOf("'known_empty_launchd_mutation'"));
  const sequenceTokens=["control.query(1)","observe_ready(io,plan,result)","observe_terminal(io,ready_identity,result)",
    "control.pid_observation(1,ready_identity,reader)","stage = 'pre_bootout_fences'","control.bootout_once()",
    "control.query(2)","control.pid_observation(2,ready_identity,reader)","control.query(3)","stage = 'post_bootout_fences'"];
  let previous=-1;ck("strict_effect_observation_order",sequenceTokens.every(s=>{const n=c.sequence.indexOf(s);if(n<=previous)return false;previous=n;return true;}));
  ck("two_exact_missing_postconditions",c.sequence.includes("need(post_first['registrationAbsent']")&&c.sequence.includes("need(post_second['registrationAbsent']"));
  ck("all_original_caps_unchanged",b.body.slice(0,b.body.indexOf("def main():")).includes("self.calls < 4")&&
    c.body.includes("PARENT_START_NS + 45000000000")&&c.body.includes("PARENT_START_NS + 35000000000")&&
    q.timeout_seconds===60&&c.body.includes("self.command_bytes < 1048576")&&c.body.includes("self.native_calls < 6")&&
    c.body.includes("time.monotonic_ns()+4000000000")&&c.body.includes("read_cap=262144,write_cap=0")&&
    c.body.includes("if len(final_raw) > 65536:"));
  ck("no_cleanup_call_in_finally",!c.body.slice(c.body.indexOf("    finally:\n",c.body.indexOf("def main():"))).includes("bootout_once()"));
  ck("filesystem_read_only_configuration",c.body.includes("io.writable = set()")&&c.body.includes("io.max_writes = 0")&&
    !c.body.includes("io.write(")&&!c.body.includes("io.mkdir("));
  ck("old_scope_unknowns_not_rewritten",c.body.includes("'registrationClosureClaimed':False")&&
    c.body.includes("'originalR4ManagedScopeStillUnknown':True")&&
    c.body.includes("'historicalReadonlyR2Helper87650ClosureStillUnknown':True")&&c.body.includes("'historicalR4Rewritten':False"));
  ck("bootout_possible_termination_disclosed",c.body.includes("'bootoutMayRequestTermination':True"));
  ck("posteffect_failure_unknown",c.newFinish.includes("result['currentRegistrationOutcomeUnknown'] = bool(result['bootoutAttempted']\n            and not result['currentLabelRemovalConfirmed'])")&&
    c.newFinish.includes("or result['currentRegistrationOutcomeUnknown']"));
  ck("final_success_requires_owned_closure_deadline",c.newFinish.includes("and result['observationComplete'] and io_closed and helpers_closed")&&
    c.newFinish.includes("and control is not None and not control.unknown")&&
    c.newFinish.includes("and result['deadlineMetAfterClosure']")&&c.body.includes("and time.monotonic_ns() < PARENT_UNTIL_NS else 1"));
  const errors=s=>JSON.parse(line(s,"PUBLIC_ERROR_CODES = ").slice("PUBLIC_ERROR_CODES = frozenset(".length,-1));
  const oldErrors=errors(b.source),newErrors=errors(c.source),added=newErrors.filter(x=>!oldErrors.includes(x));
  ck("ten_fixed_added_codes_no_removed",added.length===10&&oldErrors.every(x=>newErrors.includes(x))&&added.every(x=>x.startsWith("cleanup_")));
  ck("child_error_allowlist_whole_unchanged",line(b.source,"CHILD_PUBLIC_ERROR_CODES = ")===line(c.source,"CHILD_PUBLIC_ERROR_CODES = "));
  return {schema:"heptabao.cleanup-source-pure-verification.r1",passed:true,check_count:checks.length,checks,
    source:c.sourcePin,request:c.requestPin,journal:c.journalPin,
    nativeCalls:0,pythonOrCandidateExecution:false,rootPermissionCreated:false,
    scope:"Pure V8 mechanical binding/control-flow assertions over the exact candidate, baseline, and already returned public originals; no runtime or product qualification."};
}
