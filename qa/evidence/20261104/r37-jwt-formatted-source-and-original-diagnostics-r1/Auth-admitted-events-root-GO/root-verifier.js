
function reviewAuthAdmittedEvents(){
 const p=load("r34_packet_Auth-fixed-log-events-source"),r=p.raw,prior=load("r34_packet_Auth-fixed-log-schema-source"),c=JSON.parse(r["CONTRACT.public.json"]),b=r["source.before.py"],a=r["source.after.py"],checks=[];
 const ck=(name,v)=>{checks.push({name,passed:v===true});if(v!==true)throw Error(name);},same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
 function def(s,n){const l=s.split("\n"),i=l.findIndex(x=>x.startsWith("def "+n+"("));if(i<0)throw Error(n);let e=i+1;while(e<l.length&&!/^(?:def |class |if __name__)/.test(l[e]))e++;return l.slice(i,e).join("\n");}
 ck("whole21_338559_bytes",p.audit.whole&&p.audit.files===21&&p.audit.bytes===338559);
 ck("exact_prior_source_and_new_pins",b===prior.raw["source.after.py"]&&same(gitBlobMeta(a),c.source)&&same(gitBlobMeta(r["request.exact.json"]),c.request)&&same(gitBlobMeta(r["journal.after.js"]),c.journal));
 const fw=strictApply(b,r["source.diff"]),rv=strictApply(a,r["source.inverse.diff"]);
 ck("strict_four_source_hunks_both_directions",fw.text===a&&rv.text===b&&fw.hunks===4&&rv.hunks===4);
 const names=[...b.matchAll(/^def (\w+)\(/gm)].map(x=>x[1]).filter(n=>n!=="main");
 ck("all18_old_nonmain_definitions_exact",names.length===18&&names.every(n=>def(a,n)===def(b,n)));
 ck("all_original_globals_embedded_helpers_budgets_exact",b.slice(0,b.indexOf("class HelpRefused")).split("\n").slice(2).join("\n")===a.slice(0,a.indexOf("class HelpRefused")).split("\n").slice(2).join("\n"));
 ck("main_only_public_schema_and_projection_call",def(a,"main").replace("heptabao.mac-owned-launchd-admitted-log-events.r1","heptabao.mac-owned-launchd-fixed-log-schema.r1").replace("result['logEventObservation'] = log_admitted_event_projection(out, err, row)","result['logSchemaObservation'] = log_schema_projection(out, err, row)")===def(b,"main"));
 const q=JSON.parse(r["request.exact.json"]),oq=JSON.parse(r["request.before.json"]),nq={...q},noq={...oq};
 for(const k of ["stdin","idempotency_key"]){delete nq[k];delete noq[k];}
 ck("request_same_outer_regular_python_new_exact_stdin_key",q.stdin===a&&!("stdin_text" in q)&&same(nq,noq)&&q.idempotency_key===c.key&&c.key==="heptabao-mac-owned-launchd-log-events-398136a3-20261106-r1");
 const j=r["journal.after.js"],oj=r["journal.before.js"],jfw=strictApply(oj,r["journal.diff"]),jrv=strictApply(j,r["journal.inverse.diff"]),old=JSON.parse(prior.raw["CONTRACT.public.json"]);
 ck("strict_two_journal_hunks_exact_previous",oj===prior.raw["journal.after.js"]&&jfw.text===j&&jrv.text===oj&&jfw.hunks===2&&jrv.hunks===2);
 const normalized=j.replace(c.slot,old.slot).replace(c.request.blob,old.request.blob).replace("bytes:"+c.request.bytes+",sha256:","bytes:"+old.request.bytes+",sha256:").replace(c.request.sha256,old.request.sha256).replace("heptabao-mac-owned-launchd-log-events-398136a3-","heptabao-mac-owned-launchd-log-schema-9e7f2f71-");
 ck("journal_only_new_slot_pin_prefix",normalized===oj&&c.slot==="owner_launchd_log_events_gitfirst_r1");
 const f=def(a,"log_admitted_event_projection");
 ck("strict_complete_object_parse_before_semantic_catch",f.indexOf("need(type(item) is dict, 'log_record_object')")<f.indexOf("        try:")&&f.includes("object_pairs_hook=unique_log_object")&&f.includes("parse_constant=lambda _value: need(False, 'finite_log_json')"));
 ck("original_complete_line_classifier_only",f.includes("projected = log_projection(line_bytes + b'\\n', err, row)")&&f.includes("event = dict(projected['rows'][0])")&&f.includes("event['ordinal'] = ordinal"));
 const allowed=["one_log_message_semantics","exact_original_label_in_message","typed_log_process","typed_log_process_path","exact_launchd_process","typed_log_timestamp","log_timestamp_timezone_required","original_three_second_log_window"];
 const block=f.slice(f.indexOf("semantic_refusals = frozenset(("),f.indexOf("    events = []"));
 ck("only_eight_original_semantic_refusals",same([...block.matchAll(/'([^']+)'/g)].map(x=>x[1]),allowed)&&f.includes("if len(error.args) != 1 or error.args[0] not in semantic_refusals:\n                raise"));
 ck("finite_timestamp_failure_no_raw_exception",f.includes("except (ValueError, OverflowError):")&&f.includes("rejection = 'invalid_log_timestamp_value'")&&!f.includes("str(error)")&&!f.includes("repr("));
 ck("hard_caps_deadline_cancellation_not_changed",f.includes("len(out) + len(err) <= MAX_LOG_STREAM")&&f.includes("len(lines) <= MAX_LOG_ROWS")&&f.includes("len(line_bytes) <= MAX_LOG_LINE")&&!block.includes("deadline")&&!block.includes("cancel")&&f.match(/remaining\(\)/g).length===2);
 ck("every_ordinal_explicit_disposition",f.includes("len(events) + len(rejected) == len(lines)")&&f.includes("rejected.append({'ordinal': ordinal, 'rejectionReason': rejection,")&&f.includes("'meaning': 'unknown_object_not_admitted'")&&f.includes("'observedObjects': len(lines)")&&f.includes("'admittedEvents': len(events)")&&f.includes("'rejectedUnknownObjects': len(rejected)"));
 ck("no_whole_log_or_cause_qualification",f.includes("'wholeLogFullyClassified': False")&&f.includes("'unknownObjectSemanticsQualified': False")&&f.includes("'startupCauseQualified': False")&&f.includes("'freshObservationNotOriginal817ByteRecovery': True")&&f.includes("'originalWholeQueryFailureUnchanged': True"));
 ck("no_new_IO_or_raw_projection",!/\b(?:open|Popen|run|kill|killpg|read|write|stat|lstat)\s*\(/.test(f)&&f.includes("'rawLogTextExported': False")&&f.includes("'rawOrUnknownLogHashExported': False")&&f.includes("'unknownKeyNamesPublished': False")&&f.includes("'arbitraryFieldValuesPublished': False"));
 ck("qualified_prior_schema_and_exact_scope",c.priorSchemaActual.rootQualification.blob===load("r37_auth_log_schema_actual_qualification").blob&&same(c.exactArgv,load("r37_auth_fixed_log_schema_GO").value.scope.exact_child_argv)&&same(c.timeWindow,load("r37_auth_fixed_log_schema_GO").value.scope.original_time_evidence));
 const binding=processStartBinding(q);
 return {schema:"heptabao.root-Mac-individually-admitted-log-events-source-review.v1",status:"PASS_SOURCE_ONLY",source_packet:p.audit.tree,checks_passed:checks.length,checks,source:c.source,request:c.request,journal:c.journal,native_binding:{sha256:binding.sha256,native_fingerprint:binding.native_fingerprint,typed_stdin_field:"stdin"},manual_exception_review:"The same original line passes strict JSON parsing before the catch. In the unchanged classifier the remaining ValueError/OverflowError path is datetime parsing/conversion; only its fixed reason is exposed. Deadline/cancellation are unlisted HelpRefused and propagate.",python_compiled:false,python_or_component_executed:false,root_Runtime_calls:0};
}