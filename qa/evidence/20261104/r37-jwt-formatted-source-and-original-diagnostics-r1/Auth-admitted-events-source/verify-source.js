function verifyAdmittedEventsSource(c) {
 const checks=[];function check(value,name){checks.push({name,passed:!!value});if(!value)throw Error(name);}
 function definition(source,name){const a=source.split("\n"),i=a.findIndex(x=>x.startsWith("def "+name+"("));if(i<0)throw Error("missing_definition_"+name);let j=i+1;while(j<a.length&&!/^(def |class |if __name__)/.test(a[j]))j++;return a.slice(i,j).join("\n");}
 check(strictApplySource(c.before,c.diff.raw).raw===c.after,"source_strict_forward");
 check(strictApplySource(c.after,c.inverse.raw).raw===c.before,"source_strict_reverse");
 check(strictApplySource(c.journalBefore,c.jdiff.raw).raw===c.journal,"journal_strict_forward");
 check(strictApplySource(c.journal,c.jinv.raw).raw===c.journalBefore,"journal_strict_reverse");
 const helpers=["need","sha","identity","remaining","public_error","load_helpers","metadata","admit_binding","open_fixed","verify_all","hash_tool","unique_log_object","log_timestamp_us","log_projection","known_json_type","log_schema_projection","command_public","close_rows"];
 for(const name of helpers)check(definition(c.before,name)===definition(c.after,name),"unchanged_definition_"+name);
 const priorMain=definition(c.before,"main"),nextMain=definition(c.after,"main").replace("'heptabao.mac-owned-launchd-admitted-log-events.r1'","'heptabao.mac-owned-launchd-fixed-log-schema.r1'").replace("result['logEventObservation'] = log_admitted_event_projection(out, err, row)","result['logSchemaObservation'] = log_schema_projection(out, err, row)");
 check(priorMain===nextMain,"main_only_schema_and_projection_call");
 check(c.before.slice(0,c.before.indexOf("class HelpRefused")).split("\n").slice(2).join("\n")===c.after.slice(0,c.after.indexOf("class HelpRefused")).split("\n").slice(2).join("\n"),"all_original_globals_embedded_helpers_caps_same");
 const a=JSON.parse(c.requestBefore),b=JSON.parse(c.requestRaw);
 check(a.stdin===c.before&&b.stdin===c.after,"stdin_exact_source");
 delete a.stdin;delete b.stdin;delete a.idempotency_key;delete b.idempotency_key;
 check(JSON.stringify(a)===JSON.stringify(b),"request_only_source_and_key");
 check(gitBlobMeta(c.after).blob===c.sourcePin.blob&&gitBlobMeta(c.requestRaw).blob===c.requestPin.blob&&gitBlobMeta(c.journal).blob===c.journalPin.blob,"whole_candidate_pins");
 const fn=definition(c.after,"log_admitted_event_projection");
 check(fn.includes("projected = log_projection(line_bytes + b'\\n', err, row)"),"original_line_bytes_to_unchanged_classifier");
 check(fn.indexOf("need(type(item) is dict, 'log_record_object')")<fn.indexOf("        try:"),"strict_json_outside_semantic_catch");
 check(fn.includes("if len(error.args) != 1 or error.args[0] not in semantic_refusals:\n                raise"),"only_closed_semantic_codes_caught");
 check(!fn.includes("'log_help_cancelled'")&&!fn.includes("'log_help_original_deadline'"),"cancellation_deadline_not_caught_as_unknown_row");
 check(fn.includes("except (ValueError, OverflowError):")&&fn.includes("rejection = 'invalid_log_timestamp_value'"),"timestamp_value_error_fixed_projection");
 check(fn.includes("'observedObjects': len(lines)")&&fn.includes("'admittedEvents': len(events)")&&fn.includes("'rejectedUnknownObjects': len(rejected)"),"three_distinct_observation_counts");
 check(fn.includes("len(events) + len(rejected) == len(lines)")&&fn.includes("event['ordinal'] = ordinal")&&fn.includes("rejected.append({'ordinal': ordinal"),"every_original_ordinal_preserved");
 check(fn.includes("'wholeLogFullyClassified': False")&&fn.includes("'unknownObjectSemanticsQualified': False")&&fn.includes("'startupCauseQualified': False"),"no_complete_classification_or_cause");
 check(fn.includes("'rawLogTextExported': False")&&fn.includes("'rawOrUnknownLogHashExported': False")&&fn.includes("'unknownKeyNamesPublished': False"),"no_raw_unknown_projection");
 check(fn.includes("'originalWholeQueryFailureUnchanged': True")&&fn.includes("'freshObservationNotOriginal817ByteRecovery': True"),"old_failure_not_rewritten");
 check(!/\b(?:open|Popen|run|kill|killpg|read|write|stat|lstat)\s*\(/.test(fn),"new_function_no_io_or_process");
 check(fn.includes("need(len(lines) <= MAX_LOG_ROWS")&&fn.includes("need(len(line_bytes) <= MAX_LOG_LINE")&&fn.includes("len(out) + len(err) <= MAX_LOG_STREAM"),"hard_caps_not_slicing");
 return {schema:"heptabao.admitted-events.source-checks.r1",passed:true,checkCount:checks.length,checks,source:c.sourcePin,request:c.requestPin,journal:c.journalPin,diffHunks:c.diff.hunks,journalHunks:c.jdiff.hunks,scope:"pure_V8_source_strings_only",pythonCompiled:false,pythonExecuted:false,componentsExecuted:false,runtimeCalls:0};
}