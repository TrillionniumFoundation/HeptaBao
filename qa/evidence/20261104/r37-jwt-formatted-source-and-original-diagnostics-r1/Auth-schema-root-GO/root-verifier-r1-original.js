function verifyAuthSchemaSource(p,oldp,oldGo,oldFailure) {
 const checks=[]; const ck=(name,v)=>{if(!v)throw Error(name);checks.push({name,passed:true});};
 const t=p.raw,b=t["source.before.py"],a=t["source.after.py"],q=JSON.parse(t["request.exact.json"]),oq=JSON.parse(t["request.before.json"]),c=JSON.parse(t["CONTRACT.public.json"]);
 function pin(s){return gitBlobMeta(s);}
 function def(s,n){const x=s.split("\n"),i=x.findIndex(v=>v.startsWith("def "+n+"("));if(i<0)throw Error("missing definition "+n);let j=i+1;while(j<x.length&&!/^(?:def |if __name__)/.test(x[j]))j++;return x.slice(i,j).join("\n").trimEnd()+"\n";}
 ck("whole21_all_bytes_and_merkle",p.audit.whole&&p.audit.files===21&&p.audit.bytes===316224&&p.audit.merkle.leaf_count===21);
 ck("exact_original_source",b===oldp.raw["source.after.py"]&&pin(b).blob==="7f4821ab3e5de33849e0c92e63bdf9d1d54b44d6");
 ck("source_pin",JSON.stringify(pin(a))===JSON.stringify(c.source)&&c.source.blob==="ee549c6a17d60d37e2ae083c30495aff0e02f65a");
 const fw=strictApply(b,t["source.diff"]),rv=strictApply(a,t["source.inverse.diff"]);
 ck("strict_four_hunks_both_directions",fw.text===a&&rv.text===b&&fw.hunks===4&&rv.hunks===4);
 const unchanged=["need","sha","identity","remaining","public_error","load_helpers","metadata","admit_binding","open_fixed","verify_all","hash_tool","unique_log_object","log_timestamp_us","log_projection","command_public","close_rows"];
 ck("all16_original_python_functions_exact",unchanged.every(n=>def(a,n)===def(b,n)));
 const defs=s=>[...s.matchAll(/^def (\w+)\(/gm)].map(m=>m[1]);
 ck("only_two_new_python_definitions",JSON.stringify(defs(a).filter(n=>!defs(b).includes(n)))===JSON.stringify(["known_json_type","log_schema_projection"]));
 ck("main_only_new_schema_and_projection",def(a,"main").replace("heptabao.mac-owned-launchd-fixed-log-schema.r1","heptabao.mac-owned-launchd-fixed-log-projection.r1").replace("result['logSchemaObservation'] = log_schema_projection(out, err, row)","result['logProjection'] = log_projection(out, err, row)")===def(b,"main"));
 const fixed=["BINDING_READY = ","LOG_BINDING = ","QUERY_ARGV = ","FIXED_LABEL = ","WINDOW_START_US = ","WINDOW_END_US = ","MAX_LOG_ROWS = ","MAX_LOG_LINE = ","KNOWN_MESSAGE_PATHS = ","PYTHON = ","MODULES = ","UNTIL = ","MAX_CODE_BYTES = ","MAX_READ_CALLS = ","MAX_METADATA = ","MAX_FD_ROWS = ","MAX_LOG_STREAM = ","MAX_PUBLIC_OUTPUT = "];
 ck("all18_fixed_original_bindings_exact",fixed.every(x=>{const u=b.split("\n").filter(l=>l.startsWith(x)),v=a.split("\n").filter(l=>l.startsWith(x));return u.length===1&&JSON.stringify(u)===JSON.stringify(v);}));
 ck("request_pin",JSON.stringify(pin(t["request.exact.json"]))===JSON.stringify(c.request));
 ck("typed_stdin_exact",q.stdin===a&&!("stdin_text" in q));
 const nq={...q},noq={...oq};for(const k of ["stdin","idempotency_key"]){delete nq[k];delete noq[k];}
 ck("request_other_fields_unchanged",JSON.stringify(nq)===JSON.stringify(noq));
 ck("fresh_fixed_key_slot",q.idempotency_key===c.key&&c.key==="heptabao-mac-owned-launchd-log-schema-9e7f2f71-20261106-r1"&&c.slot==="owner_launchd_log_schema_gitfirst_r1");
 ck("source_sha_key_binding",c.key.includes(c.source.sha256.slice(0,8)));
 const j=t["journal.after.js"],oj=t["journal.before.js"],jfw=strictApply(oj,t["journal.diff"]),jrv=strictApply(j,t["journal.inverse.diff"]);
 ck("old_journal_original",oj===oldp.raw["journal.after.js"]);
 ck("strict_two_journal_hunks_both_directions",jfw.text===j&&jrv.text===oj&&jfw.hunks===2&&jrv.hunks===2);
 let jn=j.replace(c.slot,oldGo.slot).replace(c.request.blob,oldGo.exact_request.blob).replace("bytes:"+c.request.bytes+",sha256:","bytes:"+oldGo.exact_request.bytes+",sha256:").replace(c.request.sha256,oldGo.exact_request.sha256).replace("heptabao-mac-owned-launchd-log-schema-9e7f2f71-","heptabao-mac-owned-launchd-fixed-log-2b0945bc-");
 ck("journal_only_three_bindings_exact",jn===oj&&JSON.stringify(pin(j))===JSON.stringify(c.journal));
 const s=def(a,"log_schema_projection"),ty=def(a,"known_json_type");
 ck("exact_eight_key_vocabulary",s.includes("known_keys = ('eventMessage', 'message', 'composedMessage', 'process',\n                  'processImagePath', 'timestamp', 'type', 'eventType')"));
 ck("closed_json_type_vocabulary",JSON.stringify([...ty.matchAll(/return '([^']+)'/g)].map(m=>m[1]))===JSON.stringify(["null","boolean","string","number","array","object","unlisted"]));
 ck("field_summary_presence_type_only",s.includes("'jsonType': known_json_type(item[key]) if key in item else 'absent'")&&!s.includes(".keys(")&&!s.includes(".items(")&&!s.includes("sha(")&&!s.includes("hash("));
 ck("three_original_message_guards_separately_observed",s.includes("has_messages = bool(messages)")&&s.includes("all_strings = all(type(msg) is str for msg in messages)")&&s.includes("all(msg == messages[0] for msg in messages)")&&s.includes("'originalComposite': bool(has_messages and all_strings and equal_strings)"));
 ck("message_flags_only_fixed_equality_label_empty",s.includes("'emptyString': item[key] == ''")&&s.includes("'exactOriginalLabelPresent': bool(re.search(label_pattern, item[key]))"));
 ck("process_booleans_only",s.includes("item['process'] == 'launchd'")&&s.includes("item['processImagePath'].rsplit('/', 1)[-1] == 'launchd'"));
 ck("timestamp_parse_window_boolean_only",s.includes("instant = log_timestamp_us(item['timestamp'])")&&s.includes("timestamp_in_window = WINDOW_START_US <= instant <= WINDOW_END_US")&&s.includes("except (HelpRefused, ValueError, OverflowError):"));
 ck("no_nested_follow_or_raw_copy",!s.includes("json.dumps")&&!s.includes("str(item")&&!s.includes("repr(")&&!s.includes("rows.append(item")&&!s.includes("**item")&&!s.includes("len(item["));
 ck("same_strict_json_guards",s.includes("out.decode('utf-8', 'strict')")&&s.includes("object_pairs_hook=unique_log_object")&&s.includes("parse_constant=lambda _value: need(False, 'finite_log_json')")&&s.includes("need(type(item) is dict, 'log_record_object')"));
 ck("same_output_caps_and_child_outcome",s.includes("len(out) + len(err) <= MAX_LOG_STREAM")&&s.includes("len(lines) <= MAX_LOG_ROWS")&&s.includes("len(line.encode('utf-8')) <= MAX_LOG_LINE")&&s.includes("and row['exitCode'] == 0 and not err")&&s.includes("not row['outcomeUnknown'] and row['completeBeforeDeadline']"));
 ck("not_classifier_or_cause_or_old_bytes_qualification",s.includes("'schemaOnlyObservation': True")&&s.includes("'eventProjectionQualified': False")&&s.includes("'originalClassifierPassed': False")&&s.includes("'freshObservationNotOriginal817ByteRecovery': True")&&s.includes("'rawLogTextExported': False")&&s.includes("'rawOrUnknownLogHashExported': False"));
 ck("scope_argv_time_tool_unchanged",JSON.stringify(c.exactArgv)===JSON.stringify(oldGo.scope.exact_child_argv)&&JSON.stringify(c.timeWindow)===JSON.stringify(oldGo.scope.original_time_evidence));
 const old=JSON.parse(t["original-query.stdout.json"]),au=JSON.parse(t["original-query.authority.json"]);
 ck("original_known_failure_retained",old.ok===false&&old.error.code==="one_log_message_semantics"&&au.exit_code===1&&old.commands.commands[0].stdoutBytes===817&&old.commands.commands[0].exitCode===0&&c.originalFailure.rootQualification.blob===oldFailure.pin.blob);
 const binding=processStartBinding(q);
 ck("new_correct_native_binding",typeof binding.sha256==="string"&&binding.sha256.length===64&&binding.native_fingerprint!==oldGo.native_binding.native_fingerprint);
 return {schema:"heptabao.root-Mac-fixed-log-schema-source-review.v1",status:"PASS_SOURCE_ONLY",checks_passed:checks.length,checks,source_packet:p.tree,source:c.source,request:c.request,journal:c.journal,native_binding:{sha256:binding.sha256,native_fingerprint:binding.native_fingerprint,typed_stdin_field:"stdin"},scope:"One fresh bounded schema observation only; no original classifier, event, startup cause or withheld817-byte qualification.",new_python_definitions:2,unchanged_python_definitions:unchanged.length,source_hunks:4,journal_hunks:2,python_compiled:false,component_executed:false,root_Runtime_calls:0};
}