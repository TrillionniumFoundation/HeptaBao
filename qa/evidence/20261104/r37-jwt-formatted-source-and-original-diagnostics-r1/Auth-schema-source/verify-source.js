/* Pure V8 source binding checks. No Python evaluation or Runtime.
Interface: verifyFixedSchemaSource(t); dependencies gitBlobMeta, sourceUnified, strictApplySource. */
function verifyFixedSchemaSource(t) {
 const checks=[];function ok(name,value){checks.push({name,passed:!!value});if(!value)throw Error(name);}
 const before=t["source.before.py"],after=t["source.after.py"],c=JSON.parse(t["CONTRACT.public.json"]);
 const q=JSON.parse(t["request.exact.json"]),oldq=JSON.parse(t["request.before.json"]);
 const pin=gitBlobMeta;
 function def(s,name){const l=s.split("\n"),i=l.findIndex(x=>x.startsWith("def "+name+"("));if(i<0)throw Error("missingdef:"+name);let j=i+1;while(j<l.length&&!/^(def |class |if __name__)/.test(l[j]))j++;return l.slice(i,j).join("\n").trimEnd()+"\n";}
 ok("original_failed_query_source",pin(before).blob==="7f4821ab3e5de33849e0c92e63bdf9d1d54b44d6");
 ok("source_forward_whole",strictApplySource(before,t["source.diff"]).raw===after);
 ok("source_inverse_whole",strictApplySource(after,t["source.inverse.diff"]).raw===before);
 const unchanged=["need","sha","identity","remaining","public_error","load_helpers","metadata","admit_binding","open_fixed","verify_all","hash_tool","unique_log_object","log_timestamp_us","log_projection","command_public","close_rows"];
 for(const name of unchanged)ok("original_function_exact:"+name,def(before,name)===def(after,name));
 const main=def(after,"main").replace("heptabao.mac-owned-launchd-fixed-log-schema.r1","heptabao.mac-owned-launchd-fixed-log-projection.r1")
  .replace("result['logSchemaObservation'] = log_schema_projection(out, err, row)","result['logProjection'] = log_projection(out, err, row)");
 ok("main_only_schema_and_projection_call",main===def(before,"main"));
 const bl=before.split("\n"),al=after.split("\n");
 for(const prefix of ["BINDING_READY = ","LOG_BINDING = ","QUERY_ARGV = ","FIXED_LABEL = ","WINDOW_START_US = ","WINDOW_END_US = ","MAX_LOG_ROWS = ","MAX_LOG_LINE = ","KNOWN_MESSAGE_PATHS = ","PYTHON = ","MODULES = ","UNTIL = ","MAX_CODE_BYTES = ","MAX_READ_CALLS = ","MAX_METADATA = ","MAX_FD_ROWS = ","MAX_LOG_STREAM = ","MAX_PUBLIC_OUTPUT = "]){
  const x=bl.filter(s=>s.startsWith(prefix)),y=al.filter(s=>s.startsWith(prefix));ok("same_fixed_binding:"+prefix,x.length===1&&JSON.stringify(x)===JSON.stringify(y));
 }
 ok("request_source_exact",q.stdin===after&&!("stdin_text" in q));
 const a={...oldq},b={...q};delete a.stdin;delete a.idempotency_key;delete b.stdin;delete b.idempotency_key;
 ok("request_only_new_source_key",JSON.stringify(a)===JSON.stringify(b));
 ok("request_pin_key",JSON.stringify(c.source)===JSON.stringify(pin(after))&&JSON.stringify(c.request)===JSON.stringify(pin(t["request.exact.json"]))&&q.idempotency_key==="heptabao-mac-owned-launchd-log-schema-"+pin(after).sha256.slice(0,8)+"-20261106-r1");
 ok("journal_forward_whole",strictApplySource(t["journal.before.js"],t["journal.diff"]).raw===t["journal.after.js"]);
 ok("journal_inverse_whole",strictApplySource(t["journal.after.js"],t["journal.inverse.diff"]).raw===t["journal.before.js"]);
 let normalized=t["journal.after.js"].replace(c.slot,"owner_launchd_fixed_log_projection_gitfirst_r1")
  .replace(pin(t["request.exact.json"]).blob,pin(t["request.before.json"]).blob)
  .replace("bytes:"+pin(t["request.exact.json"]).bytes+",sha256:","bytes:"+pin(t["request.before.json"]).bytes+",sha256:")
  .replace(pin(t["request.exact.json"]).sha256,pin(t["request.before.json"]).sha256)
  .replace("heptabao-mac-owned-launchd-log-schema-"+pin(after).sha256.slice(0,8)+"-","heptabao-mac-owned-launchd-fixed-log-2b0945bc-");
 ok("journal_only_binding_literals",normalized===t["journal.before.js"]);
 const p=def(after,"log_schema_projection");
 ok("exact_eight_known_keys",p.includes("known_keys = ('eventMessage', 'message', 'composedMessage', 'process',\n                  'processImagePath', 'timestamp', 'type', 'eventType')"));
 ok("same_stream_row_line_hard_guards",p.includes("len(out) + len(err) <= MAX_LOG_STREAM")&&p.includes("len(lines) <= MAX_LOG_ROWS")&&p.includes("len(line.encode('utf-8')) <= MAX_LOG_LINE"));
 ok("same_known_child_zero_empty_stderr",p.includes("and row['exitCode'] == 0 and not err"));
 ok("same_duplicate_nonfinite_object_guards",p.includes("object_pairs_hook=unique_log_object")&&p.includes("parse_constant=lambda _value: need(False, 'finite_log_json')")&&p.includes("need(type(item) is dict, 'log_record_object')"));
 ok("no_unknown_key_names_or_values_output",p.includes("'unknownKeyNamesPublished': False")&&p.includes("'anyFieldValuePublished': False")&&p.includes("'anyFieldLengthPublished': False")&&!p.includes(".keys(")&&!p.includes(".items("));
 ok("no_unknown_hash_or_817_recovery",p.includes("'rawOrUnknownLogHashExported': False")&&p.includes("'freshObservationNotOriginal817ByteRecovery': True"));
 ok("not_original_classifier_qualification",p.includes("'schemaOnlyObservation': True")&&p.includes("'eventProjectionQualified': False")&&p.includes("'originalClassifierPassed': False"));
 ok("original_composite_equivalence_source",p.includes("'originalComposite': bool(has_messages and all_strings and equal_strings)")&&p.includes("equal_strings = bool(has_messages and all_strings\n                             and all(msg == messages[0] for msg in messages))"));
 const original=JSON.parse(t["original-query.stdout.json"]),authority=JSON.parse(t["original-query.authority.json"]);
 ok("known_original_failure_preserved",original.ok===false&&original.error.code==="one_log_message_semantics"&&authority.exit_code===1&&original.commands.commands[0].stdoutBytes===817&&original.commands.commands[0].exitCode===0);
 ok("no_original_unknown_body_file",!Object.keys(t).some(k=>k.includes("817.original")||k.includes("unknown-log-body")));
 return {schema:"heptabao.fixed-log-schema-source-purechecks.r1",passed:true,checks,checkCount:checks.length,
   unchangedPythonDefinitions:unchanged,sourceHunks:strictApplySource(before,t["source.diff"]).hunks,journalHunks:strictApplySource(t["journal.before.js"],t["journal.diff"]).hunks,
   pythonCompiled:false,pythonOrComponentExecuted:false,runtimeCalls:0,originalClassifierQualified:false};
}
