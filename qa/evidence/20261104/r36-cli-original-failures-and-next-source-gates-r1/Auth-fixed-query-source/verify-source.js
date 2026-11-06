/* Pure V8 binding/source verifier. No Python evaluation, imports, native tools, or Git calls.
 * Requires gitBlobMeta, utf8Text, unb64, sourceUnified and strictApplySource already loaded.
 * Interface: verifyFixedLogQuerySource(texts), where texts are this packet's exact UTF-8 leaves.
 */
function verifyFixedLogQuerySource(t) {
  const checks=[];
  function check(name,value) { checks.push({name,passed:!!value}); if(!value)throw Error("check:"+name); }
  function pin(raw) { return gitBlobMeta(raw); }
  function same(a,b) { return JSON.stringify(a)===JSON.stringify(b); }
  function line(s,prefix) {const a=s.split("\n").filter(x=>x.startsWith(prefix));check("one_line:"+prefix,a.length===1);return a[0];}
  function definition(s,name) {
    const a=s.split("\n"),i=a.findIndex(x=>x.startsWith("def "+name+"("));
    check("definition_present:"+name,i>=0);
    let j=i+1;while(j<a.length&&!/^(def |class |if __name__)/.test(a[j]))j++;
    return a.slice(i,j).join("\n").trimEnd()+"\n";
  }
  const before=t["source.before.py"],after=t["source.after.py"];
  const request=JSON.parse(t["request.exact.json"]),oldRequest=JSON.parse(t["request.before.json"]);
  const jbefore=t["journal.before.js"],journal=t["journal.after.js"];
  const contract=JSON.parse(t["CONTRACT.public.json"]);
  check("exact_actual_help_source_base",pin(before).blob==="5bbd852c3b8c49a3cc18a0dc716fe123f33c3726");
  check("source_forward_whole",strictApplySource(before,t["source.diff"]).raw===after);
  check("source_inverse_whole",strictApplySource(after,t["source.inverse.diff"]).raw===before);
  check("journal_forward_whole",strictApplySource(jbefore,t["journal.diff"]).raw===journal);
  check("journal_inverse_whole",strictApplySource(journal,t["journal.inverse.diff"]).raw===jbefore);
  const unchanged=["need","sha","identity","remaining","public_error","load_helpers","metadata",
    "admit_binding","open_fixed","verify_all","hash_tool","command_public","close_rows"];
  for(const name of unchanged)check("whole_original_definition:"+name,definition(before,name)===definition(after,name));
  for(const prefix of ["BINDING_READY = ","LOG_BINDING = ","LOG_PATH = ","PYTHON = ","MODULES = ",
      "START = ","UNTIL = ","MAX_CODE_BYTES = ","MAX_READ_CALLS = ","MAX_METADATA = ",
      "MAX_FD_ROWS = ","MAX_PUBLIC_OUTPUT = "])
    check("unchanged_binding_or_budget:"+prefix,line(before,prefix)===line(after,prefix));
  check("max_capture_stream_same_65536",before.includes("MAX_HELP_STREAM = 65536\n")&&after.includes("MAX_LOG_STREAM = 65536\n"));
  const embeddedLine=line(after,"MODULES = ");
  const mods=JSON.parse(utf8Text(unb64(/base64\.b64decode\('([^']+)'/.exec(embeddedLine)[1])));
  check("exact_two_original_embedded_helpers",same(mods.map(x=>x.name),["mac_owned_unreaped_r1","mac_owned_commands_r1"]));
  for(const m of mods){const p=pin(utf8Text(unb64(m.base64)));check("embedded_whole:"+m.name,p.blob===m.blob&&p.bytes===m.bytes&&p.sha256===m.sha256);}
  const oldOther={...oldRequest},newOther={...request};delete oldOther.stdin;delete oldOther.idempotency_key;delete newOther.stdin;delete newOther.idempotency_key;
  check("request_only_source_and_new_key",same(oldOther,newOther));
  check("request_exact_stdin",request.stdin===after&&!("stdin_text" in request));
  check("request_original_outer60",request.timeout_seconds===60);
  check("request_source_and_key_binding",same(contract.source,pin(after))&&same(contract.request,pin(t["request.exact.json"]))
    &&request.idempotency_key==="heptabao-mac-owned-launchd-fixed-log-"+pin(after).sha256.slice(0,8)+"-20261106-r1");
  const argv=JSON.parse(line(after,"QUERY_ARGV = ").slice("QUERY_ARGV = ".length));
  check("exact_fixed_argv13",same(argv,contract.exactArgv)&&argv.length===13);
  check("fixed_three_second_predicate",argv[0]==="/usr/bin/log"&&argv[1]==="show"
    &&argv[3]==="2026-11-06 00:45:18+0000"&&argv[5]==="2026-11-06 00:45:21+0000"
    &&argv[7]==="ndjson"&&argv[9]==='process = "launchd" AND message CONTAINS "org.heptabao.qa.mac-authbus-4e808-owner-r1.server"'
    &&same(argv.slice(10),["--info","--debug","--no-pager"]));
  const help=t["actual.help.txt"],helpActual=JSON.parse(t["actual.help-parent.stdout.json"]),helpAuthority=JSON.parse(t["actual.help-parent.authority.json"]);
  check("help_text_is_actual_projection",helpActual.help.publicHelpText===help&&pin(help).sha256===helpActual.help.sha256
    &&pin(help).bytes===2246&&helpActual.help.observedExitCode===64&&helpActual.help.sourceStream==="stderr");
  check("help_parent_success_with_full_closure",helpAuthority.exit_code===0&&helpAuthority.output_complete===true
    &&helpAuthority.output_durable===true&&helpActual.ok===true&&helpActual.outcomeUnknown===false
    &&helpActual.allApplicationDescriptorsClosed===true&&helpActual.allOwnedHelpChildrenClosed===true);
  for(const token of ["--start <date>","--end <date>","--predicate <predicate>","--style <style>",
      "--[no-]debug","--[no-]info","--[no-]pager","ndjson","'Y-M-D H:m:s+zzzz'"])
    check("actual_help_support:"+token,help.includes(token));
  const time=JSON.parse(t["original-time-window.public.json"]),ack=JSON.parse(t["original-worker.ack.json"]),
    authority=JSON.parse(t["original-worker.authority.json"]),worker=JSON.parse(t["original-worker.stdout.json"]);
  check("same_original_job_identity",ack.job.id===time.originalJob&&authority.job_id===time.originalJob
    &&ack.job.host==="mac"&&time.originalJob==="1a1ae51309d-fc05-5ef8");
  check("actual_time_origins",ack.job.created_unix_ms===time.jobCreatedUnixMs&&authority.at_unix_ms===time.terminalPublicationUnixMs);
  check("original1858ms_to_conservative3000ms",time.terminalPublicationUnixMs-time.jobCreatedUnixMs===1858
    &&Math.floor(time.jobCreatedUnixMs/1000)*1000===1793925918000
    &&Math.ceil(time.terminalPublicationUnixMs/1000)*1000===1793925921000
    &&time.maximumWindowMilliseconds===3000);
  const boot=worker.manager.ownedCommands.commands.filter(x=>x.argv[0]==="/bin/launchctl"&&x.argv[1]==="bootstrap");
  check("original_bootstrap_source_row",boot.length===1&&same(boot[0].argv,time.bootstrapCommand.argv)
    &&boot[0].pid===82492&&boot[0].exitCode===0&&boot[0].outcomeUnknown===false);
  check("original_label_and_unknown_not_closed",worker.manager.registrations.length===1
    &&worker.manager.registrations[0].label==="org.heptabao.qa.mac-authbus-4e808-owner-r1.server"
    &&worker.manager.allRegistrationsClosed===false&&worker.manager.allKnownLineagesClosed===false);
  check("new_timestamp_constants_exact",after.includes("WINDOW_START_US = 1793925918000000\n")
    &&after.includes("WINDOW_END_US = 1793925921000000\n"));
  const projection=definition(after,"log_projection");
  check("hard_combined_stream_refusal_before_projection",projection.indexOf("len(out) + len(err) <= MAX_LOG_STREAM")>=0
    &&projection.indexOf("len(out) + len(err) <= MAX_LOG_STREAM")<projection.indexOf("out.decode("));
  check("known_exit_zero_and_empty_stderr",projection.includes("and row['exitCode'] == 0 and not err"));
  check("hard_row_cap_and_per_line_cap",after.includes("MAX_LOG_ROWS = 64\n")&&after.includes("MAX_LOG_LINE = 8192\n")
    &&projection.includes("len(lines) <= MAX_LOG_ROWS")&&projection.includes("len(line.encode('utf-8')) <= MAX_LOG_LINE"));
  check("no_projection_truncation_or_sort",!projection.includes("[:")&&!projection.includes("sorted("));
  check("duplicate_json_and_nonfinite_refusal",projection.includes("object_pairs_hook=unique_log_object")
    &&projection.includes("parse_constant=lambda _value: need(False, 'finite_log_json')"));
  check("one_exact_label_and_process",projection.includes("'exact_original_label_in_message'")
    &&projection.includes("all(name == 'launchd' for name in process_values)"));
  check("exact_integer_time_bounds",projection.includes("WINDOW_START_US <= instant <= WINDOW_END_US")
    &&definition(after,"log_timestamp_us").includes("(delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds"));
  check("no_raw_or_hash_export",projection.includes("'rawLogTextExported': False")
    &&projection.includes("'rawOrUnknownLogHashExported': False")
    &&definition(after,"command_public").includes("row.pop('stdoutSha256', None)")
    &&definition(after,"command_public").includes("row.pop('stderrSha256', None)"));
  check("explicit_nonqualification",projection.includes("'noMatchesDoesNotProveAbsence': True")
    &&projection.includes("'classificationIsLexicalEvidenceNotRootCauseProof': True")
    &&after.includes("'historicalLineageClosureQualified': False, 'startupCauseQualified': False"));
  check("one_fixed_query_call",after.match(/commands\.run\(/g).length===1&&after.includes("list(QUERY_ARGV),\n            until=min(UNTIL, time.monotonic() + 10.0), maximum=MAX_LOG_STREAM)"));
  check("original_child_owner_and_full_close_tail",after.includes("state['allOwnedCommandsStopped']")
    &&after.includes("state['unknownCommandCount'] == 0")&&after.includes("final_clock < UNTIL")
    &&after.includes("if time.monotonic() >= UNTIL or (signals is not None and signals.pending is not None):"));
  const oldPrefix="heptabao-mac-owned-launchd-log-help-protocol-aed2df85-",
    newPrefix="heptabao-mac-owned-launchd-fixed-log-"+pin(after).sha256.slice(0,8)+"-";
  const normalized=journal.replace(contract.slot,"owner_launchd_log_help_protocol_gitfirst_r2")
    .replace(pin(t["request.exact.json"]).blob,pin(t["request.before.json"]).blob)
    .replace("bytes:"+pin(t["request.exact.json"]).bytes+",sha256:","bytes:"+pin(t["request.before.json"]).bytes+",sha256:")
    .replace(pin(t["request.exact.json"]).sha256,pin(t["request.before.json"]).sha256)
    .replace(newPrefix,oldPrefix);
  check("journal_only_slot_request_prefix",normalized===jbefore);
  check("new_slot_not_old_slot",contract.slot==="owner_launchd_fixed_log_projection_gitfirst_r1");
  return {schema:"heptabao.fixed-log-query-source-pure-verifier.r1",passed:true,checkCount:checks.length,checks,
    unchangedPythonDefinitions:unchanged,sourceHunks:strictApplySource(before,t["source.diff"]).hunks,
    journalHunks:strictApplySource(jbefore,t["journal.diff"]).hunks,
    pythonEvaluated:false,pythonCompiled:false,componentOrSdkExecuted:false,runtimeCalls:0,queryAuthorized:false};
}
