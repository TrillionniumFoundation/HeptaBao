/* Pure V8 SOURCE verifier.
 * Interface: verifyPublicNodeIgnitionLogSource(files)
 * Requires gitBlobMeta, unb64, utf8Text and strictApplySource in the evaluation.
 * files is the exact flat public SOURCE map; no filesystem/Native/Python executes.
 */
function verifyPublicNodeIgnitionLogSource(files) {
 const checks=[];
 const check=(name,ok)=>{checks.push({name,passed:!!ok});};
 const meta=gitBlobMeta;
 const pinEq=(raw,p)=>{const a=meta(raw);return a.blob===p.blob&&a.bytes===p.bytes&&a.sha256===p.sha256;};
 const s=files["source.py"],b=files["source.before.original.py"],j=files["journal.js"],jb=files["journal.before.original.js"];
 const c=JSON.parse(files["CONTRACT.public.json"]),q=JSON.parse(files["request.exact.json"]);
 const refs=JSON.parse(files["PRIMARY_REFERENCES.public.json"]);
 const root=JSON.parse(files["root-R5-actual16.original.json"]),r5=JSON.parse(files["R5.stdout.original.json"]);
 const inp=JSON.parse(files["PUBLIC_NODE_INPUTS.original.json"]);
 const def=(raw,name)=>{const at=raw.indexOf("def "+name+"(");if(at<0)throw Error("missing_python_definition:"+name);const tail=raw.slice(at);const m=/\n(?=def |class |if __name__)/.exec(tail);return (m?tail.slice(0,m.index+1):tail).trimEnd()+"\n";};
 const line=(raw,name)=>raw.split("\n").find(l=>l.startsWith(name+" = "));
 check("baseline_full_pin",pinEq(b,c.unchanged.baselineSource));
 check("source_full_pin",pinEq(s,c.source));
 check("request_full_pin",pinEq(files["request.exact.json"],c.request));
 check("journal_full_pin",pinEq(j,c.journal));
 check("forward_exact",strictApplySource(b,files["source.forward.diff"]).raw===s);
 check("inverse_exact",strictApplySource(s,files["source.inverse.diff"]).raw===b);
 check("forward_7_hunks",strictApplySource(b,files["source.forward.diff"]).hunks===7);
 check("inverse_7_hunks",strictApplySource(s,files["source.inverse.diff"]).hunks===7);
 check("journal_forward_exact",strictApplySource(jb,files["journal.forward.diff"]).raw===j);
 check("journal_inverse_exact",strictApplySource(j,files["journal.inverse.diff"]).raw===jb);
 check("journal_forward_2_hunks",strictApplySource(jb,files["journal.forward.diff"]).hunks===2);
 check("journal_inverse_2_hunks",strictApplySource(j,files["journal.inverse.diff"]).hunks===2);
 for(const n of c.unchanged.originalDefinitions) check("definition_exact:"+n,def(s,n)===def(b,n));
 for(const n of ["BINDING_READY","LOG_BINDING","LOG_PATH","PYTHON","START","UNTIL",
 "MAX_LOG_ROWS","MAX_LOG_LINE","MAX_CODE_BYTES","MAX_READ_CALLS","MAX_METADATA","MAX_FD_ROWS",
 "MAX_LOG_STREAM","MAX_PUBLIC_OUTPUT"]) check("constant_exact:"+n,line(s,n)===line(b,n));
 const modline=line(s,"MODULES");
 check("whole_modules_literal_exact",modline===line(b,"MODULES"));
 const mm=/^MODULES = json\.loads\(base64\.b64decode\('([^']+)', validate=True\)\)$/.exec(modline);
 check("exact_module_parser",!!mm);
 const mods=JSON.parse(utf8Text(unb64(mm[1])));
 check("two_original_module_names",mods.map(x=>x.name).join(",")==="mac_owned_unreaped_r1,mac_owned_commands_r1");
 for(const m of mods)check("embedded_module_whole:"+m.name,pinEq(utf8Text(unb64(m.base64)),m));
 let main=def(s,"main");
 main=main.replace("'heptabao.mac-public-node-ignition-log-diagnosis.r1'","'heptabao.mac-owned-launchd-admitted-log-events.r1'")
 .replace("'fixed-public-node-two-second-log'","'fixed-owned-label-three-second-log'")
 .replace("node_log_projection(out, err, row)","log_admitted_event_projection(out, err, row)");
 check("main_only_three_substitutions",main===def(b,"main"));
 const beforePin=/const GF_REQUEST = \{blob:"([a-f0-9]{40})",\n bytes:([0-9]+),sha256:"([a-f0-9]{64})"\};/.exec(jb)[0];
 const afterPin=/const GF_REQUEST = \{blob:"([a-f0-9]{40})",\n bytes:([0-9]+),sha256:"([a-f0-9]{64})"\};/.exec(j);
 check("journal_request_pin_exact",afterPin[1]===c.request.blob&&Number(afterPin[2])===c.request.bytes&&afterPin[3]===c.request.sha256);
 const normalized=j.replace(JSON.stringify(c.freshSlot),'"owner_authbus_public_node_crash_fixed_file_gitfirst_r5"')
 .replace(afterPin[0],beforePin).replace(c.observerPrefix,"heptabao-mac-public-node-crash-bc7efad5-");
 check("journal_three_bindings_only",normalized===jb);
 check("request_stdin_exact",q.stdin===s&&!Object.hasOwn(q,"stdin_text"));
 check("exact_request_fields",Object.keys(q).sort().join(",")==="args,cwd,executable,host,idempotency_key,stdin,timeout_seconds");
 check("fixed_request_host_python",q.host==="mac"&&q.executable==="/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14");
 check("fixed_request_args_cwd_timeout",JSON.stringify(q.args)==='["-I","-S","-B","-"]'&&q.cwd==="/Users/qianqi"&&q.timeout_seconds===60);
 check("new_stable_key",q.idempotency_key===c.observerPrefix+"20261106-r1");
 const qa=JSON.parse(line(s,"QUERY_ARGV").slice("QUERY_ARGV = ".length));
 check("query_exact_contract",JSON.stringify(qa)===JSON.stringify(c.query.argv));
 check("fixed_query_process_predicate",qa[10]==='(process = "node") OR ((process = "kernel" OR process = "sandboxd") AND message CONTAINS "51494")');
 check("fixed_query_flags",JSON.stringify(qa.slice(0,10))===JSON.stringify(["/usr/bin/log","show","--start","2026-11-06 19:35:51+0000","--end","2026-11-06 19:35:53+0000","--style","ndjson","--predicate"])===false);
 check("query_one_vector_length",qa.length===13&&qa[8]==="--predicate"&&qa.at(-1)==="--no-pager");
 check("query_exact_flags_order",JSON.stringify(qa)===JSON.stringify(["/usr/bin/log","show","--start","2026-11-06 19:35:51+0000","--end","2026-11-06 19:35:53+0000","--style","ndjson","--predicate",'(process = "node") OR ((process = "kernel" OR process = "sandboxd") AND message CONTAINS "51494")',"--info","--debug","--no-pager"]));
 check("source_exact_pid",line(s,"FIXED_PID")==="FIXED_PID = 51494");
 check("outward_exact_time",c.time.startUs===Math.floor(c.originalPublicNode.actualCreatedMs/1000)*1000000&&c.time.endUs===Math.ceil(c.originalPublicNode.actualTerminalMs/1000)*1000000&&c.time.endUs-c.time.startUs===2000000);
 check("UTC_arg_time_exact",Date.parse(c.time.startUtc)*1000===c.time.startUs&&Date.parse(c.time.endUtc)*1000===c.time.endUs);
 const np=def(s,"node_log_projection"),nr=def(s,"node_log_record"),nv=def(s,"node_log_vocabulary"),pr=def(s,"public_resource");
 check("new_four_projectors_present",[np,nr,nv,pr].every(x=>x.length>100));
 check("strict_before_projection",np.indexOf("json.loads(")<np.indexOf("node_log_record(")&&np.includes("object_pairs_hook=unique_log_object")&&np.includes("'finite_log_json'"));
 check("complete_row_caps",np.includes("len(lines) <= MAX_LOG_ROWS")&&np.includes("len(line.encode('utf-8')) <= MAX_LOG_LINE")&&np.includes("len(out) + len(err) <= MAX_LOG_STREAM"));
 check("requires_zero_full_stderr_empty",np.includes("row['exitCode'] == 0 and not err")&&np.includes("row['completeBeforeDeadline']"));
 check("all_ordinals_explicit",np.includes("rows.append(node_log_record(item, ordinal))")&&np.includes("'rejectedUnknownObjects': len(rows) - admitted"));
 check("typed_pid_gate",nr.includes("type(value) is int and 0 <= value <= 2147483647")&&nr.includes("all(value == FIXED_PID for value in pid_values)"));
 check("direct_or_system_subject",nr.includes("(origin == 'node' and pid_exact)")&&nr.includes("(origin in ('kernel', 'sandboxd') and system_subject)"));
 check("time_gate_required",nr.includes("WINDOW_START_US <= instant <= WINDOW_END_US")&&nr.includes("(within, 'outside_original_window')"));
 check("unknown_no_projection",nr.indexOf("if reasons:")<nr.indexOf("node_log_vocabulary(message)")&&nr.includes("return result\n    result['microsecondsFromWindowStart']"));
 check("code_not_errno",nv.includes("'terminationCodeIsNotAssumedErrno': True")&&nv.includes("match.group(1).lower() == 'errno'"));
 check("resource_context_separated",pr.includes("context == 'mach-lookup'")&&pr.includes("context == 'sysctl-read'")&&pr.includes("context == 'path'")===false);
 check("public_resource_caps_no_uuid",pr.includes("len(value.encode('utf-8')) > 512")&&pr.includes("len(parts) > 16")&&pr.includes("[a-fA-F0-9]{12}")&&pr.includes("part not in ('.', '..')"));
 check("only_recognized_resources_exported",nv.includes("if projected['recognized']:")&&nv.includes("unknown_resources += 1"));
 check("no_io_in_new_projectors",![nr,np,nv,pr].some(x=>/\bos\.(?:open|read|pread|write|stat|scandir)|\bsubprocess\b|\bPopen\b|\bexec\s*\(/.test(x)));
 check("unknown_raw_or_hash_not_exported",nv.includes("'rawMessageExported': False")&&nv.includes("'unknownTextOrHashExported': False")&&!/\bsha\s*\(/.test(nv));
 check("cause_history_qualifications_false",np.includes("'startupCauseQualified': False")&&np.includes("'historicalLineageClosureQualified': False")&&np.includes("'originalBusinessProgressQualified': False")&&np.includes("'originalCrashPathCorrelationQualified': False"));
 check("absence_and_unknown_boundaries",np.includes("'noMatchesDoesNotProveAbsence': True")&&np.includes("'wholeLogFullyClassified': False")&&np.includes("'unknownObjectSemanticsQualified': False"));
 check("help_all_argv_flags",["--start","--end","--style","ndjson","--predicate","--[no-]info","--[no-]debug","--[no-]pager"].every(x=>files["log.actual-help.original.txt"].includes(x)));
 check("help_whole_pin",pinEq(files["log.actual-help.original.txt"],refs.logActual.help));
 check("log_metadata_whole_pin",pinEq(files["log.actual-metadata.original.json"],refs.logActual.metadata));
 check("old_help_root_whole_pin",pinEq(files["log.help-root-qualification.original.json"],refs.logActual.rootHelpQualification));
 check("actual_log_binding_source",JSON.stringify(JSON.parse(line(s,"LOG_BINDING").slice(14)))===JSON.stringify(c.query.logTool));
 check("actual_log_binding_807536",c.query.logTool.size===807536&&c.query.logTool.identity.length===9);
 check("root_R5_actual16_whole",pinEq(files["root-R5-actual16.original.json"],c.actualR5.rootQualification));
 check("root_R5_all_16",Object.keys(root.checks).length===16&&Object.values(root.checks).every(x=>x===true));
 check("R5_actual_namespace_exact",r5.candidates[0].projection.termination.namespace.value==="<0x23>"&&r5.candidates[0].projection.termination.namespace.utf8Bytes===6);
 check("R5_path_not_qualified",r5.candidates[0].projection.matchesOriginalFreshChild===false&&r5.candidates[0].projection.pathQualificationSatisfied===false);
 check("R5_11_frames",r5.candidates[0].projection.faultingThreadPublicProjection.frames.length===11);
 check("R5_original_time_binding",r5.originalNativeCreatedMs===c.originalPublicNode.actualCreatedMs&&r5.originalNativeTerminalMs===c.originalPublicNode.actualTerminalMs);
 check("public_input_binding_whole",pinEq(files["PUBLIC_NODE_INPUTS.original.json"],c.originalPublicNode.inputBinding));
 check("public_input_job_env",inp.originalPublicProbeJob===c.originalPublicNode.job&&inp.environmentInheritance===false&&Object.keys(inp.explicitEnvironment).length===7);
 check("all_new_native_state_zero",c.nativeState.initialized===false&&c.nativeState.startSubmitted===false&&c.nativeState.activeCalls===0&&c.nativeState.activeFutures===0);
 check("typed_binding_not_fake_old_helper",c.correctTypedNativeBinding.sha256===null&&c.correctTypedNativeBinding.fingerprint===null);
 const err=JSON.parse(files["builder-error.original.json"]);
 check("pure_builder_error_retained",err.NativeCalls===0&&err.GitMutations===0&&err.candidateChanged===false);
 const failed=checks.filter(x=>!x.passed);
 return {schema:"heptabao.pure-node-ignition-log-source-review.r1",passed:failed.length===0,check_count:checks.length,checks,failed,
 source:c.source,request:c.request,journal:c.journal,NativeCalls:0,PythonExecutions:0,sourceOnly:true};
}
