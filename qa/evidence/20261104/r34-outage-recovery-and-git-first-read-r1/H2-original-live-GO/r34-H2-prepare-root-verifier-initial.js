function qualifyH2Prepare(I){
 const checks=[]; const q=(name,ok,detail)=>checks.push({name,passed:!!ok,...(detail===undefined?{}:{detail})});
 const dec=v=>typeof v==="object"&&v!==null&&"$exactInteger"in v?v.$exactInteger:String(v);
 const same=(a,b)=>dec(a)===dec(b); const j=v=>JSON.stringify(v); const hash=t=>gitBlobMeta(t).sha256;
 const {result:r,authority:a,info:info,body:n,stdout:s,stream:st,release:rel,binding:b,stage,observedStatuses}=I;
 q("original_authority_terminal_success",a.job_id==="1a1ae4ad33e-fc05-5ebf"&&a.state==="succeeded"&&a.exit_code===0&&a.output_complete&&a.output_durable&&a.terminal_publication_confirmed&&!a.automatic_retry&&!a.cancelled&&!a.timed_out);
 q("authority_streams_exact",a.log_bytes.stdout.seen===281&&a.log_bytes.stdout.stored===281&&a.log_bytes.stderr.seen===0&&a.log_bytes.stderr.stored===0&&a.log_synced.stdout&&a.log_synced.stderr&&!a.log_truncated.stdout&&!a.log_truncated.stderr&&a.log_errors.stdout===null&&a.log_errors.stderr===null);
 q("original_stream_job",st.job_id===a.job_id&&st.audit_recorded);
 for(const [name,text]of [["stdout",I.stdoutText],["stderr",""]]){const c=st[name];q(name+"_text_hex_EOF",c.offset===0&&c.size===utf8Bytes(text).length&&c.next_offset===c.size&&c.eof&&c.text===text&&c.bytes_hex===utf8Bytes(text).map(x=>x.toString(16).padStart(2,"0")).join(""));}
 q("pointer_exact",s.result===info.path&&s.result_sha256===I.resultMeta.sha256&&s.status==="passed"&&s.runtime_started===false&&s.all_owned_stopped===true);
 q("result_file_info",info.path===b.layout.prepare+"/result.public.json"&&info.size===52937&&info.sha256===I.resultMeta.sha256&&info.version==="2050:7874373:52937:1793925504923522214:1793925504923522214"&&info.mode===384&&info.metadata.uid===1000&&info.metadata.gid===1000&&info.metadata.link_count===1&&info.metadata.metadata_platform==="linux");
 q("body_version_range_EOF",n.path===info.path&&n.version===info.version&&n.offset===0&&n.next_offset===52937&&n.size===52937&&n.eof&&n.chunk_sha256===I.resultMeta.sha256);
 const bodyBytes=unb64(n.data_base64);q("body_exact_whole",bodyBytes.length===52937&&utf8Text(bodyBytes)===I.resultText&&gitBlobMeta(utf8Text(bodyBytes)).blob===I.resultMeta.blob);
 q("prepare_status_and_schema",r.schema==="heptabao.normal-native-h2-gate.prepare.v2"&&r.status==="passed"&&r.failure_code===null);
 q("prepare_not_runtime",r.runtime_started===false&&r.server_processes===0&&r.cli_snapshot_commands===0&&r.production_changed===false&&r.readiness_is_not_runtime_qualification===true&&r.inputs.whole_replacement_qualification===false&&r.inputs.official_cli_qualification===false);
 q("fixed_binding",r.binding_sha256===I.bindingMeta.sha256&&r.inputs.binding_sha256===I.bindingMeta.sha256&&I.bindingMeta.sha256==="b241c6fc78bbe77ea69fc3b8a707b1747324a81f1da1ade3d9bb15c5cea5b7d8");
 q("exact_candidate_source",r.inputs.source.commit==="4e808d0ecb1bcded22870a7ec960dfb2491cf6ec"&&r.inputs.source.tree==="eba5e650bd080b8ad41ea52a2bc68867f541d255"&&r.inputs.source.status==="");
 q("host_identity",r.inputs.host.machine==="x86_64"&&r.inputs.host.system==="Linux"&&r.inputs.host.uid===1000&&r.inputs.host.machine_id_sha256===stage.machine_id_sha256);
 q("original_action_budgets",j(r.inputs.budgets)===j(b.budgets));
 const byPath=new Map();function walk(v){if(!v||typeof v!=="object")return;if(typeof v.path==="string"&&v.device!==undefined&&v.inode!==undefined)byPath.set(v.path,v);for(const z of Object.values(v))walk(z);}walk(stage);
 for(const f of stage.qa_files)byPath.set(b.layout.control+"/qa/"+f.name,{...f,path:b.layout.control+"/qa/"+f.name});
 let count=0;const f9=["device","inode","uid","gid","mode","links","bytes","mtime_ns","ctime_ns"];
 for(const [group,bgroup]of [["artifacts","artifacts"],["h2_client","h2_client"],["old_fences","old_fences"],["qa","qa_files"],["utilities","utilities"]]){
  const actual=r.inputs.files[group],expected=b[bgroup];q("file_group_keys_"+group,j(Object.keys(actual).sort())===j(Object.keys(expected).sort()));
  for(const key of Object.keys(actual)){const x=actual[key],y=expected[key];count++;q("bound_input_"+group+"_"+key,["path","bytes","sha256","uid","mode"].every(k=>same(x[k],y[k]))&&x.links===1);
   const old=byPath.get(x.path);q("stage_full9_"+group+"_"+key,old!==undefined&&old.sha256===x.sha256&&f9.every(k=>same(old[k],x[k])));
  }
 }
 q("input_count",count===31);
 const prod=r.inputs.product_test_qualification;
 q("normal_product_61_separate",prod.original_tests===44&&prod.ingress_tests===7&&prod.cold_h2_tests===9&&prod.same_root_publication_tests===1&&prod.total_tests===61&&prod.product_commit===r.inputs.source.commit&&prod.product_tree===r.inputs.source.tree&&prod.normal_result_sha256===b.artifacts.combined_tests.sha256);
 const h2=r.inputs.independent_h2_qa;
 q("independent_instrument_6_only",h2.component_count===6&&h2.component_names.length===6&&h2.component_status==="passed"&&h2.offline_only===true&&h2.http_or_product_qualification===false&&h2.new_qa_components_not_added_to_product_44_7_9_1===true);
 q("instrument_binary_binding",Object.values(b.h2_client).some(x=>x.sha256===h2.executable_sha256)&&Object.values(b.h2_client).some(x=>x.sha256===h2.actual_build_receipt_sha256));
 q("eight_archive_and_audit_source_proofs",Object.keys(r.inputs.archive_and_audit_product_sources).length===8&&Object.values(r.inputs.archive_and_audit_product_sources).every(x=>/^[0-9a-f]{40}$/.test(x.git_blob)&&/^[0-9a-f]{64}$/.test(x.sha256)&&x.bytes>0));
 q("only_three_original_git_children",r.child_provenance.length===3&&r.owned_cleanup.length===3&&r.child_exec_visibility.length===0);
 const commands=[["rev-parse","HEAD"],["rev-parse","HEAD^{tree}"],["status","--porcelain","--untracked-files=all"]];
 for(let i=0;i<3;i++){const p=r.child_provenance[i],argv=["/usr/bin/git","-c","core.fsmonitor=false","-c","core.hooksPath=/dev/null","-C",b.layout.source,...commands[i]],expected=argv.join("\0")+"\0",cl=r.owned_cleanup.filter(x=>x.pid===p.pid&&same(x.start_ticks,p.identity.start_ticks));
 q("git_exact_provenance_"+i,p.stage==="exact_executable_and_argv"&&p.guard_accepted===true&&p.captured_only_by_original_child_guard===true&&p.identity.exe==="/usr/bin/git"&&p.actual_argc===argv.length&&p.expected_argc===argv.length&&p.extra_args_omitted===0&&p.actual_cmdline_bytes===utf8Bytes(expected).length&&p.actual_cmdline_sha256===hash(expected)&&p.args.length===argv.length&&p.args.every((x,k)=>x.index===k&&x.equal&&x.sha256===hash(argv[k])&&x.expected_sha256===hash(argv[k])&&x.bytes===utf8Bytes(argv[k]).length));
 q("original_child_reaped_"+i,cl.length===1&&cl[0].direct_child_reaped&&cl[0].owned_stopped&&cl[0].stop_terminal_captured&&cl[0].wait_returncode===0&&cl[0].remaining.length===0);}
 q("all_owned_stopped",r.all_owned_stopped===true);
 const finished=BigInt(dec(r.completed_after_cleanup_monotonic_ns)),until=BigInt(dec(r.deadline_monotonic_ns));
 q("original_prepare_deadline_after_cleanup",finished<until&&until-finished===298281929886n);
 q("owner_originals_closed",rel.process_start_count===1&&rel.business_replays===0&&rel.native_read_admissions===4&&rel.original_immutable_pages===12&&rel.readonly_call_count===20&&rel.Runtime_calls_inflight===0&&rel.owned_native_futures_active===0&&rel.pending_calls===0&&rel.current_scope_processes_active===0);
 for(let i=0;i<4;i++){const o=rel.original_observers[i],ss=observedStatuses[i];q("raw_observer_status_"+i,ss.operation_id===o.operation_id&&ss.async_state==="completed"&&ss.owned_future_active===false&&ss.payload_available===true&&ss.automatic_retry===false&&ss.result_state==="stored_observed"&&o.closed&&o.native_handler_closed);}
 q("original_page_chain_adopted_from_owner",rel.original_observers.every(o=>o.pages.length>0&&o.pages[0].offset===0&&o.pages.every((p,i)=>p.offset===(i?o.pages[i-1].next_offset:0)&&p.next_offset<=p.total_bytes&&p.result_sha256===o.payload_sha256&&p.eof===(i===o.pages.length-1))&&o.pages.at(-1).next_offset===o.payload_bytes));
 return {schema:"heptabao.root-h2-readonly-prepare-qualification.v1",qualified:checks.every(x=>x.passed),checks_count:checks.length,checks,inputs:{actual_result:I.resultMeta,authority:I.authorityMeta,file_info:I.infoMeta,body_native:I.bodyMeta,binding:I.bindingMeta,stage:I.stageMeta,owner_release:I.releaseMeta},scope:{Runtime_calls:0,product_test_cases_run:0,whole_original_statuses_read:4,whole_original_result_read:true,all_12_page_payloads_independently_reread:false,page_chain_adopted_from_complete_owner_journal:true,H2_live_executed:false,CLI_live_executed:false,full_replacement:false},deadline_remaining_after_cleanup_ns:(until-finished).toString()};
}