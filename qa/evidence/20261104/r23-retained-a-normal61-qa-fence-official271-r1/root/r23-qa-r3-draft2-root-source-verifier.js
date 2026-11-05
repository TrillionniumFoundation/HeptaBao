function verifyQaR3Draft2(input,apply,utf8,latin1,sha256,unb64){
 const checks=[];function need(x,label){if(!x)throw Error(label);checks.push(label);}const raw=b=>input.raw[b];const hash=s=>sha256(latin1(utf8(s)));
 const before=raw("d5dac1a373857515b8efbe5a16571bef9ecd54a8"),after=raw("e42655d8e5d2ac89bc05f1f8ccba83b86e8ef361"),tiny=raw("8e0ebf03711d3c554b8c489fc388c756e04b4386");const applied=apply(before,tiny);
 need(applied.hunks===1&&applied.text===after,"tiny_strict_one_hunk_whole");
 const addition='    report["cancel_signal"] = signals.pending\n    if signals.pending is not None:\n        report["status"] = "failed"\n    signals.check()\n';
 need(after.split(addition).length===2&&after.replace(addition,"")===before,"remove_only_four_lines_recovers_draft1");
 need(after.includes("                signal.signal(number, handler)\n            signals.protected -= 1\n"+addition+'    need(report["status"] == "observed_two_aliases", "cargo_binary_observation_incomplete")'),"check_after_both_handlers_before_output_return");
 const original=apply(raw("015f59e0f2212e4a683ad2b4511088b406a32e61"),raw("0f51360a661e07ae7c76f04d25ec04a3b9c97e2d"));
 need(original.hunks===4&&original.text===after,"r2_full_strict_four_hunk_reconstruction");
 const publisher=raw("e37bcaac539a444148a772d4db218646db41fc11");
 const pp=apply(raw("ca9e51f983dd7576917f296838bb1effca4be48f"),raw("8e801d12172ba840115fd38d992eeb703136f00d"));
 need(pp.hunks===1&&pp.text===publisher,"publisher_only_builder_pin_changed");
 const req=JSON.parse(input.request),carrier=JSON.parse(input.carrier);
 need(Object.keys(req).sort().join(",")==="args,cwd,executable,host,idempotency_key,stdin,timeout_seconds","exact_inert_request_fields");
 need(req.host==="rog"&&req.executable==="/usr/bin/python3"&&req.cwd==="/home/qian-qi"&&req.timeout_seconds===60,"inert_fixed_host_executable_cwd_outer");
 need(req.idempotency_key==="heptabao-df026-native-h2-qa-inert-93afaf47-20261105-r3","inert_exact_key");
 need(JSON.stringify(req.args)===JSON.stringify(["-I","-S","-B","-c",publisher]),"inert_exact_publisher_args");
 need(req.stdin===input.carrier&&utf8(input.carrier).length===403207&&hash(input.carrier)==="eb776f6c6224825da1460f87b37cb0f6db58f49d66e511195e3379f7a6e3cbc0","inert_exact_carrier_whole");
 need(carrier.schema==="heptabao.native-h2-qa-build-inputs.v1"&&Object.keys(carrier).sort().join(",")==="files,schema","carrier_schema");
 const pins={"build_native_h2_client_r1.py":"e42655d8e5d2ac89bc05f1f8ccba83b86e8ef361","inputs/native_h2_client.rs":"a959baa67acc8400cf1784a0fa747250420303c7","inputs/native_h2_client_tests.rs":"a01644e79af4095f6bef58fe6b4278ba07d6f000","inputs/Cargo.toml":"02b4af5013c3461114b3064cf277f615de7258db","inputs/canonical.Cargo.lock":"f3b5394e274d5da977e7e1ec89940b0d0e9f55ff","inputs/owned_reference_phaseb_r3.py":"03497f1ee45be3228de99ab4872ae2f9ca869de0","inputs/official_cli_reference_r4.py":"4a4a60d1d52a0fd835b467f1e4687ee95314d1de","build-binding.private.json":"38fc58cb834b150a01dd15fa23cdf80ad7a7d3f0"};
 need(Object.keys(carrier.files).sort().join(",")===Object.keys(pins).sort().join(","),"exact_eight_input_names");
 for(const [name,blob]of Object.entries(pins)){need(latin1(unb64(carrier.files[name]))===latin1(utf8(raw(blob))),"input_whole."+name);}
 const bind=JSON.parse(raw(pins["build-binding.private.json"])),oldBind=JSON.parse(raw("092aae1cdf1dccc9a84a17f27761306537cf3ba2"));
 need(JSON.stringify(bind.caps)===JSON.stringify(oldBind.caps),"all_original_caps_unchanged");
 need(bind.source===oldBind.source&&bind.target===oldBind.target&&JSON.stringify(bind.target_identity)===JSON.stringify(oldBind.target_identity)&&JSON.stringify(bind.tools)===JSON.stringify(oldBind.tools)&&JSON.stringify(bind.normal_product_result)===JSON.stringify(oldBind.normal_product_result),"original_source_target_tools_actual_normal_result_binding");
 need(bind.root==="/home/qian-qi/heptabao-native-h2-qa-df026-20261105-r3"&&bind.control==="/home/qian-qi/heptabao-native-h2-qa-controls-df026-20261105-r3","fresh_r3_literal_roots");
 const regression=JSON.parse(raw("bf6a509d4e43ea3fe238432a3c1b868bfc026350")),executor=JSON.parse(raw("b0f633cf72a614cf154f8bcd2b71b5861a53e730"));
 need(executor.exit_code===0&&executor.output===raw("bf6a509d4e43ea3fe238432a3c1b868bfc026350"),"actual_targeted_exec_zero_whole_stdout");
 need(regression.source_sha256===hash(after)&&regression.cancelled_raised_before_return===true&&regression.returned_output_after_cancel===false&&regression.report_cancel_signal===15&&regression.report_status==="failed"&&regression.fake_cleanup_calls===1&&regression.old_handlers_restored===true,"same_point_cancelled_no_return_once_cleanup_handlers_restored");
 need(regression.actual_children===0&&regression.actual_fds===0&&regression.actual_host_calls===0&&regression.actual_signals===0&&regression.full_module_executed===false,"regression_pure_selected_component_scope");
 const v=JSON.parse(raw("58c36fd0084fd67b6eafeaabd8d058a427b03216")),ve=JSON.parse(raw("399228872cf8a87fadb670cc1f89371b58c45a9f"));
 need(ve.exit_code===0&&ve.output===raw("58c36fd0084fd67b6eafeaabd8d058a427b03216"),"actual_37check_exec_whole_stdout");
 need(v.check_count===37&&v.checks.length===37&&v.checks.every(x=>x.passed===true)&&v.source_sha256===hash(after)&&v.inert_request_sha256===hash(input.request),"37_source_checks_bound_current_source_and_request");
 const plan=JSON.parse(raw("14c8f0128a7fd295c6c7d89516de79f1f5415d83"));need(plan.no_runtime_dispatch_in_this_packet===true&&plan.source_only===true,"source_only_no_dispatch_record");
 return {schema:"heptabao.qa-r3.draft2.root-source-review.v1",status:"PASS_SOURCE_ONLY_AND_INERT_READY",source_tree:input.audit.tree,files:input.audit.files,bytes:input.audit.bytes,merkle_trees:input.audit.merkle.trees_verified,checks,check_count:checks.length,previous_specific_late_cancel_blocker:"closed by four-line change and same-point selected-component actual negative",prior_draft_counterexample_preserved:true,original_eight_components_not_reexecuted:true,host_dispatches_by_this_verifier:0,actual_builder_qualification:false,current_product_qualification:false,full_replacement:false};
}
