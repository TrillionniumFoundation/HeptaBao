function verifyIndependentLabelPidSource(input){
 const checks=[],ck=(name,ok)=>checks.push({name,pass:ok===true});
 const {before,after,forward,reverse,journalBefore,journalAfter,journalForward,journalReverse,requestBefore,requestAfter}=input;
 const oldQ=JSON.parse(requestBefore),newQ=JSON.parse(requestAfter);
 ck("forward_exact",strictApplySource(before,forward).raw===after);
 ck("reverse_exact",strictApplySource(after,reverse).raw===before);
 ck("source_hunks_7_7",strictApplySource(before,forward).hunks===7&&strictApplySource(after,reverse).hunks===7);
 ck("journal_forward_exact",strictApplySource(journalBefore,journalForward).raw===journalAfter);
 ck("journal_reverse_exact",strictApplySource(journalAfter,journalReverse).raw===journalBefore);
 ck("journal_hunks_2_2",strictApplySource(journalBefore,journalForward).hunks===2&&strictApplySource(journalAfter,journalReverse).hunks===2);
 function blocks(raw){
  const re=/^(?:class|def) ([A-Za-z_][A-Za-z_0-9]*)[^\n]*/gm,starts=[...raw.matchAll(re)];
  return Object.fromEntries(starts.map((m,i)=>[m[1],raw.slice(m.index,starts[i+1]?.index??raw.length)]));
 }
 const old=blocks(before),now=blocks(after),changed=new Set(["FixedCurrentPid","require_current_pid_mapping","main"]);
 for(const [name,raw] of Object.entries(old))if(!changed.has(name))ck("unchanged_definition:"+name,now[name]===raw);
 ck("exact_definition_set",Object.keys(now).sort().join(",")===Object.keys(old).map(x=>x==="require_current_pid_mapping"?"classify_current_pid_mapping":x).sort().join(","));
 ck("constants_and_embedded_helpers_whole",before.slice(0,before.indexOf("class ProbeRefused"))===after.slice(0,after.indexOf("class ProbeRefused")));
 function method(raw,name){
  const begin=raw.indexOf("    def "+name+"(");if(begin<0)return null;
  const next=raw.indexOf("\n    def ",begin+1);return raw.slice(begin,next<0?raw.length:next+1);
 }
 for(const name of ["__init__","check_time","call","lifetime","verify_self","public"])ck("unchanged_sampler_method:"+name,method(old.FixedCurrentPid,name)===method(now.FixedCurrentPid,name));
 const main=now.main,numeric=method(now.FixedCurrentPid,"numeric"),pair=method(now.FixedCurrentPid,"pair"),mapping=now.classify_current_pid_mapping;
 ck("self_numeric_remains_strict",method(now.FixedCurrentPid,"verify_self").includes("self.numeric(os.getpid(),until_ns)")&&!method(now.FixedCurrentPid,"verify_self").includes("observe_only"));
 ck("strict_numeric_conditions_preserved",numeric.includes("complete = count == 136 and number == 0 and info.pid == pid")&&numeric.includes("need(complete,'current_pid_complete_numeric_sample')")&&numeric.includes("need(shape,'current_pid_numeric_shape')"));
 ck("target_observation_only_two_callsites",(pair.match(/observe_only=True/g)||[]).length===2);
 ck("target_numeric_scoped_exact",pair.includes("self.numeric(EXPECTED_CURRENT_PID,until_ns,observe_only=True)")&&!pair.includes("self.numeric(os.getpid()"));
 ck("numeric_esrch_is_classification",numeric.includes("'esrch_returned' if count == 0 and number == errno.ESRCH")&&numeric.includes("'metadata':None"));
 ck("no_esrch_exit_or_reap_claim",pair.includes("'pidExitOrHistoricalReapClaimed':False")&&main.includes("'pidExitOrReapClaimed':False"));
 ck("conditional_path_and_children",pair.indexOf("if first is not None:")<pair.indexOf("self.lib.proc_pidpath")&&pair.indexOf("if first is not None:")<pair.indexOf("self.lib.proc_listchildpids"));
 ck("second_numeric_outside_conditional",pair.includes("\n        second_observed = self.numeric(EXPECTED_CURRENT_PID,until_ns,observe_only=True)"));
 ck("missing_label_only_classified",mapping.includes("if print_record['registrationAbsent']:")&&mapping.includes("'exact_missing_registration'")&&!mapping.includes("need("));
 ck("two_label_classifications",(main.match(/classify_current_pid_mapping\(/g)||[]).length===2&&!main.includes("require_current_pid_mapping("));
 ck("original_first_and_second_prints",main.includes("first,first_value = control.query(1)")&&main.includes("second,second_value = control.query(2)"));
 ck("public_files_before_second_print",main.indexOf("observe_public_json(io,READY")<main.indexOf("control.query(2)")&&main.indexOf("io.observe_metadata(STDERR)")<main.indexOf("control.query(2)"));
 ck("target_pair_both",main.includes("identity_first = sampler.pair(1,native_until_first)")&&main.includes("identity_second = sampler.pair(2,native_until_second)"));
 ck("current_mapping_still_required_for_future_identity",main.includes("result['currentLabelMappingSameFixedPidBoth'] and result['currentIdentityKernelMetadataComplete']")&&main.includes("result['currentKnownPythonIdentityMatched'] and result['currentDirectChildrenEmptyBoth']"));
 ck("no_none_lifetime_dereference",main.includes("identity_first['sameLifetimeWithinPair'] and identity_second['sameLifetimeWithinPair']")&&pair.includes("first is not None and second is not None"));
 ck("new_numeric_caps_unchanged",numeric.includes("self.numeric_calls < 6")&&pair.includes("self.path_calls < 2")&&pair.includes("self.child_calls < 2")&&method(now.FixedCurrentPid,"call").includes("len(self.rows) < 10"));
 ck("same_two_four_second_windows",(main.match(/time.monotonic_ns\(\)\+4000000000/g)||[]).length===2&&(main.match(/min\(PARENT_UNTIL_NS,HELPER_ADMISSION_END_NS,/g)||[]).length===2);
 ck("same_application_io_caps",main.includes("FixedIO(signals,remaining,read_cap=262144,write_cap=0)"));
 ck("remaining_unknown_and_original_finally",main.slice(main.indexOf("    finally:"))===old.main.slice(old.main.indexOf("    finally:")));
 ck("original_final_file_fences",main.slice(main.indexOf("        stage = 'final_fixed_file_fences'"),main.indexOf("    except BaseException"))===old.main.slice(old.main.indexOf("        stage = 'final_fixed_file_fences'"),old.main.indexOf("    except BaseException")));
 ck("request_source_exact",newQ.stdin===after&&oldQ.stdin===before);
 ck("request_metadata_unchanged",JSON.stringify({...newQ,stdin:null,idempotency_key:null})===JSON.stringify({...oldQ,stdin:null,idempotency_key:null}));
 ck("exact_new_key",newQ.idempotency_key==="heptabao-mac-current-home-pid-observation-"+gitBlobMeta(after).sha256.slice(0,8)+"-20261106-r2");
 ck("journal_exact_request",journalAfter.includes(gitBlobMeta(requestAfter).blob)&&journalAfter.includes(gitBlobMeta(requestAfter).sha256)&&journalAfter.includes("bytes:"+gitBlobMeta(requestAfter).bytes));
 let normalized=journalAfter.replace("owner_authbus_home_r2_current_pid_observation_gitfirst_r2","owner_authbus_home_r2_current_pid_identity_gitfirst_r1").replace(gitBlobMeta(requestAfter).blob,gitBlobMeta(requestBefore).blob).replace("bytes:"+gitBlobMeta(requestAfter).bytes+",sha256:"+JSON.stringify(gitBlobMeta(requestAfter).sha256),"bytes:"+gitBlobMeta(requestBefore).bytes+",sha256:"+JSON.stringify(gitBlobMeta(requestBefore).sha256)).replace("heptabao-mac-current-home-pid-observation-"+gitBlobMeta(after).sha256.slice(0,8)+"-","heptabao-mac-current-home-pid-identity-6a1ee2c4-");
 ck("journal_only_identity_literals",normalized===journalBefore);
 return {schema:"heptabao.independent-label-pid-source-mechanical-review.r2",passed:checks.every(x=>x.pass),checkCount:checks.length,checks,pythonExecuted:false,compiledOrImportedCandidate:false,newNativeCalls:0,scope:"pure source whole/diff/binding and unchanged resource boundaries; no runtime qualification"};
}
