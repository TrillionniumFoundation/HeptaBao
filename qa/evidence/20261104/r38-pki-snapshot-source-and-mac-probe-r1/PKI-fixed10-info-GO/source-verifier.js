function reviewPkiFixed10ReportInfoSource(){
 const p=load("r34_packet_PKI-fixed10-report-info-source21"),r=p.raw,plan=JSON.parse(r["PLAN.public.json"]),go=load("r38_pki_fixed10_GO"),terminal=load("r38_pki_fixed10_terminal_qualification"),checks=[];
 const ck=(name,v)=>{checks.push({name,passed:v===true});if(v!==true)throw Error(name);},same=(a,b)=>JSON.stringify(a)===JSON.stringify(b),eq=(s,p)=>{const m=gitBlobMeta(s);return m.blob===p.blob&&m.bytes===p.bytes&&m.sha256===p.sha256;};
 ck("whole_source21_222133",p.audit.whole===true&&p.audit.files===21&&p.audit.bytes===222133);
 ck("previous_original_terminal_qualified",terminal.value.evidence_qualified===true&&terminal.value.check_count===55&&terminal.value.original_job==="rog/1a1af917594-fc05-69b4");
 ck("old_journal_and_helpers_exact_unchanged",eq(r["journal.before.js"],go.value.helpers.native)&&eq(r["journal.archive.unchanged.js"],go.value.helpers.archive)&&eq(r["journal.pure.unchanged.js"],go.value.helpers.pure));
 ck("plan_source_and_exact_pins",eq(r["journal.before.js"],plan.base_source)&&eq(r["journal.after.js"],plan.candidate)&&eq(r["request.file_info.REVIEW-ONLY.public.json"],plan.exact_request));
 const f=strictApply(r["journal.before.js"],r["journal.strict.diff"]),b=strictApply(r["journal.after.js"],r["journal.strict.diff"],true);
 ck("six_hunks_bidirectional_whole",f.hunks===6&&b.hunks===6&&f.text===r["journal.after.js"]&&b.text===r["journal.before.js"]);
 let derived=r["journal.before.js"];const replacements=JSON.parse(r["journal.replacements.public.json"]);
 ck("seven_literal_edits",replacements.length===7);
 for(let i=0;i<replacements.length;i++){const q=replacements[i];ck("unique_literal_"+i,derived.split(q.before).length===2);derived=derived.replace(q.before,q.after);}
 ck("literal_reconstruction_whole",derived===r["journal.after.js"]);
 const after=r["journal.after.js"],old=r["reference.approved-JWT38-info.js"];
 ck("approved_reference_exact_blob",gitBlobMeta(old).blob==="af433566033040ecec7971ba30af9997f1073ef4");
 function normalized(s){
  for(const k of ["GF_SLOT","GF_REQUEST","GF_COLLECTOR_REPORT_EXPECTED","GF_COLLECTOR_REPORT_INFO_REQUEST","GF_COLLECTOR_REPORT_INFO_PREREQUISITES"])s=s.replace(new RegExp("^const "+k+" = [\\s\\S]*?;\\n","m"),"const "+k+" = <BINDING>;\n");
  return s.replaceAll("1a1af3d52ee-fc05-6701","<JOB>").replaceAll("1a1af917594-fc05-69b4","<JOB>")
   .replaceAll("s.nextStdout===7947","s.nextStdout===<BYTES>").replaceAll("s.nextStdout===4775","s.nextStdout===<BYTES>")
   .replaceAll("heptabao.native-jwt-formatter38-terminal.v1","<SCHEMA>").replaceAll("heptabao.native-pki-formatter10-terminal.v1","<SCHEMA>")
   .replaceAll("terminal.fd_ledger.length===46","terminal.fd_ledger.length===<FDS>").replaceAll("terminal.fd_ledger.length===18","terminal.fd_ledger.length===<FDS>")
   .replaceAll("heptabao-native-jwt-e3afc157-format38-observe-r1-","<KEY>").replaceAll("heptabao-native-pki-lease400-format10-observe-r1-","<KEY>");
 }
 ck("whole_approved_reference_logic_identical_after_fixed_binding_normalization",normalized(after)===normalized(old));
 new Function(after);
 ck("javascript_syntax_parse_only_no_candidate_function_invoked",true);
 const getConst=name=>JSON.parse(after.match(new RegExp("^const "+name+" = (.*);$","m"))[1]);
 const ex=getConst("GF_COLLECTOR_REPORT_EXPECTED"),qr=getConst("GF_COLLECTOR_REPORT_INFO_REQUEST"),pr=getConst("GF_COLLECTOR_REPORT_INFO_PREREQUISITES"),tr=terminal.value.reported_public_report;
 ck("only_actual_report_path_size_hash_version_full9",same(ex,{path:tr.path,bytes:tr.bytes,sha256:tr.sha256,version:tr.version,full9:tr.full9})&&same(ex,plan.expected_report_from_original_stdout));
 const q=JSON.parse(r["request.file_info.REVIEW-ONLY.public.json"]);
 ck("exact_one_fixed_file_info_request",same(q.operation,{tool:"file_info",arguments:{host:"rog",path:tr.path}})&&q.idempotency_key==="heptabao-native-pki-lease400-format10-observe-r1-report-info"&&eq(r["request.file_info.REVIEW-ONLY.public.json"],qr));
 const actual=load("r34_packet_PKI-fixed10-collector-full-actual64"),obs=JSON.parse(actual.raw["OBSERVERS.public.json"]);
 ck("prerequisites_exact_original_two_closed_observers",same(pr,obs.map(o=>({id:o.id,tool:o.tool,nativeText:o.nativeText})))&&same(plan.required_old_observers,obs));
 ck("original_authority_stream_stdout_bytes_unchanged",r["actual.authority.native.original.json"]===actual.raw["authority.native.original.json"]&&r["actual.stdout.original.txt"]===actual.raw["stdout.original.json"]&&r["actual.streams.native.original.json"]===actual.raw["observer02.native.original.json"]);
 ck("attach_original_slot_no_initialization_or_process_replay",plan.no_reinitialize===true&&plan.original_slot===go.value.slot&&plan.original_job==="1a1af917594-fc05-69b4"&&plan.existing_process_start_replay_authorized===false);
 ck("one_info_and_original_page_caps",plan.maximum_file_info_starts===1&&plan.binary_read_authorized===false&&plan.immutable_page_bytes===8192&&plan.maximum_immutable_payload_bytes===1048576&&plan.scope==="collector_report_file_info_only");
 ck("separate_whole_GO_original_closure_guard",after.includes("goPin.blob!==s.goPin.blob")&&after.includes("s.collectorReportInfoGO===undefined")&&after.includes("s.activeObserver===null && s.startCalled===true")&&after.includes("s.collectorReportInfoStarted!==true"));
 ck("call_armed_once_marker_and_new_GO_lineage",after.includes('if(c.kind==="operation_start" && q.operation.tool==="file_info")s.collectorReportInfoStarted=true;')&&after.includes('|| s.activeObserver?.tool==="file_info" ? s.collectorReportInfoGO.pin : s.goPin'));
 ck("metadata_exact_linux_0600_uid_gid_single_link_lossless_full9",after.includes('md?.metadata_platform==="linux" && md.mode===384')&&after.includes("md.uid===1000 && md.gid===1000 && md.link_count===1")&&after.includes('JSON.stringify(full9)===JSON.stringify(GF_COLLECTOR_REPORT_EXPECTED.full9)'));
 ck("proposal_body_not_enabled_or_submitted",plan.proposed_body_scope.submitted===0&&plan.proposed_body_scope.runtime_authorized===false&&plan.proposed_body_scope.journal_authorization_implemented===false&&!after.includes('op.tool==="binary_read"')&&!after.includes('action==="authorize_collector_report_body"'));
 return {schema:"heptabao.root-source-review.PKI-fixed10-report-info.v1",status:"SOURCE_REVIEWED_FOR_SEPARATE_EXACT_INFO_GO",checks,check_count:checks.length,source_packet:p.audit,source:plan.candidate,exact_request:plan.exact_request,original_terminal_qualification:{blob:terminal.blob,bytes:terminal.bytes,sha256:terminal.sha256},original_job:plan.original_job,report_expected:ex,review:{whole_reference_logic_identical_after_only_fixed_binding_changes:true,seven_literal_edits_six_hunks:true,source_guards_reviewed:true,candidate_function_invoked:false,native_calls:0},body_authorized:false,compile_or_product_qualified:false,full_replacement:false,production_cutover:false,legacy_cleanup:false,root_Runtime_calls:0};
}