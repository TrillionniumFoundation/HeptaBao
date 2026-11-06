
function verifyJwtFixed38Report(){
 const checks=[],ck=(name,yes)=>{checks.push({name,passed:!!yes});if(!yes)throw Error(name);};
 const p=load("r34_packet_JWT-fixed38-collector-source"),r=load("r37_jwt_fixed38_actual_report_lossless"),rp=load("r37_jwt_fixed38_actual_report");
 const fixed=JSON.parse(p.raw["fixed-inputs.public.json"]),canonical=load("r34_jwt_formatter_nine_canonical"),receipt=load("r35_jwt_formatter_actual_receipt_lossless"),receiptPin=load("r35_jwt_formatter_actual_receipt");
 const prior=load("r36_jwt_formatter_receipt_actual_root_qualification"),term=load("r37_jwt_fixed38_terminal_qualification"),info=load("r37_jwt_report_info_actual_qualification"),go=load("r37_jwt_report_body_GO").value;
 const eq=(a,b)=>JSON.stringify(a)===JSON.stringify(b),metaEq=(text,p)=>{const m=gitBlobMeta(text);return m.bytes===p.bytes&&m.sha256===p.sha256&&(!p.blob||m.blob===p.blob);};
 ck("exact_whole_report_original_terminal_info_GO",rp.blob==="440710a38a76bc46aacb717446817c278e971812"&&rp.bytes===167436&&rp.sha256===go.fixed_report.sha256&&metaEq(rp.text,rp)&&term.value.evidence_qualified===true&&info.value.evidence_qualified===true);
 ck("receipt_prior_original_qualification",prior.value.passed===true&&metaEq(receiptPin.text,receiptPin)&&receiptPin.blob===r.formatter_receipt.receipt_blob&&receiptPin.sha256===r.formatter_receipt.receipt_sha256&&receipt.compileExecuted===false);
 ck("exact_schema_source_provenance",r.schema==="heptabao.native-jwt-formatter38-observation.v1"&&r.source_commit==="e3afc157447d35c861f275a761b29da3e42aff8e"&&r.source_tree==="5497775d9d473541e13e1603be8c893a3e27681b"&&r.collector_source_sha256===gitBlobMeta(p.raw["collector.source.py"]).sha256&&r.formatter_source_blob==="1266e75033bee0962b0d77d3c35ee19ec53086db");
 ck("exact38_fixed_order_and_paths",r.input_files.length===38&&fixed.length===38&&new Set(r.input_files.map(f=>f.path)).size===38&&r.input_count===38);
 ck("lossless_full9_field_order",eq(r.identity_fields,["dev","ino","uid","gid","full_mode","nlink","size","mtime_ns","ctime_ns"]));
 const reconstructed={},artifacts=[],diffRecords=[],names=Object.keys(canonical),tree=load("r34_jwt_formatter_canonical_tree_check").tree;
 ck("exact_canonical_tree_and_nine_names",tree.sha===r.source_tree&&tree.truncated===false&&r.diffs.length===9&&eq(r.diffs.map(d=>d.name),names));
 for(let i=0;i<r.diffs.length;i++){
  const d=r.diffs[i],c=canonical[d.name],before=c.text,cm=gitBlobMeta(before),rf=receipt.files.find(x=>x.name===d.name);
  const leaf=tree.tree.find(x=>x.path==="crates/heptabao-server/src/"+d.name);
  ck("canonical_"+d.name,metaEq(before,c)&&leaf?.sha===c.blob&&cm.bytes===d.before_bytes&&cm.sha256===d.before_sha256&&d.canonical_candidate_blob===c.blob&&rf.beforeBytes===cm.bytes&&rf.beforeSha256===cm.sha256);
  const dm=gitBlobMeta(d.unified_diff);
  ck("diff_pin_"+d.name,dm.bytes===d.diff_bytes&&dm.sha256===d.diff_sha256&&((d.changed&&d.unified_diff.startsWith("--- a/"+d.name+"\n+++ b/"+d.name+"\n")&&d.unified_diff.endsWith("\n"))||(!d.changed&&d.unified_diff==="")));
  const applied=d.changed?strictApply(before,d.unified_diff):{text:before,hunks:0},after=applied.text,am=gitBlobMeta(after);
  ck("strict_bidirectional_reconstruction_"+d.name,(d.changed?strictApply(after,d.unified_diff,true).text:after)===before&&am.bytes===d.after_bytes&&am.sha256===d.after_sha256&&rf.afterBytes===am.bytes&&rf.afterSha256===am.sha256&&d.changed===(before!==after)&&d.strict_forward_equal===true&&d.strict_reverse_equal===true);
  ck("stdout_stderr_receipt_"+d.name,d.stdout_byte_equal===true&&d.stderr_empty===true&&rf.stderrBytes===0&&rf.stderrSha256===gitBlobMeta("").sha256);
  reconstructed[d.name]={name:d.name,path:"crates/heptabao-server/src/"+d.name,text:after,...am,changed:d.changed,before:{blob:c.blob,bytes:c.bytes,sha256:c.sha256},diff:{blob:dm.blob,bytes:dm.bytes,sha256:dm.sha256,hunks:applied.hunks}};
  artifacts.push({name:d.name,text:after});diffRecords.push({name:d.name,before:reconstructed[d.name].before,after:am,changed:d.changed,diff:reconstructed[d.name].diff});
 }
 for(let i=0;i<38;i++){
  const f=r.input_files[i],e=fixed[i],b=f.before_full9;
  ck("fixed_input_"+i,f.index===i&&e.index===i&&f.role===e.role&&f.name===e.name&&f.path===e.path&&f.bytes===e.bytes&&f.sha256===e.sha256&&f.original_file_cap===e.cap&&f.canonical_blob===e.canonical_blob&&eq(f.prior_full9,e.expected_full9)&&f.read_bytes===f.bytes&&f.bytes<=f.original_file_cap&&f.eof===true&&f.read_calls===Math.ceil(f.bytes/65536)+1);
  ck("full9_identity_"+i,Array.isArray(b)&&b.length===9&&b.every(x=>typeof x==="string"&&/^\d+$/.test(x))&&b[2]==="1000"&&b[3]==="1000"&&b[4]==="33152"&&b[5]==="1"&&b[6]===String(f.bytes)&&eq(b,f.named_before_full9)&&eq(b,f.read_after.held)&&eq(b,f.read_after.named)&&eq(b,f.final_after.held)&&eq(b,f.final_after.named)&&(!f.prior_full9||eq(b,f.prior_full9))&&f.version===[b[0],b[1],b[6],b[7],b[8]].join(":"));
  ck("input_close_"+i,f.once_close_attempted===true&&f.once_close_completed===true&&f.close_error===null);
  let bytes;
  if(f.role==="candidate")bytes=canonical[f.name].text;
  else if(f.role==="formatted"||f.role==="stdout")bytes=reconstructed[f.name].text;
  else if(f.role==="stderr")bytes="";
  else if(f.role==="config")bytes=r.configuration_utf8;
  else if(f.role==="receipt")bytes=receiptPin.text;
  else throw Error("unexpected_role");
  ck("reconstructed_input_"+i,metaEq(bytes,{bytes:f.bytes,sha256:f.sha256,blob:f.canonical_blob}));
 }
 const sum=(a,f)=>a.reduce((n,x)=>n+f(x),0),input=r.input_files;
 ck("exact_actual_totals_and_caps",r.source_bytes===1221466&&r.formatted_bytes===1228699&&r.input_bytes===3701083&&r.diff_total_bytes===73228&&r.changed_files===6&&r.unchanged_files===3&&sum(input,x=>x.bytes)===r.input_bytes&&sum(fixed,x=>x.cap)===r.original_read_cap&&r.original_read_cap===7906155&&sum(r.diffs,x=>x.before_bytes)===r.source_bytes&&sum(r.diffs,x=>x.after_bytes)===r.formatted_bytes&&sum(r.diffs,x=>x.diff_bytes)===r.diff_total_bytes&&r.diffs.filter(d=>d.changed).length===6);
 const config=r.input_files[36],actualConfig=receipt.formatConfigurationAfter,old=actualConfig.identity.map(x=>typeof x==="object"?x.$exactInteger:String(x)),converted=[old[0],old[1],old[6],old[7],old[5],old[8],old[2],old[3],old[4]];
 ck("explicit_edition2024_config_and_actual_identity",r.configuration_utf8==='edition = "2024"\n'&&config.sha256===actualConfig.sha256&&eq(config.before_full9,converted)&&config.path===actualConfig.path);
 ck("receipt_actual_input_exact_pin",r.input_files[37].canonical_blob===receiptPin.blob&&r.input_files[37].bytes===receiptPin.bytes&&r.input_files[37].sha256===receiptPin.sha256);
 ck("original_direct_child_semantics_preserved",r.formatter_receipt.job_id==="1a1af017fae-fc05-64f1"&&r.formatter_receipt.direct_children_reaped===9&&r.formatter_receipt.same_supervisor_pgid===true&&r.formatter_receipt.independent_group_empty_observed===false&&r.formatter_receipt.compile_executed===false);
 const dirNames=["root","home","user","input","candidate","formatted"];
 ck("six_fixed_directory_identities",Object.keys(r.directories_before).length===6&&Object.keys(r.directories_after_inputs).length===6&&dirNames.every(n=>{const a=r.directories_before[n],b=r.directories_after_inputs[n];return a&&b&&eq(a.full9,b.held)&&eq(a.full9,b.named)&&a.shared_identity_only===["root","home","user"].includes(n);}));
 const cnt=r.counters_before_publication,terminal=term.value.actual.counters;
 ck("prepublication_counters_and_original_limits",cnt.fd_acquisition_attempts===44&&cnt.fd_acquisitions===44&&cnt.peak_owned_fds===44&&cnt.input_read_bytes===r.input_bytes&&cnt.read_bytes===r.input_bytes&&cnt.read_calls===sum(input,x=>x.read_calls)&&cnt.metadata_calls===252&&cnt.read_calls<=256&&cnt.metadata_calls<=320&&cnt.fsync_calls===0&&cnt.write_bytes===0&&cnt.report_read_bytes===0&&r.elapsed_seconds_before_publication>0&&r.elapsed_seconds_before_publication<50&&terminal.fd_acquisitions===46&&terminal.input_read_bytes===r.input_bytes);
 ck("input_complete_before_output_and_finally_distinction",r.input_observation_complete===true&&r.input_observations_are_sequential===true&&r.input_fds_closed_before_report_publication===true&&r.all_38_input_fds_once_closed===true&&r.output_and_directory_fd_closure_requires_final_stdout_and_authority===true&&term.value.actual.all46_owned_FDs_closed===true);
 ck("scope_no_runtime_or_input_mutation",r.child_count===0&&r.directory_listings===0&&r.network_calls===0&&r.original_input_writes===0&&r.cargo_executed===false&&r.product_executed===false);
 const v={schema:"heptabao.root-qualification.JWT-fixed38-actual-report-and-reconstruction.v1",status:"PASS_REPORT_CONTENT_AND_STRICT_SOURCE_RECONSTRUCTION_PENDING_ORIGINAL_BODY_JOURNAL",evidence_qualified:false,report_content_qualified:true,body_original_chain_qualified:false,checks,check_count:checks.length,report:{blob:rp.blob,bytes:rp.bytes,sha256:rp.sha256},source_commit:r.source_commit,source_tree:r.source_tree,receipt:{blob:receiptPin.blob,bytes:receiptPin.bytes,sha256:receiptPin.sha256},terminal_qualification:{blob:term.blob,bytes:term.bytes,sha256:term.sha256},file_info_qualification:{blob:info.blob,bytes:info.bytes,sha256:info.sha256},diff_records:diffRecords,actual:{input_files:38,input_bytes:r.input_bytes,source_bytes:r.source_bytes,formatted_bytes:r.formatted_bytes,changed_files:6,unchanged_files:3,strict_forward_and_inverse:true,all_input_files_same_held_named_full9:true,all38_input_FDs_closed:true,terminal46_FDs_closed:true},limitations:["Sequential file observations with held/named before/after checks are not an atomic filesystem snapshot.","Original formatter direct children shared the supervisor process group; independent per-child group emptiness is not claimed.","Content reconstruction is supported by actual pinned formatter/report and exact bidirectional diffs, not compiler or product execution."],compile_qualified:false,product_qualified:false,full_replacement:false,production_cutover:false,legacy_cleanup:false,root_Runtime_calls:0};
 store("r37_jwt_formatted_nine_reconstructed",reconstructed);store("r37_jwt_report_content_qualification_value",v);store("r37_jwt_formatted_nine_artifacts",artifacts);
 return {status:v.status,checks:v.check_count,report:v.report,reconstructed:diffRecords.map(x=>({name:x.name,blob:x.after.blob,bytes:x.after.bytes,changed:x.changed,hunks:x.diff.hunks}))};
}
