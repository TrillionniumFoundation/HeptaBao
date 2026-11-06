function verify(input){
 const checks=[],ck=(name,ok)=>{checks.push({name,passed:ok===true});if(ok!==true)throw Error(name);};
 function apply(raw,diff,reverse=false){
  const base=raw.split("\n");ck("diff_base_final_lf_"+checks.length,base.pop()==="");
  const lines=diff.split("\n");ck("diff_final_lf_"+checks.length,lines.pop()==="");
  ck("diff_headers_"+checks.length,lines[0].startsWith("--- a/")&&lines[1].startsWith("+++ b/"));
  const out=[];let at=0,pos=2;
  while(pos<lines.length){
   const m=/^@@ -(\d+),(\d+) \+(\d+),(\d+) @@$/.exec(lines[pos++]);ck("hunk_header_"+checks.length,!!m);
   let os=+m[1],oc=+m[2],ns=+m[3],nc=+m[4];if(reverse)[os,oc,ns,nc]=[ns,nc,os,oc];
   const end=oc===0?os:os-1;
   ck("hunk_order_"+checks.length,end>=at&&end<=base.length);out.push(...base.slice(at,end));at=end;
   ck("hunk_output_offset_"+checks.length,out.length===(nc===0?ns:ns-1));
   let old=0,neu=0;
   while(pos<lines.length&&!lines[pos].startsWith("@@ ")){
    let tag=lines[pos][0],body=lines[pos++].slice(1);if(reverse)tag=tag==="+"?"-":tag==="-"?"+":tag;
    if(tag===" "||tag==="-"){if(base[at++]!==body)throw Error("strict_diff_context");old++;}
    if(tag===" "||tag==="+"){out.push(body);neu++;}
    if(![" ","+","-"].includes(tag)||old>oc||neu>nc)throw Error("strict_diff_counts");
   }
   ck("hunk_counts_"+checks.length,old===oc&&neu===nc);
  }out.push(...base.slice(at));return out.join("\n")+"\n";
 }
 ck("reference_collector_pin",gitBlobMeta(input.before).blob==="6346d622e31526522459ae4c1a2cdc858369d2ed");
 ck("strict_forward_source",apply(input.before,input.diff)===input.after);
 ck("strict_reverse_source",apply(input.after,input.diff,true)===input.before);
 ck("strict_forward_journal",apply(input.journalBefore,input.journalDiff)===input.journalAfter);
 ck("strict_reverse_journal",apply(input.journalAfter,input.journalDiff,true)===input.journalBefore);
 let staged=input.before;for(const x of input.replacements){if(staged.split(x.from).length-1!==x.count)throw Error("source_literal_count");staged=staged.split(x.from).join(x.to);}
 ck("literal_forward_exact",staged===input.after);for(const x of [...input.replacements].reverse())staged=staged.split(x.to).join(x.from);ck("literal_reverse_exact",staged===input.before);
 let jj=input.journalBefore;for(const x of input.journalReplacements){if(jj.split(x.from).length-1!==x.count)throw Error("journal_literal_count");jj=jj.replace(x.from,x.to);}ck("journal_only_three_literals",jj===input.journalAfter&&input.journalReplacements.length===3);
 const spans=raw=>{const m=[...raw.matchAll(/^(?:def|class) ([A-Za-z_][A-Za-z_0-9]*)[^\n]*/gm)],out={};for(let i=0;i<m.length;i++)out[m[i][1]]=raw.slice(m[i].index,i+1<m.length?m[i+1].index:raw.length);return out;};
 const bd=spans(input.before),ad=spans(input.after),changed=["open_inputs","read_inputs","validate_receipt","make_diffs","recheck_inputs_and_close","public_input_records","main"];
 ck("same_top_level_definition_names",JSON.stringify(Object.keys(bd))===JSON.stringify(Object.keys(ad)));
 for(const name of Object.keys(bd).filter(n=>!changed.includes(n)))ck("unchanged_definition_"+name,bd[name]===ad[name]);
 ck("entire_custody_class_byte_equal",bd.Custody===ad.Custody);
 const q=JSON.parse(input.request),sp=gitBlobMeta(input.after);
 ck("exact_original_invocation_shape",q.host==="rog"&&q.executable==="/usr/bin/python3"&&q.cwd==="/home/qian-qi"&&q.timeout_seconds===60&&q.stdin===undefined&&q.args.length===6&&JSON.stringify(q.args.slice(0,4))===JSON.stringify(["-I","-S","-B","-c"]));
 ck("inline_source_and_tail_sha",q.args[4]===input.after&&q.args[5]===sp.sha256);
 ck("stable_new_collector_key",q.idempotency_key==="heptabao-native-pki-lease400-format10-collector-20261106-r1-"+sp.sha256.slice(0,8));
 ck("journal_exact_request_pin",input.journalAfter.includes("const GF_REQUEST = "+JSON.stringify(gitBlobMeta(input.request))+";"));
 ck("fresh_collector_slot",input.journalAfter.includes('const GF_SLOT = "native_pki_lease400_formatter10_collector_gitfirst_r1";'));
 const embedded=JSON.parse(JSON.parse(/^ROWS=json.loads\((.*)\)$/m.exec(input.after)[1]));
 ck("embedded_ten_rows_exact",JSON.stringify(embedded)===JSON.stringify(input.rows)&&input.rows.length===10);
 ck("ten_unique_fixed_paths",new Set(input.rows.map(x=>x.path)).size===10&&input.rows.every((x,i)=>x.index===i));
 ck("original_fixed_file_roles",JSON.stringify(input.rows.map(x=>x.role))===JSON.stringify(["candidate","formatted","stdout","stderr","candidate","formatted","stdout","stderr","config","receipt"]));
 ck("input_bytes_543621",input.rows.reduce((n,x)=>n+x.bytes,0)===543621);
 ck("shared_read_cap_1424736",input.rows.reduce((n,x)=>n+x.cap,0)===1424736&&input.after.includes("READ_CAP=1424736"));
 ck("report_readback_inside_cap",543621+262144<=1424736&&ad.publish_report.includes('read_exact(c,out["fd"],len(raw),"report")')&&ad.Custody.includes("self.read_bytes"));
 ck("fd_acquisition_peak_counts",6+10+2===18&&6+10===16&&input.after.includes("FD_CAP=18")&&input.after.includes("PEAK_FD_CAP=16"));
 ck("all_caps_not_increased",input.after.includes("LIMIT=50.0")&&input.after.includes("DIFF_CAP=131072")&&input.after.includes("REPORT_CAP=262144")&&input.after.includes("READ_CALL_CAP=256")&&input.after.includes("META_CAP=320")&&input.after.includes("STDOUT_CAP=16384"));
 const receipt=parseLosslessIntegers(input.receipt),mp=parseLosslessIntegers(input.metadata);
 ck("receipt_pin",gitBlobMeta(input.receipt).blob==="6638b8f22581832b5451d8b79e275feccec54959"&&gitBlobMeta(input.receipt).bytes===4907);
 for(let i=0;i<2;i++){
  const f=receipt.files[i],a=input.rows[4*i],b=input.rows[4*i+1],o=input.rows[4*i+2],e=input.rows[4*i+3],pin=gitBlobMeta(input.candidates[i]);
  ck("candidate_blob_"+i,pin.blob===a.immutable_blob&&pin.sha256===a.sha256&&pin.bytes===a.bytes&&a.bytes===f.beforeBytes&&a.sha256===f.beforeSha256);
  ck("formatted_stdout_binding_"+i,b.bytes===f.afterBytes&&o.bytes===b.bytes&&b.sha256===f.afterSha256&&o.sha256===b.sha256);
  ck("empty_stderr_"+i,e.bytes===0&&e.sha256==="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"&&e.cap===65536);
 }
 ck("one_changed_one_unchanged_receipt",receipt.files.filter(x=>x.beforeSha256!==x.afterSha256).length===1);
 ck("full9_unobserved_eight_kept_null",input.rows.slice(0,8).every(x=>x.expected_full9===null));
 ck("config_lossless_full9",JSON.stringify(input.rows[8].expected_full9)===JSON.stringify(["66306","28071611","1000","1000","33152","1","17","1793944550719366866","1793944550719366866"]));
 ck("receipt_lossless_full9",JSON.stringify(input.rows[9].expected_full9)===JSON.stringify(["66306","28071628","1000","1000","33152","1","4907","1793944550782366173","1793944550782366173"]));
 ck("exact_receipt_content_row",input.rows[9].sha256===gitBlobMeta(input.receipt).sha256&&input.rows[9].immutable_blob===gitBlobMeta(input.receipt).blob);
 ck("source_base_only_truth",receipt.sourceIdentityIsBaseOnly===true&&receipt.uncommittedCandidateInputs===true&&input.after.includes('"source_identity_is_base_only":True,"uncommitted_candidate_inputs":True'));
 ck("candidate_provenance_not_canonical",!input.after.includes("canonical")&&input.after.includes("formatter_exact_supplied_candidate_provenance"));
 ck("no_checkout_guard_misrepresented",!input.after.includes("allFixedSourceInputsUnchanged")&&input.after.includes('receipt["inputOriginalAndCandidatePins"]==INPUT_ORIGINAL_AND_CANDIDATE_PINS'));
 ck("input_custody_guard_preserved",ad.open_inputs.includes('held.st_nlink==1 and held.st_mode==(stat.S_IFREG|0o600)')&&ad.open_inputs.includes('a==row["expected_full9"]'));
 ck("final_all_closed_and_original_deadline",ad.main.includes("len(c.ledger)==18")&&ad.main.includes("finally:\n  c.close_all()\n  c.restore()")&&ad.main.endsWith('if __name__=="__main__":\n sys.exit(main())\n'));
 return {schema:"heptabao.pki-formatter10-collector-source-checks.r1",scope:"Pure V8 source/data/strict-diff verification. No Python compilation, collector execution, Native read or product test.",passed:checks.length,checks,definition_count:Object.keys(bd).length,unchanged_definition_count:Object.keys(bd).length-changed.length,changed_definitions:changed};
}
