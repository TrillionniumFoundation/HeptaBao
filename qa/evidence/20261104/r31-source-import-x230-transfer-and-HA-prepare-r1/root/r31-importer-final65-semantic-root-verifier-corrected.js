function verifyImporterFinalArchive(d) {
  const checks = []; const ok=(v,n)=>{if(!v) throw new Error(n); checks.push(n);};
  const canon=v=>JSON.stringify((function walk(x){if(Array.isArray(x))return x.map(walk); if(x&&typeof x==="object")return Object.fromEntries(Object.keys(x).sort().map(k=>[k,walk(x[k])])); return x;})(v));
  const equal=(a,b)=>canon(a)===canon(b);
  const r=d.raw, a=new Map(d.audit.records.map(x=>[x.path,x])), core=d.lossless(r["actual/result.public.json"]), state=JSON.parse(r["STATE.public.json"]), rep=JSON.parse(r["actual/65-file-content-representations.public.json"]);
  const plan=JSON.parse(r["plan/finite-original-file-read-plan.public.json"]), planned=[...plan.small_files,...plan.large_files];
  ok(d.audit.tree==="52f3258ff47319da11db9c6f586687ab31b1fc99"&&d.audit.files===289&&d.audit.bytes===2556370&&d.audit.merkle.trees_verified===110,"final289-whole-blob-and-Merkle-audit");
  ok(r["actual/result.public.json"]===d.previous["actual/result.public.json"],"core-byte-exact-to-root91-qualified-scope");
  const old=Object.keys(d.previous).filter(p=>!["MANIFEST.public.json","STATE.public.json","README.md"].includes(p));
  ok(old.length===112&&old.every(p=>r[p]===d.previous[p]),"112-prior-original-paths-byte-exact-aggregate-successors-distinguished");
  ok(r["plan/finite-original-file-read-plan.public.json"]===d.planRaw,"original65-read-plan-unmodified");
  ok(rep.entries.length===65&&new Set(rep.entries.map(x=>x.path)).size===65&&planned.length===65,"exact65-unique-content-representations");
  ok(rep.native_small_file_reads===63&&rep.canonical_reconstructed_large_representations===2&&rep.current_host_large_body_RPC_count===0&&rep.root_reuse_GO==="f7eda3b5696e478342b58999871788d009fef97a","truthful63-native-plus2-measured-canonical-content-origin");
  const byPath=new Map(rep.entries.map(e=>[e.path,e]));
  for(const p of planned){
    const e=byPath.get(p.path), pin=e&&a.get(e.artifact);
    ok(!!e&&e.kind===p.kind&&!!pin&&pin.blob===e.content_blob&&pin.bytes===e.bytes&&pin.sha256===e.sha256&&("bytes"in p?p.bytes===e.bytes:true)&&("sha256"in p?p.sha256===e.sha256:true),"content-pin:"+p.path.split("/").pop());
    if(plan.small_files.includes(p))ok(e.content_origin==="ACTUAL_NATIVE_READ_MULTIPLE_FILES_WHOLE"&&e.atomic_snapshot===false&&e.snapshot_scope==="independent_file"&&/^2050:[0-9]+:[0-9]+:[0-9]+:[0-9]+$/.test(e.version)&&e.version.split(":")[2]===String(e.bytes)&&typeof e.original_observation==="string"&&/^[0-9a-f]{64}$/.test(e.operation_id),"native-version-origin:"+p.path.split("/").pop());
  }
  ok(rep.entries.filter(e=>e.content_origin==="ACTUAL_NATIVE_READ_MULTIPLE_FILES_WHOLE").reduce((s,e)=>s+e.bytes,0)===61389&&rep.entries.reduce((s,e)=>s+e.bytes,0)===950565,"65-content-byte-totals");
  ok(core.commands.length===21,"21-original-command-records");
  const controls=plan.fixed_control;
  for(const c of core.commands){
    const record=byPath.get(controls+"/"+c.label+".public.json");
    ok(record&&equal(d.lossless(r[record.artifact]),c),"record-lossless-equals-independent-core:"+c.label);
    for(const stream of ["stdout","stderr"]){
      const e=byPath.get(controls+"/"+c.label+"."+stream);
      ok(e&&e.bytes===c[stream+"_bytes"]&&e.sha256===c[stream+"_sha256"],"original-stream-size-and-whole-hash:"+c.label+":"+stream);
    }
  }
  const controller=byPath.get(controls+"/importer.py");
  ok(controller.content_blob==="e19892771c202552ca73905b78455ffeeaf26d7d"&&r[controller.artifact]===d.previous["execution/intent/reviewed-importer.py"],"actual-saved-controller-byte-exact-reviewed-source");
  const intent=d.lossless(r[byPath.get(controls+"/intent.public.json").artifact]);
  ok(equal(intent.controller,core.controller)&&equal(intent.input_files_before,core.input_files_before)&&intent.source_commit===core.source_commit&&intent.source_tree===core.source_tree&&intent.source+"/.git"===core.source_after.git_directory&&intent.overall_seconds===300&&intent.git_command_seconds===60&&intent.clone_seconds===90&&intent.maximum_bundle_bytes===67108864,"actual-preexecution-intent-inputs-source-and-original-budgets");
  ok(intent.source_imported===false&&intent.status==="failed"&&intent.product_tests_executed===0&&intent.production_changed===false,"preexecution-intent-not-misrepresented-as-terminal-success");
  const get=s=>r[byPath.get(controls+"/"+s).artifact];
  ok(get("005-canonical-kind.stdout")==="commit\n"&&get("006-canonical-tree.stdout")==="eba5e650bd080b8ad41ea52a2bc68867f541d255\n"&&get("007-canonical-parents.stdout")==="1c66541993662f92cf717154e33717abedb2ea74\n"&&get("008-canonical-count.stdout")==="3763\n"&&get("009-canonical-roots.stdout")==="67d79b3b5442ed033d38929eab2010403463e56d\n","original-raw-canonical-history-command-output");
  ok(get("014-source-after-head.stdout")==="4e808d0ecb1bcded22870a7ec960dfb2491cf6ec\n"&&get("015-source-after-tree.stdout")==="eba5e650bd080b8ad41ea52a2bc68867f541d255\n"&&get("016-source-after-status.stdout")===""&&get("018-source-after-common-dir.stdout")===".git\n"&&get("019-source-after-shallow.stdout")==="false\n","original-raw-clean-independent-source-command-output");
  for(let i=0;i<2;i++){
    const f=d.reuse.files[i],e=byPath.get(f.path);
    ok(e.content_origin==="CANONICAL_GIT_TREE_RECONSTRUCTION_BOUND_TO_CURRENT_NATIVE_FULL_FILE_SHA"&&e.content_blob===f.reconstructed_content_blob&&e.current_file_info_blob===f.current_info_blob&&e.current_file_info_operation===f.current_info_operation&&equal(e.full9_decimal,f.full9_decimal)&&e.version===f.version&&e.current_host_body_RPC_count===0&&e.replaced_unsubmitted_body_slots===7&&e.root_reuse_GO==="f7eda3b5696e478342b58999871788d009fef97a","current-NUL-info-and-explicit-reuse-binding:"+i);
    ok(r[e.artifact]===d.nul[i],"complete-NUL-byte-sequence-equals-independent-canonical-reconstruction:"+i);
  }
  ok(state.returned_observer_count===12&&state.observers.length===12&&state.observers.reduce((n,o)=>n+o.pages.length,0)===36&&state.observers.every(o=>o.complete===true&&o.closed_status.operation_id===o.operation_id&&o.closed_status.async_state==="completed"&&o.closed_status.result_state==="stored_observed"&&o.closed_status.owned_future_active===false),"12-returned-original-observers-36-pages-closed-aggregate");
  ok(state.first_tail_admission_without_ACK==="UNKNOWN_PRESERVED"&&state.reconciliation_reused===false&&state.smallbatch3_reconciliation.reused===true&&state.smallbatch3_reconciliation.returned_operation_id==="73b13cbbe33cf212fe58efb35a0c7e84e5155518c01d3b3793bb7aea5384d08f"&&state.smallbatch3_reconciliation.returned_ID_closed_full===true,"distinct-read-errors-recovery-and-old-tail-UNKNOWN-preserved");
  ok(state.execution_submissions===1&&state.tool_calls_inflight===0&&state.LAN_prepare_live_submitted===false&&state.source_import_evidence_ready_for_root===true&&state.full_source_import_qualification===false,"one-business-execution-no-premature-root-or-LAN-claim");
  return {schema:"heptabao.root-importer-final65-semantic-increment.r31.v1",status:"PASS_FINAL65_SEMANTIC_INCREMENT",checks_passed:checks.length,checks,packet:d.audit.tree,original_job:"desktop/1a1acd0d62d-fc05-571a",core_blob:"575f3ef51bb6e859ee28b0cf268966ce2b6a7513",core_sha256:"484ebbd31e94213c526bbde8664a516658fbab48a273bace01396a6ca10adb72",previous_core_review:d.coreReview,raw_command_records:21,raw_streams:42,source_control_files:2,native_content_files:63,native_content_bytes:61389,canonical_NUL_files:2,canonical_NUL_bytes:889176,current_host_large_body_RPC_count:0,all_content_bytes:950565,returned_observers:12,immutable_pages:36,old_tail_lost_ACK:"UNKNOWN_PRESERVED",same_original_pure_peer_verifier_rerun:false,incremental_chain_peer_intake_pending:true,root_Runtime_calls:0};
}