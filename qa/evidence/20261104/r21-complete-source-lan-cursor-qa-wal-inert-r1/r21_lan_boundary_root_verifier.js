function verifyLanBoundary(a,get,parse,u,bs,h,prepared){
  const checks=[];const ck=(n,v)=>{if(!v)throw Error(n);checks.push(n);};
  const rec=p=>a.records.find(r=>r.path===p),raw=p=>get(rec(p).blob),j=p=>parse(raw(p));
  const native=p=>{const s=j(p);ck("SDK wrapper "+p,!s.isError&&s.content?.length===1&&s.content[0].type==="text");return parse(s.content[0].text);};
  const versions=j("source-file-versions.json").boundary;ck("98 version records",versions.length===98&&new Set(versions.map(x=>x.path)).size===98);
  const files=[];for(let k=0;k<7;k++){const n=native("sdk/public-boundary-"+String(k).padStart(2,"0")+".json");ck("batch complete "+k,!n.truncated&&n.encoding==="utf-8"&&n.files.length<=16);files.push(...n.files);}
  ck("98 originals",files.length===98&&new Set(files.map(x=>x.path)).size===98);
  const root="/home/qian-qi/heptabao-ha-closure-20261103-r1/formal-cold-h2-pocket3-mac1-postrecovery-cold-r1/private-recovery/";
  for(const f of files){ck("fixed path "+f.path,f.path.startsWith(root));const p="boundary/"+f.path.slice(root.length),r=rec(p),v=versions.find(v=>v.path===f.path);ck("whole body "+p,!!r&&f.eof&&f.text===raw(p)&&u(f.text).length===f.size&&h(bs(u(f.text)))===f.sha256&&f.sha256===r.sha256);ck("literal version "+p,!!v&&v.size===f.size&&v.sha256===f.sha256&&v.version===f.version);}
  const s=j("core/summary.json"),ev=s.events.filter(x=>x.event==="mutation_attempted_once");
  ck("49 mutation events",ev.length===49);
  const statuses={},budgets={},pairs=[];
  for(let seq=1;seq<=49;seq++){
    const base="boundary/mutation-"+String(seq).padStart(5,"0"),i=j(base+".intent.json"),o=j(base+".outcome.json"),e=ev[seq-1];
    ck("once pair "+seq,i.sequence===seq&&o.sequence===seq&&i.fixture_run_id===s.fixture_run_id&&o.fixture_run_id===s.fixture_run_id&&i.automatic_retry===false&&o.automatic_retry===false&&i.dispatch_attempts_allowed===1&&o.transport_returned);
    ck("within budget "+seq,i.original_http_budget_seconds===o.original_http_budget_seconds&&o.within_original_budget===true&&o.elapsed_ms>=0&&o.elapsed_ms<=1000*o.original_http_budget_seconds);
    ck("event pair "+seq,e.node===i.node_id&&e.method===i.method&&e.status===o.http_status&&e.elapsed_ms===o.elapsed_ms);
    ck("public fields "+seq,Object.keys(i).every(x=>["automatic_retry","dispatch_attempts_allowed","fixture_run_id","method","node_id","original_http_budget_seconds","recorded_before_dispatch_unix_seconds","request_body_sha256","route","schema","sequence","stage","expected_cas","expected_data_sha256","expected_version"].includes(x))&&Object.keys(o).every(x=>["automatic_retry","elapsed_ms","fixture_run_id","http_status","original_http_budget_seconds","response_sha256","schema","sequence","storage_commit_outcome","transport_returned","within_original_budget","response_data_version"].includes(x))&&/^[0-9a-f]{64}$/.test(i.request_body_sha256)&&/^[0-9a-f]{64}$/.test(o.response_sha256)&&o.storage_commit_outcome==="not_inferred_from_http_or_transport");
    ck("public optional metadata "+seq,(!Object.hasOwn(i,"expected_cas")||(Number.isSafeInteger(i.expected_cas)&&i.expected_cas>=0))&&(!Object.hasOwn(i,"expected_version")||(Number.isSafeInteger(i.expected_version)&&i.expected_version>=1))&&(!Object.hasOwn(i,"expected_data_sha256")||/^[0-9a-f]{64}$/.test(i.expected_data_sha256))&&(!Object.hasOwn(o,"response_data_version")||(Number.isSafeInteger(o.response_data_version)&&o.response_data_version>=1)));
    statuses[o.http_status]=(statuses[o.http_status]||0)+1;budgets[o.original_http_budget_seconds]=(budgets[o.original_http_budget_seconds]||0)+1;
    pairs.push({sequence:seq,node:i.node_id,route:i.route,status:o.http_status,elapsed_ms:o.elapsed_ms,response_sha256:o.response_sha256});
  }
  ck("terminal status totals",statuses[200]===39&&statuses[204]===8&&statuses[503]===2&&Object.keys(statuses).length===3);
  ck("original budgets totals",budgets[15]===48&&budgets[12]===1&&Object.keys(budgets).length===2);
  ck("original98 preserved as actual incomplete",s.required_check_count===prepared.required_checks&&s.checks.length===91&&s.checks.every(x=>x.passed)&&s.missing_checks.length===7&&new Set([...s.checks.map(x=>x.case),...s.missing_checks]).size===98);
  ck("extra12 exact prepared order",JSON.stringify(s.post_recovery_cold.required_extra_checks)===JSON.stringify(prepared.required_extra_checks)&&s.post_recovery_cold.checks.length===0&&!s.post_recovery_cold.completed);
  ck("49 known transport outcomes",s.fixture_recovery.mutation_intents===49&&s.fixture_recovery.mutation_responses===49&&s.fixture_recovery.unknown_transport_outcomes===0&&!s.fixture_recovery.automatic_resume_or_retry);
  ck("last known failure",pairs[48].node===2&&pairs[48].route==="sys/unseal"&&pairs[48].status===503&&pairs[48].elapsed_ms===10289.344&&pairs[48].response_sha256==="f05273faea0480ecda3965f3233bc523ad2cc6da20482368438d12da340599e1");
  return {checks,statuses,budgets,pairs};
}
