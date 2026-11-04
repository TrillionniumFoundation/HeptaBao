export function reviewPublicJournals(input, hash, decode) {
  const need = (ok, code) => { if (!ok) throw new Error(code); };
  const bytes = s => unescape(encodeURIComponent(s)).length;
  const canonical = v => JSON.stringify(sort(v));
  function sort(v) { return Array.isArray(v) ? v.map(sort) : v && typeof v === "object" ? Object.fromEntries(Object.keys(v).sort().map(k => [k, sort(v[k])])) : v; }
  need(hash(input.packet) === "5d11bf46d1dd6a4492b7788ec3941f6126a05cda474039d212be5d2206e26d9f", "packet_pin");
  need(hash(input.result) === "efc6b9f60aa0caa1c06afa5057277050473433f1361b670eb08f2cb6ebbc84ee", "result_pin");
  need(hash(input.wire) === "d1f40a22db1a2e1b53e282191976e4eb44d96cd870ec046b91c31f891da58cf0", "wire_pin");
  const packet=JSON.parse(input.packet), result=JSON.parse(input.result), wire=JSON.parse(input.wire), files=new Map();
  need(packet.file_count===140 && packet.files.length===140, "closed_file_count");
  for (const f of packet.files) {
    need(/^operations\/\d{4}\.(intent|outcome)\.public\.json$/.test(f.path) && !files.has(f.path), "closed_unique_path");
    const raw=decode(f.data_base64);
    need(bytes(raw)===f.bytes && hash(raw)===f.sha256, "journal_raw_pin");
    files.set(f.path, JSON.parse(raw));
  }
  const pairs=[], methods={}, totals={complete_http_responses:0,definite_preconnect_failures:0,unknown:0};
  for (let i=1;i<=70;i++) {
    const prefix="operations/"+String(i).padStart(4,"0"), a=files.get(prefix+".intent.public.json"), b=files.get(prefix+".outcome.public.json");
    need(a && b && a.sequence===i && b.sequence===i && a.label===b.label && a.node===b.node, "exact_pair_binding");
    need(a.http_seconds===15 && a.redirect_following===false && a.valid_restore_body===false, "original_http_contract");
    need(Number.isSafeInteger(a.deadline_monotonic_ns), "safe_monotonic_number");
    if (a.parent_deadline_monotonic_ns!==null) need(Number.isSafeInteger(a.parent_deadline_monotonic_ns) && a.deadline_monotonic_ns<=a.parent_deadline_monotonic_ns, "parent_deadline");
    need(b.outcome_unknown===false && b.caller_timed_out===false && b.child_reaped===true && b.child_remaining.length===0, "known_reaped_outcome");
    methods[a.method]=(methods[a.method]||0)+1;
    if (b.response_complete===true) {
      need(b.phase==="complete" && b.request_sent===true && b.child_returncode===0 && Number.isInteger(b.status), "complete_http");
      totals.complete_http_responses++;
    } else if (b.phase==="before_connect" && b.request_sent===false) {
      need(b.response_complete===false && b.error_type==="ConnectionRefusedError", "preconnect");
      totals.definite_preconnect_failures++;
    } else totals.unknown++;
    pairs.push({intent:a,outcome:b});
  }
  need(totals.complete_http_responses===67 && totals.definite_preconnect_failures===3 && totals.unknown===0, "outcome_denominator");
  need(canonical(methods)===canonical({GET:45,POST:22,PUT:3}), "method_denominator");
  need(packet.source_result_sha256===hash(input.result) && packet.intents===70 && packet.outcomes===70 && packet.outcome_unknown===0, "packet_result_binding");
  need(result.http_intents===70 && result.http_outcomes===70 && result.http_unknown===0 && result.missing_outcome_sequences.length===0, "result_denominator");
  need(result.checks.length===64 && result.checks.every(c=>c.passed===true), "original_result_checks");
  need(result.client_cleanup.length===70 && result.server_cleanup.length===3 && [...result.client_cleanup,...result.server_cleanup].every(c=>c.owned_stopped===true && c.remaining.length===0), "all_owned_cleanup");
  need(result.all_owned_stopped===true && result.operation_replayed===false && result.production_services_touched===false && result.formal_heptabao_qualification===false, "reference_scope");
  let bound=0, business=0;
  for (const c of wire.cases) {
    if (c.token_lookup) continue;
    const pair=pairs[c.sequence-1];
    need(pair && Object.entries(pair.outcome).every(([k,v])=>canonical(c[k])===canonical(v)), "wire_outcome_binding");
    bound++;
    if (c.kind==="scoped_acl_and_consistency") {
      need(c.method===pair.intent.method && c.route===pair.intent.path && c.credential_class===pair.intent.credential_class && canonical(c.headers)===canonical(pair.intent.headers), "wire_business_intent");
      business++;
    }
  }
  need(bound===34 && business===30, "wire_denominator");
  const six=pairs[5], seven=pairs[6];
  need(six.outcome.status===503 && seven.outcome.status===501 && six.intent.parent_deadline_monotonic_ns===seven.intent.parent_deadline_monotonic_ns && seven.intent.headers["X-Vault-Inconsistent"]==="fail", "setup_original_deadline");
  return {
    schema:"heptabao.root-official271-policy-journal-review.v1",
    input_sha256:{packet:hash(input.packet),result:hash(input.result),wire:hash(input.wire)},
    exact_raw_files_verified:140, paired_intents_and_outcomes:70, ...totals, methods,
    wire_outcome_records_bound:bound, wire_business_intents_bound:business,
    reference_result_checks_all_passed:64, owned_client_cleanup_records:70, owned_server_cleanup_records:3,
    setup_503_then_explicit_fail_501_same_parent_deadline:true,
    original_http_budget_seconds:15, operation_replayed:false, production_services_touched:false,
    qualification_scope:"Fixed OpenBao 2.7.1 public reference journals and reported cleanup only.",
    limitations:["Derived token policies, uses and archive contents cannot be reconstructed from public body digests alone.","Original Unix nanosecond fields remain in hash-bound raw files; no numeric-precision assertion uses those large JSON numbers.","This review does not execute or qualify HeptaBao, physical HA, restore or snapshot-format interoperability."],
    formal_heptabao_qualification:false, full_replacement_qualified:false
  };
}
